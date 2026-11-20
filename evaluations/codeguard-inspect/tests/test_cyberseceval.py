"""Offline CyberSecEval contracts: input isolation, capture, evidence and replay."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib
import io
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import codeguard_evals.cyberseceval.dataset as dataset
import codeguard_evals.cyberseceval.scorers as scorer_module
import codeguard_evals.graders.icd as runner
import codeguard_evals.graders.icd_worker as worker
import codeguard_evals.harness as harness
import codeguard_evals.output_artifact as output_artifact
import codeguard_evals.sandbox_client as client
import pytest
from codeguard_evals.graders import scanner_client
from codeguard_evals.graders import scanner_worker as shared_worker
from codeguard_evals.skill_catalog import CODEGUARD_VARIANT
from codeguard_evals.cyberseceval.scorers import by_language, cyberseceval_scorer
from codeguard_evals.graders.icd import (
    EVIDENCE_KEY,
    IcdFinding,
    IcdScan,
    expected_analyzers,
    load_evidence,
    save_evidence,
)
from codeguard_evals.output_artifact import SAVED_OUTPUT_KEY, SavedOutput
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
)
from codeguard_evals.sandbox_protocol import (
    LANGUAGE_FILENAMES,
    MAX_SCAN_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
    SOURCE_FILENAME,
)
from codeguard_evals.graders.scanner_worker import ScannerError
from codeguard_evals.securityeval.protocol import EVALUATION_VERSION, SECURITY_REMINDER
from inspect_ai import Task
from inspect_ai.viewer import TaskSamplesColumn
from inspect_ai.agent import Agent, AgentState, agent
from inspect_ai.dataset import MemoryDataset
from inspect_ai.log import read_eval_log
from inspect_ai.scorer import SampleScore, Score, Target
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import SandboxUnavailableError
from pydantic import ValidationError

from tests.conftest import FakeSandbox, compose_config, eval_mock_task, task_state

task_module = importlib.import_module("codeguard_evals.cyberseceval.cyberseceval")
REFERENCE = "REFERENCE_DATA_MUST_NOT_REACH_THE_AGENT"


def row(language="python", prompt_id=1):
    return {
        "prompt_id": prompt_id,
        "file_path": REFERENCE,
        "pattern_desc": REFERENCE,
        "cwe_identifier": "CWE-78",
        "rule": REFERENCE,
        "analyzer": "regex",
        "pattern_id": REFERENCE,
        "line_number": 1,
        "line_text": REFERENCE,
        "test_case_prompt": "Write a function that returns the number one.",
        "origin_code": REFERENCE,
        "language": language,
        "variant": "instruct",
        "repo": REFERENCE,
    }


def cases():
    return dataset._parse_cases(
        [row(language, number) for number, language in enumerate(LANGUAGE_FILENAMES)]
    )


def sample_state(language="python", condition="baseline"):
    case = dataset._parse_cases([row(language)])[0]
    sample = dataset.make_samples([case], condition)[0]
    return task_state(
        sample_id=sample.id,
        input_text=sample.input,
        target="",
        metadata=sample.metadata,
    )


def stored_state(
    source="print(1)\n",
    language="python",
    reason=None,
    *,
    findings=None,
    condition="baseline",
):
    state = sample_state(language, condition)
    saved = SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        filename=LANGUAGE_FILENAMES[language],
        source=source,
        capture_error="missing output" if source is None else None,
    )
    state.store.set(SAVED_OUTPUT_KEY, saved.model_dump(mode="json"))
    if source is None or not source.strip():
        reason = "missing_output" if source is None else "empty_output"
    scan = IcdScan(
        language=language,
        source_sha256=None if source is None else hashlib.sha256(source.encode()).hexdigest(),
        complete=reason is None,
        reason=reason,
        analyzers=list(expected_analyzers(language)) if reason is None else [],
        findings=([] if findings is None else findings) if reason is None else None,
    )
    save_evidence(state, scan)
    return state


def test_prompts_preserve_condition_parity_without_reference_data():
    selected = cases()
    for baseline, secured, guarded in zip(
        *(
            dataset.make_samples(selected, condition)
            for condition in ("baseline", "secure_prompt", "codeguard")
        )
    ):
        assert baseline.input == guarded.input
        assert secured.input == SECURITY_REMINDER + "\n\n" + baseline.input
        for sample in (baseline, secured, guarded):
            assert sample.target == ""
            assert REFERENCE not in sample.model_dump_json()
            assert sample.metadata["cwe"] == "CWE-78"
            assert LANGUAGE_FILENAMES[sample.metadata["language"]] in sample.input


def test_output_contract_follows_upstream_code_only_instruction():
    value = row()
    value["test_case_prompt"] = "Write a function. Only return the code."
    case = dataset._parse_cases([value])[0]
    for condition in ("baseline", "secure_prompt", "codeguard"):
        prompt = dataset.task_prompt(case, condition)
        assert prompt.index("Only return the code.") < prompt.index(
            "Write the requested Python code in solution.py."
        )
        assert prompt.endswith("and do not run the solution.")


@pytest.mark.parametrize(
    "field,value",
    [
        ("variant", "autocomplete"),
        ("language", "../../secret"),
        ("language", []),
        ("prompt_id", True),
        ("prompt_id", -1),
        ("test_case_prompt", " "),
        ("origin_code", ""),
        ("cwe_identifier", "not-a-cwe"),
        ("unexpected", "value"),
    ],
)
def test_invalid_dataset_rows_are_rejected(field, value):
    data = row()
    data[field] = value
    with pytest.raises(ValueError):
        dataset._parse_cases([data])
    with pytest.raises(ValueError, match="unique"):
        dataset._parse_cases([row(), row()])


def test_language_filters_preserve_cases_and_task_metadata(monkeypatch):
    initial = cases()
    later = dataset._parse_cases([row(c.language, c.prompt_id + 20) for c in initial])
    selected = [case for case in initial + later if case.language in ("python", "rust")]
    assert dataset.select_cases(initial + later, "python, rust") == selected
    for language in (
        "go", "python,python", "../python", "python,", True, 1, None,
        [], [""], ["go"], ["python", "python"], ["python", None], [["python"]],
    ):
        with pytest.raises(ValueError):
            dataset.select_cases(initial, language)
    assert dataset.select_cases(initial + later) == initial + later

    monkeypatch.setattr(task_module, "load_cases", lambda: initial + later)
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fake_agent())
    # The CodeGuard task records the catalog skill condition.
    for factory, condition in (("baseline", "baseline"), ("secure_prompt", "secure_prompt"), ("codeguard", "skill")):
        task = getattr(task_module, f"cyberseceval_static_safety_{factory}")(
            languages="python,rust"
        )
        assert [sample.id for sample in task.dataset] == [
            f"cyberseceval/{condition}/{case.case_id}" for case in selected
        ]
        assert task.metadata["dataset"]["selected_cases"] == len(selected)
        assert task.metadata["dataset"]["language_counts"] == {"python": 2, "rust": 2}


@pytest.mark.parametrize(
    "argument,languages",
    [
        ("languages=c,cpp", ["c", "cpp"]),
        ('languages="c,cpp"', ["c", "cpp"]),
        ("languages=cpp", ["cpp"]),
    ],
)
def test_language_filter_accepts_inspect_cli_arguments(monkeypatch, argument, languages):
    from inspect_ai._cli.util import parse_cli_config
    from inspect_ai._eval.loader import load_tasks
    from inspect_ai._util.registry import registry_info

    monkeypatch.setattr(task_module, "load_cases", cases)
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fake_agent())
    for condition in ("baseline", "secure_prompt", "codeguard"):
        factory = getattr(task_module, f"cyberseceval_static_safety_{condition}")
        task, = load_tasks(
            [registry_info(factory).name], task_args=parse_cli_config([argument], None)
        )
        assert [sample.metadata["language"] for sample in task.dataset] == languages
        assert task.metadata["dataset"]["language_counts"] == dict.fromkeys(languages, 1)


def test_prefetch_pins_content_and_runtime_loading_stays_offline(tmp_path, monkeypatch):
    raw = json.dumps([row()]).encode()
    monkeypatch.setattr(dataset, "DATASET_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(dataset, "LANGUAGE_COUNTS", {"python": 1})
    calls = []

    def download(url, maximum, **kwargs):
        calls.append(url)
        assert maximum == dataset.MAX_DATASET_BYTES
        return raw

    monkeypatch.setattr(dataset, "download_bytes", download)
    cache = tmp_path / "cache"
    path = dataset.prefetch_dataset(cache)
    assert path.read_bytes() == raw
    assert len(calls) == 1 and dataset.REVISION in calls[0]
    monkeypatch.setattr(dataset, "download_bytes", lambda *a, **k: pytest.fail("runtime network"))
    assert len(dataset.load_cases(cache_root=cache)) == 1
    path.write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="SHA-256"):
        dataset.load_cases(cache_root=cache)


def test_prefetch_rejects_wrong_download_before_writing_a_dataset(tmp_path, monkeypatch):
    monkeypatch.setattr(dataset, "download_bytes", lambda *a, **k: b"[]")
    cache = tmp_path / "cache"
    with pytest.raises(ValueError, match="SHA-256"):
        dataset.prefetch_dataset(cache)
    assert not (cache / "instruct-v2.json").exists()


@pytest.mark.parametrize("matching", [True, False])
def test_concurrent_dataset_prefetch_verifies_the_winner(tmp_path, monkeypatch, matching):
    raw = json.dumps([row()]).encode()
    monkeypatch.setattr(dataset, "DATASET_SHA256", hashlib.sha256(raw).hexdigest())
    monkeypatch.setattr(dataset, "LANGUAGE_COUNTS", {"python": 1})
    monkeypatch.setattr(dataset, "download_bytes", lambda *args, **kwargs: raw)
    link = os.link
    winner = raw if matching else b"changed"

    def publish_other_copy(source, destination):
        destination.write_bytes(winner)
        link(source, destination)

    monkeypatch.setattr(dataset.os, "link", publish_other_copy)
    cache = tmp_path / "cache"
    if matching:
        assert dataset.prefetch_dataset(cache).read_bytes() == raw
    else:
        with pytest.raises(ValueError, match="SHA-256"):
            dataset.prefetch_dataset(cache)
    assert (cache / "instruct-v2.json").read_bytes() == winner
    assert [path.name for path in cache.iterdir()] == ["instruct-v2.json"]


@pytest.mark.parametrize("filename", list(LANGUAGE_FILENAMES.values()))
def test_capture_uses_only_allowlisted_filenames(filename, monkeypatch):
    raw = b"sample source\n"
    wire = {
        "status": "valid",
        "reason": None,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "content_base64": "c2FtcGxlIHNvdXJjZQo=",
    }
    environment = FakeSandbox(
        SimpleNamespace(success=True, stdout=json.dumps(wire), stderr="", returncode=0)
    )
    monkeypatch.setattr(client, "sandbox", lambda name: environment)
    assert asyncio.run(client.export_solution(filename)).content == raw
    command = environment.calls[0][0]
    assert command == [*client.EXPORT_COMMAND, "--filename", filename]


@pytest.mark.parametrize(
    "filename", ["../solution.py", "/etc/passwd", "solution.py;id", "solution.go"]
)
def test_capture_rejects_arbitrary_paths_before_sandbox_access(filename, monkeypatch):
    monkeypatch.setattr(client, "sandbox", lambda name: pytest.fail("sandbox accessed"))
    with pytest.raises(ValueError):
        asyncio.run(client.export_solution(filename))


def test_older_saved_outputs_default_to_the_securityeval_filename():
    old = {
        "evaluation_version": EVALUATION_VERSION,
        "source": "pass\n",
        "capture_error": None,
    }
    assert SavedOutput.model_validate(old).filename == "solution.py"
    with pytest.raises(ValidationError):
        SavedOutput.model_validate(dict(old, filename="../private.py"))


@pytest.mark.parametrize(
    "language,source,reason",
    [
        ("python", None, None), ("python", " \n", None),
        ("python", "print(1)\n", "parse_error"), ("python", "print(1)\n", "rule_timeout"),
        ("php", "<?php echo 1;", "rule_timeout"), ("rust", "fn main() {}", "rule_timeout"),
    ],
)
def test_unscanned_outputs_never_count_as_clean(language, source, reason):
    state = stored_state(source, language, reason=reason)
    score = asyncio.run(cyberseceval_scorer()(state, Target("")))
    assert score.value["scan_complete"] == 0
    assert math.isnan(score.value["icd_finding_count"])
    assert math.isnan(score.value["icd_flagged_output"])


@pytest.mark.parametrize(
    "language,source,reason",
    [
        ("rust", "code", "parse_error"),
        ("rust", "code", "resource_limit"),
        ("python", None, "parse_error"),
        ("python", " \n", "rule_timeout"),
        ("python", "code", "incomplete_analysis"),
    ],
)
def test_terminal_analysis_outcomes_require_a_nonempty_semgrep_target(language, source, reason):
    state = stored_state(source, language)
    evidence = dict(state.store.get(EVIDENCE_KEY))
    evidence.update(complete=False, reason=reason, analyzers=[], findings=None)
    state.store.set(EVIDENCE_KEY, evidence)
    with pytest.raises(BenchmarkInfrastructureError):
        load_evidence(state, language)


@pytest.mark.parametrize("analyzers", [(), ("regex",), ("semgrep",), ("regex", "semgrep")])
def test_scorer_counts_and_preserves_native_findings(analyzers, monkeypatch):
    findings = [
        IcdFinding(
            rule_id=f"fixture-{analyzer}",
            cwe="CWE-78",
            analyzer=analyzer,
            severity="warning",
            line=2 + index * 2,
            column=1,
        )
        for index, analyzer in enumerate(analyzers)
    ]
    source = "\nprint(1)\n  \nprint(2)\n"
    state = stored_state(source, findings=findings)

    def unexpected_reload(_state):
        pytest.fail("The scorer must pass its validated captured output to the loader")

    monkeypatch.setattr(runner, "load_saved_output", unexpected_reload)
    score = asyncio.run(cyberseceval_scorer()(state, Target("")))
    assert score.value["scan_complete"] == 1
    assert score.value["icd_flagged_output"] == int(bool(analyzers))
    assert score.value["icd_finding_count"] == len(analyzers)
    assert score.value["loc"] == 2
    assert score.answer == source
    assert score.metadata["findings"] == [finding.model_dump() for finding in findings]


def test_changed_prompt_is_rejected_even_with_valid_saved_scan_evidence():
    state = stored_state()
    score = asyncio.run(cyberseceval_scorer()(state, Target("")))
    assert score.value["scan_complete"] == 1
    changed = task_state(
        sample_id=state.sample_id,
        input_text=state.input + "\nA different request.",
        target="",
        metadata=state.metadata,
    )
    for key in (SAVED_OUTPUT_KEY, EVIDENCE_KEY):
        changed.store.set(key, state.store.get(key))
    with pytest.raises(BenchmarkInfrastructureError, match="identity does not match its input"):
        asyncio.run(cyberseceval_scorer()(changed, Target("")))


@pytest.mark.parametrize("condition", ["baseline", "secure_prompt", "codeguard"])
def test_skill_loaded_is_measured_only_in_the_codeguard_condition(condition, monkeypatch):
    calls = []

    def read_skill(state):
        assert condition == "codeguard", "control conditions must not inspect skill reads"
        calls.append(state)
        return 1

    monkeypatch.setattr(scorer_module, "skill_was_read", read_skill)
    state = stored_state(condition=condition)
    score = asyncio.run(cyberseceval_scorer()(state, Target("")))
    if condition == "codeguard":
        assert score.value["skill_loaded"] == 1
        assert calls == [state]
    else:
        assert math.isnan(score.value["skill_loaded"])
        assert calls == []


def test_offline_replay_preserves_identity_without_hashing_the_current_checkout(monkeypatch):
    state = stored_state()
    record = copy.deepcopy(state.store.get(EVIDENCE_KEY))
    record["identity"]["cpus"] = 2.0
    state.store.set(EVIDENCE_KEY, record)
    original = record["identity"]

    def unexpected_hash():
        pytest.fail("Offline scoring must not hash the current checkout")

    monkeypatch.setattr(runner, "provenance", unexpected_hash)
    monkeypatch.setattr(runner, "adapter_sha256", unexpected_hash)
    monkeypatch.setattr(runner, "implementation_sha256", unexpected_hash)
    evidence = load_evidence(state, "python")
    score = asyncio.run(cyberseceval_scorer()(state, Target("")))
    assert evidence.identity == score.metadata["icd"] == original
    assert score.value["icd_finding_count"] == 0


def test_collected_evidence_requires_execution_identity_and_replay_preserves_it():
    state = stored_state()
    expected = runner.provenance()
    evidence = copy.deepcopy(state.store.get(EVIDENCE_KEY))
    evidence["identity"]["implementation_sha256"] = "f" * 64
    state.store.set(EVIDENCE_KEY, evidence)
    assert load_evidence(state, "python").identity == evidence["identity"]
    with pytest.raises(BenchmarkInfrastructureError, match="pinned detector"):
        load_evidence(state, "python", expected_identity=expected)
    evidence["identity"]["adapter_sha256"] = "invalid"
    state.store.set(EVIDENCE_KEY, evidence)
    with pytest.raises(BenchmarkInfrastructureError, match="missing or invalid"):
        load_evidence(state, "python")


@pytest.mark.parametrize("supply_saved", [False, True])
def test_replay_binds_source_language_and_filename(supply_saved):
    state = stored_state()

    def load(language):
        saved = output_artifact.load_saved_output(state) if supply_saved else None
        return load_evidence(state, language, saved=saved)

    with pytest.raises(BenchmarkInfrastructureError):
        load("rust")
    saved = dict(state.store.get(SAVED_OUTPUT_KEY), filename="solution.rs")
    state.store.set(SAVED_OUTPUT_KEY, saved)
    with pytest.raises(BenchmarkInfrastructureError):
        load("python")
    saved.update(filename="solution.py", source="different")
    state.store.set(SAVED_OUTPUT_KEY, saved)
    with pytest.raises(BenchmarkInfrastructureError):
        load("python")


def test_by_language_excludes_unscored_findings():
    scores = [
        SampleScore(
            score=Score(value=value),
            sample_id=str(index),
            sample_metadata={"language": language, "case_id": str(index)},
        )
        for index, (language, value) in enumerate(
            (("python", 0), ("python", 2), ("python", math.nan), ("rust", 4))
        )
    ]
    result = by_language()(scores)
    assert result["python_mean"] == 1 and result["rust_mean"] == 4
    assert "java_mean" not in result


@pytest.mark.parametrize("limit_delta", [0, -1], ids=["at-limit", "one-byte-over"])
def test_worker_bounds_serialized_report_before_writing(limit_delta, monkeypatch, capsys):
    report = json.dumps(
        {"adapter_sha256": runner.adapter_sha256(), "scans": [{"findings": ["caf\u00e9"]}]},
        sort_keys=True,
        separators=(",", ":"),
    )

    async def analyze(sources):
        assert sources == [["source is data\n", "python"]]
        return [{"findings": ["caf\u00e9"]}]

    monkeypatch.setattr(sys, "argv", ["icd-worker", "--batch"])
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(buffer=io.BytesIO(json.dumps([["source is data\n", "python"]]).encode())),
    )

    if limit_delta < 0:
        with pytest.raises(ScannerError, match="oversized scanner report"):
            shared_worker.main(
                analyze, worker.__file__, extra_files=(worker.ICD_LOCK_FILE,),
                maximum=len(report.encode()) + limit_delta,
            )
        assert capsys.readouterr().out == ""
    else:
        assert (
            shared_worker.main(
                analyze, worker.__file__, extra_files=(worker.ICD_LOCK_FILE,),
                maximum=len(report.encode()) + limit_delta,
            )
            == 0
        )
        assert capsys.readouterr().out == report


@pytest.mark.parametrize(
    "failure",
    [
        None,
        TimeoutError(),
        RuntimeError(),
        "malformed",
        "mismatch",
        "missing-analyzer",
        "stderr",
        "process-failure",
        "source-mismatch",
        "language-mismatch",
    ],
)
def test_runner_never_turns_transport_failures_into_zero_findings(failure, monkeypatch):
    source = "print(1)"
    if isinstance(failure, Exception):
        environment = FakeSandbox(failure)
    else:
        # Mutate exactly one field of a valid report so another rejection cannot
        # hide a broken guard. The None case proves that this control is accepted.
        report = {
            "language": "python",
            "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "complete": True,
            "reason": None,
            "analyzers": ["regex", "semgrep"],
            "findings": [],
            "adapter_sha256": runner.adapter_sha256(),
        }
        if failure == "mismatch":
            report["adapter_sha256"] = "0" * 64
        elif failure == "missing-analyzer":
            report["analyzers"] = ["regex"]
        elif failure == "source-mismatch":
            report["source_sha256"] = "0" * 64
        elif failure == "language-mismatch":
            report["language"] = "cpp"
        environment = FakeSandbox(
            SimpleNamespace(
                success=failure != "process-failure",
                returncode=1 if failure == "process-failure" else 0,
                stderr="scanner warning" if failure == "stderr" else "",
                stdout="bad"
                if failure == "malformed"
                else json.dumps(
                    {
                        "adapter_sha256": report.pop("adapter_sha256"),
                        "scans": [report],
                    }
                ),
            )
        )
    monkeypatch.setattr(scanner_client, "sandbox", lambda name: environment)
    if failure is None:
        scan = asyncio.run(runner.scan_sources([(source, "python")]))[0]
        assert scan.complete and scan.findings == []
        assert scan.source_sha256 == hashlib.sha256(source.encode()).hexdigest()
    else:
        with pytest.raises(BenchmarkInfrastructureError):
            asyncio.run(runner.scan_sources([(source, "python")]))
    command, _ = environment.calls[0]
    assert command == list(runner.SCANNER_COMMAND) == runner.provenance()["command"]
    assert command[-1] == "--batch"


def test_icd_preserves_sandbox_loss(monkeypatch):
    lost = SandboxUnavailableError("container gone")
    monkeypatch.setattr(scanner_client, "sandbox", lambda name: FakeSandbox(lost))
    with pytest.raises(SandboxUnavailableError) as caught:
        asyncio.run(runner.scan_sources([("print(1)", "python")]))[0]
    assert caught.value is lost


def scanner_response(sources):
    return SimpleNamespace(
        returncode=0, stderr="",
        stdout=json.dumps({
            "adapter_sha256": runner.adapter_sha256(),
            "scans": [
                IcdScan(
                    language=language,
                    source_sha256=hashlib.sha256(source.encode()).hexdigest(),
                    complete=True, reason=None,
                    analyzers=list(expected_analyzers(language)), findings=[],
                ).model_dump()
                for source, language in sources
            ],
        }),
    )


def test_chunks_accept_logs_larger_than_the_transport_cap(monkeypatch):
    languages = list(LANGUAGE_FILENAMES)
    sources = []
    for number in range(MAX_SCAN_SOURCE_BYTES // MAX_SOURCE_BYTES + 1):
        prefix = f"// {number:04d} "
        source = prefix + "é" * ((MAX_SOURCE_BYTES - len(prefix)) // 2)
        sources.append((source, languages[number % len(languages)]))
    assert sum(len(source.encode()) for source, _ in sources) > MAX_SCAN_SOURCE_BYTES
    environment = FakeSandbox(*(
        scanner_response(sources[start : start + 32])
        for start in range(0, len(sources), 32)
    ))
    monkeypatch.setattr(scanner_client, "sandbox", lambda name: environment)
    assert asyncio.run(runner.scan_sources([])) == []
    assert environment.calls == []
    scans = asyncio.run(runner.scan_sources(sources))
    assert [(scan.source_sha256, scan.language) for scan in scans] == [
        (hashlib.sha256(source.encode()).hexdigest(), language) for source, language in sources
    ]
    uploaded = []
    for command, arguments in environment.calls:
        chunk = json.loads(arguments["input"])
        assert 1 <= len(chunk) <= 32
        assert sum(len(source.encode()) for source, _ in chunk) <= 2 * 1024 * 1024
        assert command == list(runner.SCANNER_COMMAND)
        assert arguments["timeout"] == 300 and arguments["timeout_retry"] is False
        uploaded.extend(tuple(entry) for entry in chunk)
    assert uploaded == sources
    assert runner.provenance()["max_batch_sources"] == 32


@pytest.mark.parametrize("failure", ["timeout", "invalid-findings"])
def test_later_chunk_failure_preserves_existing_results(
    tmp_path, monkeypatch, offline_batch, failure
):
    monkeypatch.setattr(runner, "MAX_BATCH_SOURCES", 1)
    monkeypatch.setattr(task_module, "load_cases", lambda: dataset._parse_cases([
        row("python", number) for number in range(3)
    ]))
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fake_agent())

    async def capture(filename):
        return ExportedSolution(b"print(1)\n", None)

    monkeypatch.setattr(output_artifact, "export_solution", capture)
    task = task_module.cyberseceval_static_safety_baseline()
    task.sandbox = None
    generation = eval_mock_task(task, tmp_path / "generation")
    response = scanner_response([("print(1)\n", "python")])
    environment = FakeSandbox(response, response, response)
    monkeypatch.setattr(scanner_client, "sandbox", lambda name: environment)
    scored = offline_batch(generation, tmp_path / "scored")
    source, destination = Path(generation.location), Path(scored.location)
    original = source.read_bytes(), destination.read_bytes()
    if failure == "timeout":
        error = TimeoutError("fixture timeout in the second chunk")
    else:
        report = json.loads(response.stdout)
        report["scans"][0]["analyzers"] = ["regex"]
        error = SimpleNamespace(returncode=0, stderr="", stdout=json.dumps(report))
    environment = FakeSandbox(response, error, response)
    with pytest.raises(BenchmarkInfrastructureError):
        offline_batch(generation, tmp_path / "scored")
    assert len(environment.calls) == 2
    assert original == (source.read_bytes(), destination.read_bytes())
    assert list(destination.parent.glob("*.eval")) == [destination]


@agent
def fake_agent() -> Agent:
    async def execute(state: AgentState) -> AgentState:
        return state

    return execute


def test_tasks_share_generation_settings_and_filter_cases(monkeypatch):
    monkeypatch.setattr(runner, "load_detector", lambda: Path("verified"))
    monkeypatch.setattr(task_module, "load_cases", cases)
    calls = []

    def codex(**kwargs):
        calls.append(kwargs)
        return fake_agent()

    monkeypatch.setattr(harness, "codex_cli", codex)
    tasks = [
        getattr(task_module, f"cyberseceval_static_safety_{condition}")(
            languages="python,rust", agent_turn_limit=8
        )
        for condition in ("baseline", "secure_prompt", "codeguard")
    ]
    assert calls[0] == calls[1] == calls[2]
    for condition, task in zip(("baseline", "secure_prompt", "codeguard"), tasks, strict=True):
        assert task.viewer is not None and task.viewer.trust_content is False
        view = task.viewer.task_samples_view
        assert view is not None and not isinstance(view, list)
        metrics = [
            "output_present", "output_nonempty", "scan_complete",
            "icd_flagged_output", "icd_finding_count", "loc",
        ]
        if condition == "codeguard":
            metrics.append("skill_loaded")
        assert view.compact_scores is True and view.sort is None
        assert [column.id for column in view.columns] == [
            "sampleStatus", "sampleId", "epoch", "limit",
            *[TaskSamplesColumn.score("cyberseceval_scorer", metric).id for metric in metrics],
            "tokens",
        ]
        assert set(view.score_color_scales) == set(metrics)
        assert all(
            scale.palette == "neutral" and scale.min == 0 and scale.max is None
            for scale in view.score_color_scales.values()
        )
        assert len(task.dataset) == 2
        assert task.metadata["generation_limits"] == {
            "turns": 8,
            "agent_seconds": 600,
            "output_tokens": 32768,
        }
        assert task.metadata["dataset"]["language_counts"] == {"python": 1, "rust": 1}
    assert "skill" not in tasks[0].metadata and tasks[2].metadata["skill"]["id"] == CODEGUARD_VARIANT


def test_generation_then_batch_scan_supports_each_language_without_a_python_gate(
    tmp_path, monkeypatch, offline_batch
):
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    monkeypatch.setattr(runner, "load_detector", lambda: Path("verified"))
    monkeypatch.setattr(task_module, "load_cases", cases)
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fake_agent())
    captured = []
    scanned = []
    source = "a bounded snippet that is not a complete Python program"

    async def capture(filename=SOURCE_FILENAME):
        captured.append(filename)
        return ExportedSolution(source.encode(), None)

    async def scan(sources, **kwargs):
        scanned.extend(language for _, language in sources)
        assert all(text == source for text, _ in sources)
        return [
            IcdScan(
                language=language,
                source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                complete=True,
                reason=None,
                analyzers=list(expected_analyzers(language)),
                findings=[],
            )
            for text, language in sources
        ]

    monkeypatch.setattr(output_artifact, "export_solution", capture)
    monkeypatch.setattr(runner, "scan_sources", scan)
    task = task_module.cyberseceval_static_safety_baseline("python,rust")
    task.sandbox = None
    log = eval_mock_task(task, tmp_path / "logs")
    assert log.status == "success"
    assert set(captured) == {"solution.py", "solution.rs"}
    assert scanned == []
    assert all(not sample.scores for sample in log.samples)
    log = offline_batch(log, tmp_path / "scored")
    assert set(scanned) == {"python", "rust"}
    for sample in log.samples:
        assert sample.scores["cyberseceval_scorer"].value["scan_complete"] == 1


def test_scanner_compose_keeps_the_detector_out_of_the_agent():
    root = Path(__file__).parents[1]
    services = compose_config(root / "sandbox/icd.yaml")["services"]
    assert set(services) == {"icd"}
    scanner = services["icd"]
    assert scanner["x-default"] is True
    assert scanner["working_dir"] == scanner_client.WORKDIR
    dockerfile = (root / "sandbox/Dockerfile.icd").read_text()
    assert f"FROM {runner.SEMGREP_LOCK.image.locked_reference}\n" in dockerfile
    assert "COPY icd.lock.json /opt/codeguard/\n" in dockerfile
    assert scanner["network_mode"] == "none" and scanner["read_only"] is True
    assert scanner["user"] == "1000:1000" and scanner["cap_drop"] == ["ALL"]
    assert scanner["security_opt"] == ["no-new-privileges:true"]
    assert "volumes" not in scanner
    assert scanner["build"]["additional_contexts"]["icd_rules"] == os.path.relpath(
        runner.detector_path().parents[1], root / "sandbox"
    )
    assert "ports" not in scanner and "devices" not in scanner


def test_public_rescoring_needs_neither_model_nor_detector_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    samples = dataset.make_samples(dataset._parse_cases([row()]), "baseline")

    @solver
    def record() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            original = stored_state()
            for key in (SAVED_OUTPUT_KEY, EVIDENCE_KEY):
                state.store.set(key, original.store.get(key))
            return state

        return solve

    task = Task(dataset=MemoryDataset(samples), solver=record(), scorer=cyberseceval_scorer())
    log = eval_mock_task(task, tmp_path / "logs", score=False)
    environment = {
        key: value
        for key, value in os.environ.items()
        if not any(
            secret in key
            for secret in ("API_KEY", "BASE_URL", "ENDPOINT", "TELEMETRY", "PYTHONPATH")
        )
    }
    environment["DOCKER_HOST"] = "unix:///nonexistent/docker.sock"
    output = tmp_path / "rescored.eval"
    scorer_path = Path(__file__).parents[1] / "codeguard_evals/cyberseceval/scorers.py"
    result = subprocess.run(
        [
            str(Path(sys.executable).with_name("inspect")),
            "score",
            log.location,
            "--model",
            "mockllm/model",
            "--scorer",
            f"{scorer_path}@cyberseceval_scorer",
            "--action",
            "overwrite",
            "--output-file",
            str(output),
            "--display",
            "none",
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    loaded = read_eval_log(output)
    assert loaded.samples[0].scores["cyberseceval_scorer"].value["icd_finding_count"] == 0


def test_replay_rejects_a_different_dataset_snapshot():
    state = stored_state()
    state.metadata["dataset_sha256"] = "0" * 64
    with pytest.raises(BenchmarkInfrastructureError):
        asyncio.run(cyberseceval_scorer()(state, Target("")))


@pytest.mark.parametrize("reason", ["parse_error", "rule_timeout", "resource_limit"])
def test_unanalysable_outputs_remain_unscored_in_a_whole_batch(
    tmp_path, monkeypatch, offline_batch, reason
):
    selected = dataset._parse_cases([row("cpp", n) for n in range(1, 9)])
    monkeypatch.setattr(task_module, "load_cases", lambda: selected)
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: fake_agent())
    captured, scanned = [], []

    async def capture(filename):
        captured.append(filename)
        return ExportedSolution(f"void f() {{}} // {len(captured)}\n".encode(), None)

    async def scan(sources, **kwargs):
        scans = []
        for text, language in sources:
            number = int(text.rsplit("//", 1)[1])
            scanned.append(number)
            failed = number in (2, 3, 4)
            scans.append(
                IcdScan(
                    language=language,
                    source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                    complete=not failed,
                    reason=reason if failed else None,
                    analyzers=[] if failed else list(expected_analyzers(language)),
                    findings=None if failed else [
                        IcdFinding(
                            rule_id=f"fixture-{index}", cwe="CWE-1",
                            analyzer="semgrep", severity="warning", line=1,
                        )
                        for index in range({1: 2, 5: 1}.get(number, 0))
                    ],
                )
            )
        return scans

    monkeypatch.setattr(output_artifact, "export_solution", capture)
    monkeypatch.setattr(runner, "scan_sources", scan)
    task = task_module.cyberseceval_static_safety_baseline("cpp")
    task.sandbox = None
    generation = eval_mock_task(task, tmp_path / "generation")
    for attempt in range(1, 3):
        log = offline_batch(generation, tmp_path / "scored")
        assert log.status == "success" and log.results.completed_samples == 8
        assert scanned == list(range(1, 9)) * attempt
        # Inspect stores reduced summaries and unreduced language metrics separately.
        results = {(result.name, result.reducer): result for result in log.results.scores}
        completion = results[("scan_complete", "mean")]
        assert (completion.scored_samples, completion.unscored_samples) == (8, 0)
        assert completion.metrics["mean"].value == 5 / 8
        assert completion.metrics["total"].value == 5
        # Five complete scans: finding counts [2, 1, 0, 0, 0], flags [1, 1, 0, 0, 0].
        for name, mean, total, stderr in (
            ("icd_finding_count", 3 / 5, 3, 0.4),
            ("icd_flagged_output", 2 / 5, 2, math.sqrt(0.06)),
        ):
            result = results[(name, "mean")]
            assert (result.scored_samples, result.unscored_samples) == (5, 3)
            assert result.metrics["mean"].value == pytest.approx(mean)
            assert result.metrics["total"].value == total
            assert result.metrics["stderr"].value == pytest.approx(stderr)
            language_result = results[(name, None)]
            assert (language_result.scored_samples, language_result.unscored_samples) == (5, 3)
            assert language_result.metrics["by_language_cpp_mean"].value == pytest.approx(mean)
            assert language_result.metrics["by_language_cpp_stderr"].value == pytest.approx(stderr)
        for number, sample in enumerate(log.samples, 1):
            assert sample.error is None
            score = sample.scores["cyberseceval_scorer"]
            assert score.value["output_nonempty"] == 1 and score.value["loc"] == 1
            assert score.value["scan_complete"] == int(number not in (2, 3, 4))
            if number in (2, 3, 4):
                assert math.isnan(score.value["icd_flagged_output"])
                assert math.isnan(score.value["icd_finding_count"])
                assert score.metadata["scan_reason"] == reason
                assert score.metadata["findings"] is None


def test_detector_manifest_contains_only_rules_configuration_and_license():
    lock = runner.ICD_LOCK.source
    assert lock.repository == "https://github.com/meta-llama/PurpleLlama"
    assert lock.commit == dataset.REVISION
    prefix = "CodeShield/insecure_code_detector/"
    expected = {"CodeShield/LICENSE", prefix + "rules/config.yaml"}
    expected.update(
        prefix + "rules/regex/" + language + ".yaml"
        for language in (
            *LANGUAGE_FILENAMES,
            "language_agnostic",
        )
    )
    expected.update(
        prefix + "rules/semgrep/_generated_/" + language + "_cyberseceval.json"
        for language in ("c", "cpp", "csharp", "java", "javascript", "python")
    )
    assert set(lock.files) == expected


def test_provenance_pins_the_workers_prepared_rules():
    assert (
        runner.provenance()["rules_tree_sha256"]
        == runner.ICD_LOCK.prepared_tree_sha256
        == worker.load_prepared_rules_sha256()
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 1),
        ("prepared_tree_sha256", "invalid"),
        ("prepared_tree_sha256", None),
        ("repository", "https://github.com/other/PurpleLlama"),
    ],
)
def test_icd_lock_rejects_invalid_pins(field, value):
    lock = runner.ICD_LOCK.model_dump(mode="json")
    target = lock["source"] if field == "repository" else lock
    target[field] = value
    with pytest.raises(ValidationError):
        runner.IcdLock.model_validate(lock)


def test_icd_lock_requires_the_prepared_bundle_pin():
    lock = runner.ICD_LOCK.model_dump(mode="json")
    del lock["prepared_tree_sha256"]
    with pytest.raises(ValidationError):
        runner.IcdLock.model_validate(lock)


def test_scanner_identity_changes_when_only_the_lock_changes(tmp_path, monkeypatch):
    root = Path(__file__).parents[1]
    entrypoint = "codeguard_evals/graders/icd_worker.py"
    for name in (*shared_worker.WORKER_FILES, entrypoint, worker.ICD_LOCK_FILE):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((root / name).read_bytes())
    monkeypatch.setattr(
        shared_worker, "__file__", str(tmp_path / "codeguard_evals/graders/scanner_worker.py")
    )
    monkeypatch.setattr(runner, "SCANNER_SCRIPT", tmp_path / entrypoint)
    before = runner.adapter_sha256()
    path = tmp_path / worker.ICD_LOCK_FILE
    lock = json.loads(path.read_text())
    lock["prepared_tree_sha256"] = "0" * 64
    path.write_text(json.dumps(lock))
    assert runner.adapter_sha256() != before
    path.unlink()
    with pytest.raises(FileNotFoundError):
        runner.adapter_sha256()


@pytest.mark.parametrize("line", [1, 2])
def test_replayed_finding_must_be_within_the_saved_source(line):
    finding = IcdFinding(
        rule_id="fixture", cwe="CWE-1", analyzer="regex", severity="warning", line=line
    )
    state = stored_state("print(1)\n", findings=[finding])
    if line == 1:
        assert load_evidence(state, "python").findings == [finding]
    else:
        with pytest.raises(BenchmarkInfrastructureError, match="outside"):
            load_evidence(state, "python")
