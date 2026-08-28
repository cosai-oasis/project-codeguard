from __future__ import annotations

import asyncio
import copy
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.log import read_eval_log
from inspect_ai.model import (
    ChatMessageAssistant,
    Logprob,
    Logprobs,
    ModelFallback,
    ModelOutput,
    ModelUsage,
    StopDetails,
)
from inspect_ai.scorer import Target
from inspect_ai.solver import Generate, Solver, TaskState, solver

import codeguard_evals.output_artifact as artifact_module
from codeguard_evals.output_artifact import (
    SAVED_OUTPUT_KEY,
    SEMGREP_EVIDENCE_KEY,
    SavedOutput,
    SemgrepEvidence,
    capture_generated_output,
    load_saved_output,
    load_semgrep_evidence,
    save_semgrep_evidence,
)
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
)
from codeguard_evals.sandbox_protocol import MAX_PYTHON_SOURCE_BYTES
from codeguard_evals.scorers import static_safety_scorer
from codeguard_evals.securityeval.protocol import (
    EVALUATION_VERSION,
    TASK_PROMPT,
    securityeval_task_name,
)
from codeguard_evals.semgrep_artifacts import SEMGREP_LOCK, SemgrepFinding
from tests.conftest import (
    CASE_ID,
    ORIGINAL_SOURCE,
    SAFE_SOURCE,
    SAMPLE_CWE,
    SAMPLE_ID,
    STUB_SOURCE,
    task_state,
)


def _state(sample_id: str = SAMPLE_ID) -> TaskState:
    output = ModelOutput.from_content(
        "mockllm/model",
        "agent narration",
        stop_reason="max_tokens",
        stop_details=StopDetails(
            type="length",
            explanation="The provider reached its output limit.",
        ),
    )
    output.choices[0].logprobs = Logprobs(
        content=[Logprob(token="agent", logprob=-0.25)]
    )
    output.usage = ModelUsage(input_tokens=11, output_tokens=7, total_tokens=18)
    output.fallback = ModelFallback(
        model="mockllm/model",
        fallback_model="mockllm/fallback",
        count=2,
    )
    output.time = 1.25
    output.metadata = {
        "provider.request_id": "request-1",
        "provider.tags": ["benchmark"],
    }
    return task_state(
        sample_id=sample_id,
        messages=[
            ChatMessageAssistant(
                content="agent narration",
                model="mockllm/model",
            )
        ],
        output=output,
        metadata={
            "case_id": CASE_ID,
            "condition": "baseline",
            "cwe": SAMPLE_CWE,
        },
    )


def _export(
    source: bytes | None = SAFE_SOURCE.encode(),
    *,
    reason: str | None = None,
) -> ExportedSolution:
    if source is None:
        return ExportedSolution(None, reason or "missing output")
    return ExportedSolution(source, reason)


def _capture(
    monkeypatch: pytest.MonkeyPatch,
    exported: ExportedSolution,
    *,
    state: TaskState | None = None,
) -> TaskState:
    async def capture() -> ExportedSolution:
        return exported

    monkeypatch.setattr(artifact_module, "export_solution", capture)
    captured_state = _state() if state is None else state
    asyncio.run(capture_generated_output(captured_state))
    return captured_state


def _stored_payload(state: TaskState) -> dict[str, object]:
    value = state.store.get(SAVED_OUTPUT_KEY)
    assert isinstance(value, dict)
    return value


def _evidence_payload(state: TaskState) -> dict[str, object]:
    value = state.store.get(SEMGREP_EVIDENCE_KEY)
    assert isinstance(value, dict)
    return value


def test_scoring_imports_do_not_load_the_sandbox_runner() -> None:
    project_root = Path(__file__).parents[1]
    script = (
        "import sys\n"
        "import codeguard_evals.output_artifact\n"
        "import codeguard_evals.scorers\n"
        "raise SystemExit(int('codeguard_evals.semgrep_runner' in sys.modules))\n"
    )

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=project_root,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr


def test_capture_preserves_model_output_and_stores_validated_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _state()
    original_output = state.output.model_copy(deep=True)
    original_messages = copy.deepcopy(state.messages)

    result = _capture(monkeypatch, _export(), state=state)

    assert result.output == original_output
    assert result.messages == original_messages
    assert result.output.metadata == {
        "provider.request_id": "request-1",
        "provider.tags": ["benchmark"],
    }
    assert load_saved_output(result) == SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        source=SAFE_SOURCE,
        capture_error=None,
    )

    with pytest.raises(BenchmarkInfrastructureError, match="already exists"):
        asyncio.run(capture_generated_output(result))


@pytest.mark.parametrize(
    ("source", "reason", "expected_source", "expected_answer", "explanation"),
    [
        (None, "missing output", None, None, "missing output"),
        (b"", None, "", "", "empty solution"),
    ],
)
def test_missing_and_empty_sources_remain_distinguishable(
    monkeypatch: pytest.MonkeyPatch,
    source: bytes | None,
    reason: str | None,
    expected_source: str | None,
    expected_answer: str | None,
    explanation: str,
) -> None:
    state = _capture(monkeypatch, _export(source, reason=reason))
    save_semgrep_evidence(state, None)
    saved = load_saved_output(state)
    score = asyncio.run(
        static_safety_scorer()(
            state,
            Target(ORIGINAL_SOURCE),
        )
    )

    assert state.output.completion == "agent narration"
    assert saved.source == expected_source
    assert score.answer == expected_answer
    assert score.value["valid_output"] == 0
    assert score.value["loc"] == 0
    assert isinstance(score.value["finding_count"], float)
    assert score.explanation == explanation


def test_replay_requires_saved_output_key() -> None:
    with pytest.raises(BenchmarkInfrastructureError, match="evidence is missing"):
        load_saved_output(_state())


@pytest.mark.parametrize("value", [1, "0.0.0"])
def test_replay_rejects_wrong_evaluation_version(
    monkeypatch: pytest.MonkeyPatch,
    value: object,
) -> None:
    state = _capture(monkeypatch, _export())
    _stored_payload(state)["evaluation_version"] = value

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_saved_output(state)


@pytest.mark.parametrize(
    "mutated",
    [
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": SAFE_SOURCE,
            "capture_error": None,
            "unexpected": True,
        },
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": SAFE_SOURCE,
            "capture_error": "capture failed",
        },
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": None,
            "capture_error": None,
        },
        {
            "evaluation_version": EVALUATION_VERSION,
            "source": 1,
            "capture_error": None,
        },
        ["not", "an", "object"],
    ],
)
def test_replay_rejects_malformed_saved_output(
    monkeypatch: pytest.MonkeyPatch,
    mutated: object,
) -> None:
    state = _capture(monkeypatch, _export())
    state.store.set(SAVED_OUTPUT_KEY, mutated)

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_saved_output(state)


@pytest.mark.parametrize(
    "source",
    [
        "\ud800",
        "#" * (MAX_PYTHON_SOURCE_BYTES + 1),
    ],
)
def test_replay_rejects_unbounded_or_non_utf8_source(
    source: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    _stored_payload(state)["source"] = source

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_saved_output(state)


@pytest.mark.parametrize(
    "findings",
    [
        None,
        (),
        (
            SemgrepFinding(
                rule_id="python.security.rule",
                severity="ERROR",
                line=2,
                subcategory="vuln",
            ),
        ),
    ],
)
def test_semgrep_evidence_preserves_null_empty_and_populated_findings(
    findings: tuple[SemgrepFinding, ...] | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())

    save_semgrep_evidence(state, findings)
    evidence = load_semgrep_evidence(state)

    assert evidence.findings == findings
    assert evidence.source_sha256 == hashlib.sha256(
        SAFE_SOURCE.encode("utf-8")
    ).hexdigest()
    assert evidence.image_digest == SEMGREP_LOCK.image.index_digest
    assert evidence.rules_commit == SEMGREP_LOCK.rules.commit
    assert evidence.rules_tree_sha256 == SEMGREP_LOCK.rules.tree_sha256
    with pytest.raises(BenchmarkInfrastructureError, match="already exists"):
        save_semgrep_evidence(state, findings)


def test_source_free_evidence_requires_null_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export(None))

    save_semgrep_evidence(state, None)
    assert load_semgrep_evidence(state).source_sha256 is None

    payload = _evidence_payload(state)
    payload["findings"] = []
    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_semgrep_evidence(state)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evaluation_version", "0.0.0"),
        ("source_sha256", "0" * 64),
        ("image_digest", "sha256:" + "0" * 64),
        ("rules_commit", "0" * 40),
        ("rules_tree_sha256", "0" * 64),
    ],
)
def test_semgrep_evidence_rejects_version_or_identity_tampering(
    field: str,
    value: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    save_semgrep_evidence(state, ())
    _evidence_payload(state)[field] = value

    message = "evidence is invalid" if field == "evaluation_version" else "identity"
    with pytest.raises(BenchmarkInfrastructureError, match=message):
        load_semgrep_evidence(state)


def test_semgrep_evidence_is_bound_to_saved_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    save_semgrep_evidence(state, ())
    _stored_payload(state)["source"] = SAFE_SOURCE + "# changed\n"

    with pytest.raises(BenchmarkInfrastructureError, match="identity"):
        load_semgrep_evidence(state)


@pytest.mark.parametrize(
    "findings",
    [
        [{"rule_id": "", "severity": "HIGH", "line": 1, "subcategory": "vuln"}],
        [{"rule_id": "rule", "severity": "UNKNOWN", "line": 1, "subcategory": "vuln"}],
        [{"rule_id": "rule", "severity": "HIGH", "line": 0, "subcategory": "vuln"}],
        [{"rule_id": "rule", "severity": "HIGH", "line": 1, "subcategory": "other"}],
    ],
)
def test_semgrep_evidence_strictly_validates_normalized_findings(
    findings: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    save_semgrep_evidence(state, ())
    _evidence_payload(state)["findings"] = findings

    with pytest.raises(BenchmarkInfrastructureError, match="evidence is invalid"):
        load_semgrep_evidence(state)


@pytest.mark.parametrize(
    "exported",
    [
        ExportedSolution(None, None),
        ExportedSolution(SAFE_SOURCE.encode(), "capture failed"),
        ExportedSolution(b"\xff", None),
    ],
)
def test_capture_rejects_inconsistent_exporter_result(
    monkeypatch: pytest.MonkeyPatch,
    exported: ExportedSolution,
) -> None:
    with pytest.raises(BenchmarkInfrastructureError, match="inconsistent"):
        _capture(monkeypatch, exported)


@pytest.mark.parametrize("captured_source", [STUB_SOURCE, SAFE_SOURCE])
def test_public_deferred_scoring_uses_stored_findings_without_any_services(
    captured_source: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    findings: tuple[SemgrepFinding, ...] = ()
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))

    async def capture() -> ExportedSolution:
        return _export(captured_source.encode())

    monkeypatch.setattr(artifact_module, "export_solution", capture)

    @solver
    def capture_for_deferred_scoring() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            del generate
            state.output = ModelOutput.from_content(
                "mockllm/model",
                "agent narration",
            )
            state.output.metadata = {"provider.request_id": "request-1"}
            await capture_generated_output(state)
            save_semgrep_evidence(state, findings)
            return state

        return solve

    task = Task(
        name=securityeval_task_name("baseline"),
        dataset=MemoryDataset(
            [
                Sample(
                    id=SAMPLE_ID,
                    input=TASK_PROMPT,
                    target=ORIGINAL_SOURCE,
                    metadata={
                        "case_id": CASE_ID,
                        "condition": "baseline",
                        "cwe": SAMPLE_CWE,
                    },
                )
            ]
        ),
        solver=capture_for_deferred_scoring(),
        scorer=static_safety_scorer(),
        version=EVALUATION_VERSION,
    )
    generated_dir = tmp_path / "eval-set"
    generated = inspect_eval(
        task,
        model="mockllm/model",
        score=False,
        display="none",
        log_dir=str(generated_dir),
        log_realtime=False,
        ctl_server=False,
    )[0]
    loaded = read_eval_log(generated.location)
    assert loaded.samples is not None
    sample = loaded.samples[0]
    assert sample.scores == {}
    assert sample.output.completion == "agent narration"
    assert sample.output.metadata == {"provider.request_id": "request-1"}
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == (
        captured_source
    )
    assert SemgrepEvidence.model_validate(
        sample.store[SEMGREP_EVIDENCE_KEY]
    ).findings == findings

    inspect_executable = Path(sys.executable).with_name("inspect")
    assert inspect_executable.is_file()
    project_root = Path(__file__).parents[1]
    scorer_path = project_root / "codeguard_evals" / "scorers.py"
    rescored_path = tmp_path / "rescored.eval"
    environment = os.environ.copy()
    for name in (
        "AZUREAI_OPENAI_API_KEY",
        "AZUREAI_OPENAI_API_VERSION",
        "AZUREAI_OPENAI_BASE_URL",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_BASE_URL",
        "AZURE_OPENAI_ENDPOINT",
        "INSPECT_API_KEY_OVERRIDE",
        "INSPECT_TELEMETRY",
        "OPENAI_API_KEY",
        "OPENAI_API_VERSION",
        "OPENAI_BASE_URL",
        "PYTHONPATH",
    ):
        environment.pop(name, None)
    environment["DOCKER_HOST"] = "unix:///nonexistent/codeguard-test.sock"
    result = subprocess.run(
        [
            str(inspect_executable),
            "score",
            generated.location,
            "--model",
            "mockllm/model",
            "--stream",
            "1",
            "--scorer",
            f"{scorer_path}@static_safety_scorer",
            "--action",
            "overwrite",
            "--output-file",
            str(rescored_path),
            "--display",
            "none",
        ],
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr

    rescored = read_eval_log(str(rescored_path))
    assert rescored.samples is not None
    rescored_sample = rescored.samples[0]
    assert rescored_sample.output.completion == "agent narration"
    assert SavedOutput.model_validate(
        rescored_sample.store[SAVED_OUTPUT_KEY]
    ).source == captured_source
    scores = rescored_sample.scores
    assert scores is not None
    replayed = scores["static_safety_scorer"]
    assert replayed.answer == captured_source
    assert replayed.value["valid_output"] == 1
    assert replayed.value["loc"] == 2
    assert replayed.value["finding_count"] == 0


def test_loading_does_not_mutate_saved_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _capture(monkeypatch, _export())
    before = copy.deepcopy(_stored_payload(state))

    load_saved_output(state)

    assert _stored_payload(state) == before
