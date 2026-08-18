from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, cast

import pytest
from inspect_ai import Epochs, Task, eval as inspect_eval, score as inspect_score
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import (
    ChatMessage,
    ChatMessageTool,
    ChatMessageUser,
    ModelOutput,
)
from inspect_ai.scorer import Score, Target
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import OutputLimitExceededError

import codeguard_evals.sandbox_client as sandbox_client
import codeguard_evals.scorers as scorer_module
from codeguard_evals.output_artifact import (
    GENERATION_LIMIT_KEY,
    SAVED_OUTPUT_KEY,
    SavedOutput,
)
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    export_solution,
)
from codeguard_evals.sandbox_protocol import (
    MAX_EXPORT_REPORT_BYTES,
    MAX_PYTHON_SOURCE_BYTES,
    SANDBOX_NAME,
    SANDBOX_USER,
)
from codeguard_evals.scorers import (
    FINDING_COUNT_METRIC,
    IMPLEMENTED_OUTPUT_METRIC,
    LOC_METRIC,
    SCORING_PYTHON_VERSION,
    SKILL_LOADED_METRIC,
    VALID_OUTPUT_METRIC,
    static_safety_scorer,
)
from codeguard_evals.semgrep_runner import (
    SEMGREP_PACKAGE_VERSION,
    SemgrepFinding,
)
from codeguard_evals.securityeval.protocol import (
    CODEGUARD_SKILL_DIR,
    EVALUATION_VERSION,
    TASK_PROMPT,
)

from tests.conftest import (
    CASE_ID,
    FakeSandbox,
    ORIGINAL_SOURCE,
    SAFE_SOURCE,
    SAMPLE_CWE,
    SAMPLE_ID,
    STUB_SOURCE,
    task_state,
)


def _save_output(state: TaskState, source: str | None) -> None:
    saved = SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        source=source,
        capture_error="missing output" if source is None else None,
    )
    state.store.set(SAVED_OUTPUT_KEY, saved.model_dump(mode="json"))


def _state_with_output(
    *,
    source: str | None = SAFE_SOURCE,
    sample_id: str = SAMPLE_ID,
    input_text: str | list[ChatMessage] = TASK_PROMPT,
    metadata: dict[str, object] | None = None,
) -> TaskState:
    """Build a sample whose source has already been captured into Inspect."""
    state = task_state(
        sample_id=sample_id,
        input_text=input_text,
        metadata=metadata,
    )
    _save_output(state, source)
    return state


def _export_report(source: bytes | None = SAFE_SOURCE.encode()) -> str:
    if source is None:
        return json.dumps(
            {
                "status": "invalid",
                "reason": "missing output",
                "size_bytes": 0,
                "sha256": None,
                "content_base64": None,
            }
        )
    return json.dumps(
        {
            "status": "valid",
            "reason": None,
            "size_bytes": len(source),
            "sha256": hashlib.sha256(source).hexdigest(),
            "content_base64": base64.b64encode(source).decode("ascii"),
        }
    )


# --- export wire protocol ---------------------------------------------------


def test_parse_export_report_requires_matching_bounded_source() -> None:
    exported = sandbox_client._parse_export_report(_export_report())
    assert exported.content == SAFE_SOURCE.encode()
    assert exported.reason is None

    for field, value in (
        ("sha256", "0" * 64),
        ("size_bytes", 999),
        ("content_base64", "!!not-base64!!"),
    ):
        report = json.loads(_export_report())
        report[field] = value
        with pytest.raises(ValueError):
            sandbox_client._parse_export_report(json.dumps(report))


def test_parse_export_report_accepts_explicit_missing_output() -> None:
    exported = sandbox_client._parse_export_report(_export_report(None))

    assert exported.content is None
    assert exported.reason == "missing output"


def test_parse_export_report_rejects_oversized_source() -> None:
    """The host bounds untrusted content even if the exporter reports it as valid."""
    oversized = b"#" * (MAX_PYTHON_SOURCE_BYTES + 1)

    with pytest.raises(ValueError):
        sandbox_client._parse_export_report(_export_report(oversized))


def test_protocol_rejects_duplicate_keys_and_non_standard_numbers() -> None:
    duplicate = (
        '{"status":"invalid","reason":"missing output","reason":"other"'
        ',"size_bytes":0,"sha256":null,"content_base64":null}'
    )
    non_standard = duplicate.replace(
        '"reason":"missing output","reason":"other"', '"reason":"missing output"'
    ).replace('"size_bytes":0', '"size_bytes":NaN')

    for raw in (duplicate, non_standard):
        with pytest.raises(ValueError):
            sandbox_client._parse_export_report(raw)


# --- capture from the agent sandbox -----------------------------------------


def test_export_uses_the_agent_sandbox_with_fixed_argv_and_output_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    agent = FakeSandbox(
        SimpleNamespace(
            success=True,
            stdout=_export_report(),
            stderr="",
            returncode=0,
        )
    )
    limits: list[tuple[int, str]] = []
    sandbox_names: list[str] = []

    @contextmanager
    def output_limit(maximum: int, operation: str) -> Iterator[None]:
        limits.append((maximum, operation))
        yield

    def get_sandbox(name: str) -> FakeSandbox:
        sandbox_names.append(name)
        return agent

    monkeypatch.setattr(sandbox_client, "sandbox", get_sandbox)
    monkeypatch.setattr(sandbox_client, "override_sandbox_output_limit", output_limit)

    exported = asyncio.run(export_solution())

    assert exported.content == SAFE_SOURCE.encode()
    assert sandbox_names == [SANDBOX_NAME]
    expected_command = [
        "/usr/local/bin/python",
        "-I",
        "-m",
        "codeguard_evals.export_solution",
    ]
    assert agent.calls[0][0] == expected_command
    call = agent.calls[0][1]
    assert call["input"] == b""
    assert call["cwd"] == "/"
    assert call["user"] == SANDBOX_USER
    assert call["timeout_retry"] is False
    assert call["env"] == {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": "/tmp",
    }
    assert limits == [(MAX_EXPORT_REPORT_BYTES, "exec")]


@pytest.mark.parametrize("succeeded", [False, True])
def test_export_errors_do_not_expose_untrusted_output(
    monkeypatch: pytest.MonkeyPatch,
    succeeded: bool,
) -> None:
    """Neither a nonzero exit nor unexpected stderr may echo the agent's bytes.

    The two cases take different branches: a failure is reported by status, and
    a success that wrote stderr is rejected separately.
    """
    secret = "do-not-log-generated-content"
    result = SimpleNamespace(
        success=succeeded,
        stdout=_export_report() if succeeded else secret,
        stderr=secret,
        returncode=0 if succeeded else 2,
    )
    monkeypatch.setattr(sandbox_client, "sandbox", lambda name: FakeSandbox(result))

    with pytest.raises(BenchmarkInfrastructureError) as captured:
        asyncio.run(export_solution())

    assert secret not in str(captured.value)


@pytest.mark.parametrize(
    ("result", "message"),
    [
        pytest.param(
            TimeoutError("sensitive timeout details"),
            "exceeded",
            id="timeout",
        ),
        pytest.param(
            OutputLimitExceededError(
                "test output limit",
                "do-not-log-generated-content",
            ),
            "too large",
            id="output-limit",
        ),
        pytest.param(
            SimpleNamespace(
                success=True,
                stdout="\ud800",
                stderr="",
                returncode=0,
            ),
            "invalid UTF-8",
            id="invalid-utf8",
        ),
        pytest.param(
            SimpleNamespace(
                success=True,
                stdout='{"secret":"do-not-log-generated-content"}',
                stderr="",
                returncode=0,
            ),
            "invalid report",
            id="malformed-report",
        ),
    ],
)
def test_export_normalizes_sandbox_failures_without_exposing_details(
    monkeypatch: pytest.MonkeyPatch,
    result: object,
    message: str,
) -> None:
    monkeypatch.setattr(sandbox_client, "sandbox", lambda _name: FakeSandbox(result))

    with pytest.raises(BenchmarkInfrastructureError, match=message) as captured:
        asyncio.run(export_solution())

    error = str(captured.value)
    assert "sensitive timeout details" not in error
    assert "do-not-log-generated-content" not in error


# --- static-safety scoring --------------------------------------------------


def _scan_with_findings() -> tuple[SemgrepFinding, ...]:
    return (
        SemgrepFinding("rule.high", "HIGH", 1),
        SemgrepFinding("rule.info", "INFO", 2),
        SemgrepFinding("rule.experiment", "EXPERIMENT", 2),
        SemgrepFinding("rule.inventory", "INVENTORY", 2),
    )


def _score(state: TaskState) -> Score:
    return asyncio.run(static_safety_scorer()(state, Target(ORIGINAL_SOURCE)))


@pytest.mark.parametrize(
    ("source", "expected_valid", "expected_loc", "expected_implemented"),
    [
        (None, 0, 0, 0),
        ("def generated(command):\n    return (\n", 0, 2, 0),
        (STUB_SOURCE, 1, 2, 0),
        (SAFE_SOURCE, 1, 2, 1),
    ],
)
def test_static_safety_scorer_uses_the_intended_metric_denominators(
    monkeypatch: pytest.MonkeyPatch,
    source: str | None,
    expected_valid: int,
    expected_loc: int,
    expected_implemented: int,
) -> None:
    scanned: list[str] = []

    async def scan(candidate: str) -> tuple[SemgrepFinding, ...]:
        scanned.append(candidate)
        return _scan_with_findings()

    monkeypatch.setattr(scorer_module, "scan_source", scan)
    score = _score(_state_with_output(source=source))
    values = score.as_dict()

    assert values[VALID_OUTPUT_METRIC] == expected_valid
    assert values[LOC_METRIC] == expected_loc
    assert values[IMPLEMENTED_OUTPUT_METRIC] == expected_implemented
    assert math.isnan(cast(float, values[SKILL_LOADED_METRIC]))
    if expected_implemented:
        assert values[FINDING_COUNT_METRIC] == 2
        assert scanned == [SAFE_SOURCE]
        assert score.metadata is not None
        assert score.metadata["findings"] == [
            {"rule_id": "rule.high", "severity": "HIGH", "line": 1},
            {"rule_id": "rule.info", "severity": "INFO", "line": 2},
            {
                "rule_id": "rule.experiment",
                "severity": "EXPERIMENT",
                "line": 2,
            },
            {
                "rule_id": "rule.inventory",
                "severity": "INVENTORY",
                "line": 2,
            },
        ]
    else:
        assert isinstance(values[FINDING_COUNT_METRIC], float)
        assert math.isnan(values[FINDING_COUNT_METRIC])
        assert scanned == []
    assert score.answer == source


def test_static_safety_scorer_records_loaded_and_skipped_codeguard_samples(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return ()

    monkeypatch.setattr(scorer_module, "scan_source", scan)
    codeguard_id = f"static_safety/codeguard/{CASE_ID}"
    metadata = {
        "case_id": CASE_ID,
        "cwe": SAMPLE_CWE,
        "condition": "codeguard",
    }

    def state_with_command(
        command: str,
        *,
        exit_code: int,
        source: str | None = SAFE_SOURCE,
        result_id: str = "read-skill",
    ) -> TaskState:
        state = _state_with_output(
            source=source,
            sample_id=codeguard_id,
            metadata=metadata,
        )
        state.messages = [
            ModelOutput.for_tool_call(
                "mockllm/model",
                "exec_command",
                {"cmd": command},
                tool_call_id="read-skill",
            ).message,
            ChatMessageTool(
                content=f"Process exited with code {exit_code}",
                tool_call_id=result_id,
                function="exec_command",
            ),
        ]
        return state

    skill_path = f"{CODEGUARD_SKILL_DIR}/SKILL.md"
    loaded = state_with_command(
        f"sed -n '1,160p' {skill_path}",
        exit_code=0,
        source=None,
    )
    skipped = _state_with_output(sample_id=codeguard_id, metadata=metadata)
    path_check_only = state_with_command(f"test -f {skill_path}", exit_code=0)
    failed_read = state_with_command(f"cat {skill_path}", exit_code=1)
    failed_read.messages[-1] = ChatMessageTool(
        content=(
            "Process exited with code 1\n"
            "Output:\n"
            "Process exited with code 0"
        ),
        tool_call_id="read-skill",
        function="exec_command",
    )
    uncorrelated_read = state_with_command(
        f"cat {skill_path}",
        exit_code=0,
        result_id="different-call",
    )

    loaded_values = _score(loaded).as_dict()
    skipped_values = _score(skipped).as_dict()
    path_check_values = _score(path_check_only).as_dict()
    failed_read_values = _score(failed_read).as_dict()
    uncorrelated_values = _score(uncorrelated_read).as_dict()

    assert loaded_values[SKILL_LOADED_METRIC] == 1
    assert skipped_values[SKILL_LOADED_METRIC] == 0
    assert path_check_values[SKILL_LOADED_METRIC] == 0
    assert failed_read_values[SKILL_LOADED_METRIC] == 0
    assert uncorrelated_values[SKILL_LOADED_METRIC] == 0


def test_static_safety_scorer_records_replayable_scoring_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return _scan_with_findings()

    monkeypatch.setattr(scorer_module, "scan_source", scan)

    state = _state_with_output()
    state.store.set(GENERATION_LIMIT_KEY, "turn")
    score = _score(state)

    assert score.metadata is not None
    assert score.metadata["generation_limit"] == "turn"
    assert score.metadata["implementation_status"] == "non_stub"
    assert score.metadata["scoring_python_version"] == SCORING_PYTHON_VERSION
    assert score.metadata["stub_classifier"] == "python-ast-obvious-stub"
    assert score.metadata["semgrep"] == {
        "version": SEMGREP_PACKAGE_VERSION,
        "ruleset": "p/security-audit",
        "rules_source": "semgrep-registry",
        "rules_mutable": True,
        "counted_severities": [
            "CRITICAL",
            "ERROR",
            "HIGH",
            "INFO",
            "LOW",
            "MEDIUM",
            "WARNING",
        ],
    }


@pytest.mark.parametrize("invalid_limit", ["working", [], {}])
def test_static_safety_scorer_rejects_invalid_generation_limit(
    invalid_limit: object,
) -> None:
    state = _state_with_output()
    state.store.set(GENERATION_LIMIT_KEY, invalid_limit)

    with pytest.raises(BenchmarkInfrastructureError, match="unsupported limit"):
        _score(state)


@pytest.mark.parametrize(
    "state",
    [
        _state_with_output(input_text="different prompt"),
        _state_with_output(input_text=[ChatMessageUser(content=TASK_PROMPT)]),
    ],
)
def test_static_safety_scorer_rejects_prompt_mismatches(state: TaskState) -> None:
    with pytest.raises(RuntimeError, match="input does not match"):
        _score(state)


def test_static_safety_scorer_rejects_sample_identity_mismatch() -> None:
    with pytest.raises(RuntimeError, match="ID does not match"):
        _score(
            _state_with_output(
                sample_id="static_safety/baseline/other.py",
            )
        )


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "case_id": CASE_ID,
            "condition": "baseline",
        },
        {
            "case_id": CASE_ID,
            "cwe": SAMPLE_CWE,
            "condition": "baseline",
            "unexpected": True,
        },
        {
            "case_id": "case.py",
            "cwe": SAMPLE_CWE,
            "condition": "baseline",
        },
    ],
)
def test_static_safety_scorer_rejects_invalid_sample_metadata(
    metadata: dict[str, object],
) -> None:
    with pytest.raises(RuntimeError, match="metadata is invalid"):
        _score(_state_with_output(metadata=metadata))


def test_static_safety_scorer_rejects_case_cwe_mismatch() -> None:
    metadata = {
        "case_id": CASE_ID,
        "cwe": "CWE-89",
        "condition": "baseline",
    }

    with pytest.raises(RuntimeError, match="CWE does not match"):
        _score(_state_with_output(metadata=metadata))


def test_static_safety_scorer_fails_closed_on_assessment_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scanned = False

    def fail_assessment(source: str, *, original: str) -> object:
        del source, original
        raise ValueError("untrusted source details")

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        nonlocal scanned
        scanned = True
        return _scan_with_findings()

    monkeypatch.setattr(
        scorer_module,
        "validate_python_solution",
        fail_assessment,
    )
    monkeypatch.setattr(scorer_module, "scan_source", scan)

    with pytest.raises(RuntimeError, match="could not be assessed") as captured:
        _score(_state_with_output())

    assert "untrusted source details" not in str(captured.value)
    assert scanned is False


def test_static_safety_scorer_propagates_scanner_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fail_scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise RuntimeError("Semgrep exited with status 2; verify registry access")

    monkeypatch.setattr(scorer_module, "scan_source", fail_scan)

    with pytest.raises(RuntimeError, match="status 2"):
        _score(_state_with_output())


def test_static_safety_scorer_rejects_missing_artifact() -> None:
    with pytest.raises(BenchmarkInfrastructureError, match="missing"):
        _score(task_state())


def _captured_outputs(sources: dict[str, str | None]) -> Solver:
    @solver
    def install() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            del generate
            sample_id = str(state.sample_id)
            source = sources[sample_id]
            state.output = ModelOutput.from_content(
                "mockllm/model",
                "agent narration",
            )
            _save_output(state, source)
            return state

        return solve

    return install()


def test_inspect_preserves_captured_output_when_scanning_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))

    async def fail_scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise RuntimeError("Semgrep exited with status 2; verify registry access")

    monkeypatch.setattr(scorer_module, "scan_source", fail_scan)
    task = Task(
        name="static_safety_scanner_failure",
        dataset=MemoryDataset(
            [
                Sample(
                    id=SAMPLE_ID,
                    input=TASK_PROMPT,
                    target=ORIGINAL_SOURCE,
                    metadata={
                        "case_id": CASE_ID,
                        "cwe": SAMPLE_CWE,
                        "condition": "baseline",
                    },
                )
            ]
        ),
        solver=_captured_outputs({SAMPLE_ID: SAFE_SOURCE}),
        scorer=static_safety_scorer(),
        fail_on_error=True,
        continue_on_fail=True,
        score_on_error=False,
    )

    log = inspect_eval(
        task,
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
        log_realtime=False,
        ctl_server=False,
    )[0]

    assert log.status == "error"
    assert log.samples is not None and len(log.samples) == 1
    sample = log.samples[0]
    assert sample.error is not None
    assert "Semgrep exited with status 2" in sample.error.message
    assert sample.output.completion == "agent narration"
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == (
        SAFE_SOURCE
    )
    assert sample.scores == {}

    async def healthy_scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return ()

    monkeypatch.setattr(scorer_module, "scan_source", healthy_scan)
    rescored = inspect_score(
        log,
        static_safety_scorer(),
        model="mockllm/model",
        action="overwrite",
        display="none",
    )

    assert rescored.status == "error"
    assert rescored.samples is not None
    rescored_sample = rescored.samples[0]
    assert rescored_sample.error is not None
    assert rescored_sample.scores is not None
    recovered = rescored_sample.scores["static_safety_scorer"]
    assert recovered.answer == SAFE_SOURCE
    assert recovered.value[FINDING_COUNT_METRIC] == 0


def test_inspect_aggregates_each_metric_over_its_intended_samples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    missing_id = "static_safety/baseline/CWE-078_missing_1.py"
    invalid_id = "static_safety/baseline/CWE-078_invalid_1.py"
    stub_id = "static_safety/baseline/CWE-078_stub_1.py"
    implemented_id = "static_safety/baseline/CWE-078_implemented_1.py"
    sources = {
        missing_id: None,
        invalid_id: "def generated(command):\n    return (\n",
        stub_id: STUB_SOURCE,
        implemented_id: SAFE_SOURCE,
    }

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return _scan_with_findings()

    monkeypatch.setattr(scorer_module, "scan_source", scan)
    samples = [
        Sample(
            id=sample_id,
            input=TASK_PROMPT,
            target=ORIGINAL_SOURCE,
            metadata={
                "case_id": sample_id.rsplit("/", 1)[1],
                "cwe": SAMPLE_CWE,
                "condition": "baseline",
            },
        )
        for sample_id in sources
    ]
    task = Task(
        name="static_safety_metric_aggregation",
        dataset=MemoryDataset(samples),
        solver=_captured_outputs(sources),
        scorer=static_safety_scorer(),
    )

    log = inspect_eval(
        task,
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
        log_realtime=False,
        ctl_server=False,
    )[0]

    assert log.status == "success", log.error
    assert log.samples is not None
    raw_values = {
        str(sample.id): cast(
            dict[str, object],
            sample.scores["static_safety_scorer"].value,
        )
        for sample in log.samples
        if sample.scores is not None
    }
    assert {
        sample_id: value[VALID_OUTPUT_METRIC]
        for sample_id, value in raw_values.items()
    } == {
        missing_id: 0,
        invalid_id: 0,
        stub_id: 1,
        implemented_id: 1,
    }
    assert {
        sample_id: value[IMPLEMENTED_OUTPUT_METRIC]
        for sample_id, value in raw_values.items()
    } == {
        missing_id: 0,
        invalid_id: 0,
        stub_id: 0,
        implemented_id: 1,
    }
    assert sum(
        isinstance(value[FINDING_COUNT_METRIC], float)
        and math.isnan(cast(float, value[FINDING_COUNT_METRIC]))
        for value in raw_values.values()
    ) == 3

    assert log.results is not None
    results = {result.name: result for result in log.results.scores}
    assert results[VALID_OUTPUT_METRIC].scored_samples == 4
    assert results[VALID_OUTPUT_METRIC].unscored_samples == 0
    assert results[IMPLEMENTED_OUTPUT_METRIC].scored_samples == 4
    assert results[IMPLEMENTED_OUTPUT_METRIC].unscored_samples == 0
    assert results[FINDING_COUNT_METRIC].scored_samples == 1
    assert results[FINDING_COUNT_METRIC].unscored_samples == 3
    assert results[VALID_OUTPUT_METRIC].metrics["mean"].value == 0.5
    assert results[LOC_METRIC].metrics["mean"].value == 1.5
    assert results[IMPLEMENTED_OUTPUT_METRIC].metrics["mean"].value == 0.25
    assert results[FINDING_COUNT_METRIC].metrics["mean"].value == 2.0


def test_inspect_aggregates_epochs_as_clustered_generations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    variable_id = "static_safety/baseline/CWE-078_variable_1.py"
    stable_id = "static_safety/baseline/CWE-078_stable_1.py"
    stable_source = "def generated(command):\n    return repr(command)\n"

    @solver
    def capture_epoch_output() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            del generate
            sample_id = str(state.sample_id)
            if sample_id == variable_id:
                source = SAFE_SOURCE if state.epoch == 1 else STUB_SOURCE
            elif sample_id == stable_id:
                source = stable_source
            else:
                raise AssertionError(f"Unexpected sample ID: {sample_id}")
            _save_output(state, source)
            return state

        return solve

    async def scan(source: str) -> tuple[SemgrepFinding, ...]:
        findings = (
            tuple(
                SemgrepFinding(f"rule.{index}", "HIGH", 1)
                for index in range(10)
            )
            if source == SAFE_SOURCE
            else ()
        )
        return findings

    monkeypatch.setattr(scorer_module, "scan_source", scan)
    samples = [
        Sample(
            id=sample_id,
            input=TASK_PROMPT,
            target=ORIGINAL_SOURCE,
            metadata={
                "case_id": sample_id.rsplit("/", 1)[1],
                "cwe": SAMPLE_CWE,
                "condition": "baseline",
            },
        )
        for sample_id in (variable_id, stable_id)
    ]
    task = Task(
        name="static_safety_epoch_aggregation",
        dataset=MemoryDataset(samples),
        solver=capture_epoch_output(),
        scorer=static_safety_scorer(),
        epochs=Epochs(3, []),
    )

    log = inspect_eval(
        task,
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
        log_realtime=False,
        ctl_server=False,
    )[0]

    assert log.status == "success", log.error
    assert log.samples is not None
    assert len(log.samples) == 6
    assert log.results is not None
    results = {result.name: result for result in log.results.scores}
    finding_result = results[FINDING_COUNT_METRIC]
    assert finding_result.scored_samples == 4
    assert finding_result.unscored_samples == 2
    assert finding_result.metrics["mean"].value == pytest.approx(2.5)
    assert finding_result.metrics["stderr"].value == pytest.approx(3.75)
