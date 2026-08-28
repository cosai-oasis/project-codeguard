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
from inspect_ai import Epochs, Task
from inspect_ai import eval as inspect_eval
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import (
    ChatMessage,
    ChatMessageTool,
    ChatMessageUser,
    ModelOutput,
)
from inspect_ai.scorer import Score, Target
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.tool import ToolCallError
from inspect_ai.util import OutputLimitExceededError

import codeguard_evals.sandbox_client as sandbox_client
import codeguard_evals.scorers as scorer_module
from codeguard_evals.codeguard import load_codeguard
from codeguard_evals.output_artifact import (
    SAVED_OUTPUT_KEY,
    SavedOutput,
    save_semgrep_evidence,
)
from codeguard_evals.python_output import validate_python_solution
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
    LOC_METRIC,
    SCORING_PYTHON_VERSION,
    SKILL_LOADED_METRIC,
    VALID_OUTPUT_METRIC,
    static_safety_scorer,
)
from codeguard_evals.securityeval.protocol import (
    CODEGUARD_SKILL_DIR,
    EVALUATION_VERSION,
    TASK_PROMPT,
)
from codeguard_evals.semgrep_artifacts import SemgrepFinding, semgrep_provenance
from tests.conftest import (
    CASE_ID,
    ORIGINAL_SOURCE,
    SAFE_SOURCE,
    SAMPLE_CWE,
    SAMPLE_ID,
    STUB_SOURCE,
    FakeSandbox,
    task_state,
)

_DEFAULT_FINDINGS = object()


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
    findings: tuple[SemgrepFinding, ...] | None | object = _DEFAULT_FINDINGS,
) -> TaskState:
    """Build a sample whose source has already been captured into Inspect."""
    state = task_state(
        sample_id=sample_id,
        input_text=input_text,
        metadata=metadata,
    )
    _save_output(state, source)
    evidence_findings = (
        (
            ()
            if source is not None
            and validate_python_solution(source).valid
            else None
        )
        if findings is _DEFAULT_FINDINGS
        else cast(tuple[SemgrepFinding, ...] | None, findings)
    )
    save_semgrep_evidence(state, evidence_findings)
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
        SemgrepFinding(
            rule_id="rule.high", severity="HIGH", line=1, subcategory="vuln"
        ),
        SemgrepFinding(
            rule_id="rule.secure-default",
            severity="INFO",
            line=2,
            subcategory="secure default",
        ),
        SemgrepFinding(
            rule_id="rule.audit", severity="HIGH", line=2, subcategory="audit"
        ),
        SemgrepFinding(
            rule_id="rule.experiment",
            severity="EXPERIMENT",
            line=2,
            subcategory="vuln",
        ),
        SemgrepFinding(
            rule_id="rule.inventory",
            severity="INVENTORY",
            line=2,
            subcategory="vuln",
        ),
    )


def _score(state: TaskState) -> Score:
    return asyncio.run(static_safety_scorer()(state, Target(ORIGINAL_SOURCE)))


@pytest.mark.parametrize(
    ("source", "expected_valid", "expected_loc", "expected_findings"),
    [
        (None, 0, 0, None),
        ("def generated(command):\n    return (\n", 0, 2, None),
        (STUB_SOURCE, 1, 2, 0),
        (SAFE_SOURCE, 1, 2, 2),
    ],
)
def test_static_safety_scorer_applies_metric_denominators_and_finding_filters(
    source: str | None,
    expected_valid: int,
    expected_loc: int,
    expected_findings: int | None,
) -> None:
    state = _state_with_output(
        source=source,
        findings=(
            _scan_with_findings()
            if expected_findings == 2
            else (() if expected_findings == 0 else None)
        ),
    )
    score = _score(state)
    values = score.as_dict()

    assert values[VALID_OUTPUT_METRIC] == expected_valid
    assert values[LOC_METRIC] == expected_loc
    assert math.isnan(cast(float, values[SKILL_LOADED_METRIC]))
    if expected_findings is None:
        assert isinstance(values[FINDING_COUNT_METRIC], float)
        assert math.isnan(values[FINDING_COUNT_METRIC])
    else:
        assert values[FINDING_COUNT_METRIC] == expected_findings

    if expected_findings == 2:
        assert score.metadata is not None
        assert score.metadata["findings"] == [
            {
                "rule_id": "rule.high",
                "severity": "HIGH",
                "line": 1,
                "subcategory": "vuln",
            },
            {
                "rule_id": "rule.secure-default",
                "severity": "INFO",
                "line": 2,
                "subcategory": "secure default",
            },
            {
                "rule_id": "rule.audit",
                "severity": "HIGH",
                "line": 2,
                "subcategory": "audit",
            },
            {
                "rule_id": "rule.experiment",
                "severity": "EXPERIMENT",
                "line": 2,
                "subcategory": "vuln",
            },
            {
                "rule_id": "rule.inventory",
                "severity": "INVENTORY",
                "line": 2,
                "subcategory": "vuln",
            },
        ]
    assert score.answer == source


def test_static_safety_scorer_records_zero_findings_descriptively() -> None:
    clean = _score(_state_with_output(findings=())).as_dict()
    flagged = _score(_state_with_output(findings=_scan_with_findings())).as_dict()

    assert clean[FINDING_COUNT_METRIC] == 0
    assert flagged[FINDING_COUNT_METRIC] == 2


@pytest.mark.parametrize(
    ("source", "findings"),
    [
        (SAFE_SOURCE, None),
        ("def generated(command):\n    return (\n", ()),
    ],
)
def test_static_safety_scorer_rejects_inconsistent_evidence_applicability(
    source: str | None,
    findings: tuple[SemgrepFinding, ...] | None,
) -> None:
    state = _state_with_output(source=source, findings=findings)

    with pytest.raises(BenchmarkInfrastructureError, match="inconsistent"):
        _score(state)


def test_static_safety_scorer_records_loaded_and_skipped_codeguard_samples(
) -> None:
    codeguard_id = f"static_safety/codeguard/{CASE_ID}"
    metadata = {
        "case_id": CASE_ID,
        "cwe": SAMPLE_CWE,
        "condition": "codeguard",
    }
    expected_skill = load_codeguard()["SKILL.md"].decode("utf-8")
    skill_document = (
        "Script completed\nOutput:\n"
        f"{expected_skill}"
        "\n--- solution.py ---\n"
        "def generated(command): ...\n"
    )

    def state_with_call(
        function: str,
        arguments: dict[str, object],
        *,
        output: str = skill_document,
        source: str | None = SAFE_SOURCE,
        result_id: str = "read-skill",
        tool_error: ToolCallError | None = None,
        parse_error: str | None = None,
    ) -> TaskState:
        state = _state_with_output(
            source=source,
            sample_id=codeguard_id,
            metadata=metadata,
        )
        assistant = ModelOutput.for_tool_call(
            "mockllm/model",
            function,
            arguments,
            tool_call_id="read-skill",
        ).message
        assert assistant.tool_calls is not None
        assistant.tool_calls[0].parse_error = parse_error
        state.messages = [
            assistant,
            ChatMessageTool(
                content=output,
                tool_call_id=result_id,
                function=function,
                error=tool_error,
            ),
        ]
        return state

    skill_path = f"{CODEGUARD_SKILL_DIR}/SKILL.md"
    direct_read = state_with_call(
        "exec_command",
        {"cmd": f"sed -n '1,160p' {skill_path}"},
        source=None,
    )
    wrapped_read = state_with_call(
        "exec",
        {
            "input": (
                "const r = await tools.exec_command({"
                f'cmd:"sed -n \'1,240p\' {skill_path}"'
                "}); text(r.output);"
            )
        },
    )
    skipped = _state_with_output(sample_id=codeguard_id, metadata=metadata)
    path_check_only = state_with_call(
        "exec_command",
        {"cmd": f"test -f {skill_path}"},
        output="Process exited with code 0",
    )
    marker_only_output = state_with_call(
        "exec_command",
        {"cmd": f"cat {skill_path}"},
        output=(
            "Process exited with code 0\n"
            "name: codeguard\n"
            "# CodeGuard Skill\n"
        ),
    )
    unrelated_path = state_with_call(
        "exec_command",
        {"cmd": "cat /tmp/SKILL.md"},
    )
    uncorrelated_read = state_with_call(
        "exec_command",
        {"cmd": f"cat {skill_path}"},
        result_id="different-call",
    )
    errored_read = state_with_call(
        "exec_command",
        {"cmd": f"cat {skill_path}"},
        tool_error=ToolCallError("permission", "permission denied"),
    )
    malformed_call = state_with_call(
        "exec_command",
        {"cmd": f"cat {skill_path}"},
        parse_error="invalid tool arguments",
    )

    direct_values = _score(direct_read).as_dict()
    wrapped_values = _score(wrapped_read).as_dict()
    skipped_values = _score(skipped).as_dict()
    path_check_values = _score(path_check_only).as_dict()
    marker_only_values = _score(marker_only_output).as_dict()
    unrelated_values = _score(unrelated_path).as_dict()
    uncorrelated_values = _score(uncorrelated_read).as_dict()
    errored_values = _score(errored_read).as_dict()
    malformed_values = _score(malformed_call).as_dict()

    assert direct_values[SKILL_LOADED_METRIC] == 1
    assert wrapped_values[SKILL_LOADED_METRIC] == 1
    assert skipped_values[SKILL_LOADED_METRIC] == 0
    assert path_check_values[SKILL_LOADED_METRIC] == 0
    assert marker_only_values[SKILL_LOADED_METRIC] == 0
    assert unrelated_values[SKILL_LOADED_METRIC] == 0
    assert uncorrelated_values[SKILL_LOADED_METRIC] == 0
    assert errored_values[SKILL_LOADED_METRIC] == 0
    assert malformed_values[SKILL_LOADED_METRIC] == 0


def test_static_safety_scorer_records_replayable_scoring_provenance(
) -> None:
    state = _state_with_output(findings=_scan_with_findings())
    score = _score(state)

    assert score.metadata is not None
    assert score.metadata["scoring_python_version"] == SCORING_PYTHON_VERSION
    assert score.metadata["semgrep"] == semgrep_provenance()


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
    def fail_assessment(source: str) -> object:
        del source
        raise ValueError("untrusted source details")

    monkeypatch.setattr(
        scorer_module,
        "validate_python_solution",
        fail_assessment,
    )

    with pytest.raises(RuntimeError, match="could not be assessed") as captured:
        _score(_state_with_output())

    assert "untrusted source details" not in str(captured.value)


def test_static_safety_scorer_requires_durable_semgrep_evidence() -> None:
    state = task_state()
    _save_output(state, SAFE_SOURCE)

    with pytest.raises(
        BenchmarkInfrastructureError,
        match="Semgrep evidence is missing",
    ):
        _score(state)


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
            save_semgrep_evidence(
                state,
                (
                    _scan_with_findings()
                    if source == SAFE_SOURCE
                    else (
                        ()
                        if source is not None
                        and validate_python_solution(source).valid
                        else None
                    )
                ),
            )
            return state

        return solve

    return install()


def test_inspect_aggregates_each_metric_over_its_intended_samples(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    missing_id = "static_safety/baseline/CWE-078_missing_1.py"
    invalid_id = "static_safety/baseline/CWE-078_invalid_1.py"
    clean_id = "static_safety/baseline/CWE-078_clean_1.py"
    flagged_id = "static_safety/baseline/CWE-078_flagged_1.py"
    sources = {
        missing_id: None,
        invalid_id: "def generated(command):\n    return (\n",
        clean_id: STUB_SOURCE,
        flagged_id: SAFE_SOURCE,
    }

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
        clean_id: 1,
        flagged_id: 1,
    }
    assert sum(
        isinstance(value[FINDING_COUNT_METRIC], float)
        and math.isnan(cast(float, value[FINDING_COUNT_METRIC]))
        for value in raw_values.values()
    ) == 2

    assert log.results is not None
    results = {result.name: result for result in log.results.scores}
    assert results[VALID_OUTPUT_METRIC].scored_samples == 4
    assert results[VALID_OUTPUT_METRIC].unscored_samples == 0
    assert results[FINDING_COUNT_METRIC].scored_samples == 2
    assert results[FINDING_COUNT_METRIC].unscored_samples == 2
    assert results[VALID_OUTPUT_METRIC].metrics["mean"].value == 0.5
    assert results[LOC_METRIC].metrics["mean"].value == 1.5
    assert results[FINDING_COUNT_METRIC].metrics["mean"].value == 1.0


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
            # These cluster patterns make clustered and ordinary stderr differ.
            if source == SAFE_SOURCE:
                finding_count = 10
            elif source == stable_source:
                finding_count = 2
            else:
                finding_count = 0
            findings = tuple(
                SemgrepFinding(
                    rule_id=f"rule.{index}",
                    severity="HIGH",
                    line=1,
                    subcategory="vuln",
                )
                for index in range(finding_count)
            )
            save_semgrep_evidence(state, findings)
            return state

        return solve
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
    assert finding_result.scored_samples == 6
    assert finding_result.unscored_samples == 0
    assert finding_result.metrics["mean"].value == pytest.approx(8 / 3)
    assert finding_result.metrics["stderr"].value == pytest.approx(2 / 3)
