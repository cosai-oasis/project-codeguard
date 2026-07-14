from __future__ import annotations

import asyncio
import copy
import math
from pathlib import Path

import pytest
from inspect_ai import Task, eval as inspect_eval
from inspect_ai.dataset import Sample
from inspect_ai.model import ChatMessage, ModelName, ModelOutput, StopReason, get_model
from inspect_ai.scorer import Target
from inspect_ai.solver import TaskState, generate

import codeguard_evals.bandit as scorer_module
from codeguard_evals.bandit import (
    REPORTED_FILENAME,
    bandit_cwe,
    parse_bandit_report,
    run_bandit,
)

PROMPT = "def generated(command):\n    pass\n"
DETECTED_SOURCE = (
    "import subprocess\n\n"
    "def generated(command):\n"
    "    return subprocess.run(command, shell=True)  # nosec\n"
)

def _state(
    source: str,
    *,
    cwe: str = "CWE-78",
    condition: str = "baseline",
    generation_error: str | None = None,
    stop_reason: StopReason = "stop",
) -> TaskState:
    output = ModelOutput.from_content(
        "mockllm/model",
        source,
        stop_reason=stop_reason,
    )
    output.error = generation_error
    return TaskState(
        model=ModelName("mockllm/model"),
        sample_id=f"{condition}/case.py",
        epoch=1,
        input=PROMPT,
        messages=[],
        output=output,
        metadata={"case_id": "case.py", "cwe": cwe, "condition": condition},
    )


def _finding(
    filename: str = REPORTED_FILENAME, cwe: int = 78
) -> dict[str, object]:
    return {
        "code": "1 import subprocess\n",
        "col_offset": 0,
        "end_col_offset": 17,
        "filename": filename,
        "issue_confidence": "HIGH",
        "issue_cwe": {
            "id": cwe,
            "link": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
        },
        "issue_severity": "LOW",
        "issue_text": "Unsafe subprocess use.",
        "line_number": 1,
        "line_range": [1],
        "more_info": "https://bandit.readthedocs.io/",
        "test_id": "B404",
        "test_name": "blacklist",
    }


def _report() -> dict[str, object]:
    return {
        "errors": [],
        "generated_at": "2026-07-13T00:00:00Z",
        "metrics": {"_totals": {}, REPORTED_FILENAME: {}},
        "results": [_finding()],
    }


def test_parse_bandit_report_preserves_findings() -> None:
    findings, error = parse_bandit_report(_report())

    assert error is None
    assert findings[0].metadata() == {
        "rule_id": "B404",
        "cwe": "CWE-78",
        "severity": "LOW",
        "confidence": "HIGH",
        "line": 1,
        "message": "Unsafe subprocess use.",
    }


@pytest.mark.parametrize("mutation", ["missing_file", "unknown_result", "bad_cwe"])
def test_parse_bandit_report_rejects_malformed_data(mutation: str) -> None:
    report = copy.deepcopy(_report())
    if mutation == "missing_file":
        del report["metrics"][REPORTED_FILENAME]
    elif mutation == "unknown_result":
        report["results"][0]["filename"] = "./unknown.py"
    else:
        report["results"][0]["issue_cwe"]["id"] = True

    with pytest.raises(ValueError):
        parse_bandit_report(report)


def test_parse_bandit_report_returns_file_error() -> None:
    report = _report()
    report["results"] = []
    report["errors"] = [
        {"filename": REPORTED_FILENAME, "reason": "could not parse"}
    ]

    findings, error = parse_bandit_report(report)

    assert findings == []
    assert error == "could not parse"


def test_bandit_ignore_nosec_prevents_generated_suppression() -> None:
    findings, error = asyncio.run(run_bandit(DETECTED_SOURCE))

    assert error is None
    assert any(finding.cwe == "CWE-78" for finding in findings)


def test_bandit_does_not_execute_generated_source(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"

    _, error = asyncio.run(run_bandit(source))

    assert error is None
    assert not marker.exists()


def test_bandit_stops_when_report_exceeds_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(scorer_module, "MAX_BANDIT_REPORT_BYTES", 16)
    monkeypatch.setattr(
        scorer_module,
        "_BANDIT_COMMAND",
        (scorer_module.sys.executable, "-c", "print('x' * 1000)"),
    )

    findings, error = asyncio.run(run_bandit("pass\n"))

    assert findings == []
    assert error == "Bandit report exceeds 16 bytes"


def test_bandit_stops_at_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scorer_module, "BANDIT_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(
        scorer_module,
        "_BANDIT_COMMAND",
        (scorer_module.sys.executable, "-c", "import time; time.sleep(60)"),
    )

    findings, error = asyncio.run(run_bandit("pass\n"))

    assert findings == []
    assert error == "Bandit exceeded 0.01 seconds"


@pytest.mark.parametrize(
    ("target_cwe", "expected"),
    [("CWE-78", 1), ("CWE-79", 0)],
)
def test_scorer_reports_target_cwe_detection(
    target_cwe: str, expected: int
) -> None:
    score = asyncio.run(
        bandit_cwe()(_state(DETECTED_SOURCE, cwe=target_cwe), Target(PROMPT))
    )

    assert score.value == {"valid_output": 1, "target_cwe_detected": expected}
    assert score.metadata["status"] == "scored"
    assert score.metadata["findings"]


def test_scorer_keeps_invalid_output_out_of_detection_rate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def unexpected(source: str) -> tuple[list[object], str | None]:
        raise AssertionError("Bandit must not run for invalid output")

    monkeypatch.setattr(scorer_module, "run_bandit", unexpected)
    score = asyncio.run(bandit_cwe()(_state(PROMPT), Target(PROMPT)))

    assert score.value["valid_output"] == 0
    assert math.isnan(score.value["target_cwe_detected"])
    assert score.metadata["status"] == "invalid_output"


def test_scorer_treats_generation_error_as_invalid() -> None:
    score = asyncio.run(
        bandit_cwe()(
            _state(DETECTED_SOURCE, generation_error="model failed"),
            Target(PROMPT),
        )
    )

    assert score.value["valid_output"] == 0
    assert math.isnan(score.value["target_cwe_detected"])
    assert score.explanation == "generation failed: model failed"


def test_scorer_treats_truncated_generation_as_invalid() -> None:
    score = asyncio.run(
        bandit_cwe()(
            _state(DETECTED_SOURCE, stop_reason="max_tokens"),
            Target(PROMPT),
        )
    )

    assert score.value["valid_output"] == 0
    assert math.isnan(score.value["target_cwe_detected"])
    assert score.explanation == "generation stopped with max_tokens"


def test_scorer_keeps_analyzer_errors_out_of_detection_rate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failed(source: str) -> tuple[list[object], str | None]:
        return [], "Bandit timed out"

    monkeypatch.setattr(scorer_module, "run_bandit", failed)

    score = asyncio.run(bandit_cwe()(_state(DETECTED_SOURCE), Target(PROMPT)))

    assert score.value["valid_output"] == 1
    assert math.isnan(score.value["target_cwe_detected"])
    assert score.metadata["status"] == "analyzer_error"


def test_inspect_reports_grouped_condition_metrics_with_mockllm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "inspect-trace.log"))

    def output(messages: list[ChatMessage], *args: object) -> ModelOutput:
        source = PROMPT if messages[-1].text == "invalid" else DETECTED_SOURCE
        return ModelOutput.from_content("mockllm/model", source)

    samples = [
        Sample(
            id=f"{condition}/case.py",
            input=PROMPT,
            target=PROMPT,
            metadata={
                "case_id": "case.py",
                "cwe": "CWE-79" if condition == "generic" else "CWE-78",
                "condition": condition,
            },
        )
        for condition in ("baseline", "generic", "codeguard")
    ]
    samples.append(
        Sample(
            id="baseline/invalid.py",
            input="invalid",
            target=PROMPT,
            metadata={
                "case_id": "invalid.py",
                "cwe": "CWE-78",
                "condition": "baseline",
            },
        )
    )
    log = inspect_eval(
        Task(dataset=samples, solver=generate(), scorer=bandit_cwe()),
        model=get_model("mockllm/model", custom_outputs=output),
        log_dir=str(tmp_path / "logs"),
        log_realtime=False,
        display="none",
    )[0]

    assert log.status == "success"
    assert log.results is not None
    results = {score.name: score for score in log.results.scores}
    assert set(results) == {"valid_output", "target_cwe_detected"}
    assert results["valid_output"].scored_samples == 4
    assert results["target_cwe_detected"].scored_samples == 3
    assert {
        metric.name: metric.value
        for metric in results["valid_output"].metrics.values()
    } == {"baseline": 0.5, "generic": 1, "codeguard": 1}
    assert {
        metric.name: metric.value
        for metric in results["target_cwe_detected"].metrics.values()
    } == {"baseline": 1, "generic": 0, "codeguard": 1}
