"""SecurityEval uses the shared, source-bound scanner transport."""

import asyncio
import hashlib
import json
from types import SimpleNamespace

import pytest
from codeguard_evals.graders import scanner_client as client
from codeguard_evals.graders import semgrep_runner as runner
from codeguard_evals.graders import semgrep_worker
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import SEMGREP_SANDBOX_USER
from codeguard_evals.graders.scanner_worker import worker_sha256
from inspect_ai.util import OutputLimitExceededError, SandboxUnavailableError

from tests.conftest import SAFE_SOURCE, FakeSandbox


@pytest.mark.parametrize("configured,expected", [
    (None, 4.0), ("", 4.0), ("2.0", 2.0),
    ("0", None), ("-1", None), ("nan", None), ("inf", None), ("invalid", None),
])
def test_scanner_cpu_configuration_is_bounded_and_recorded(monkeypatch, configured, expected):
    if configured is None:
        monkeypatch.delenv("CODEGUARD_SCANNER_CPUS", raising=False)
    else:
        monkeypatch.setenv("CODEGUARD_SCANNER_CPUS", configured)
    if expected is None:
        with pytest.raises(BenchmarkInfrastructureError, match="finite positive number"):
            runner.scan_identity()
    else:
        assert runner.scan_identity()["cpus"] == expected


def report():
    return {
        "adapter_sha256": worker_sha256(semgrep_worker.__file__),
        "scans": [
            {
                "language": "python",
                "source_sha256": hashlib.sha256(SAFE_SOURCE.encode()).hexdigest(),
                "complete": True,
                "reason": None,
                "analyzers": ["semgrep"],
                "findings": [],
            }
        ],
    }


@pytest.mark.parametrize(
    "failure",
    [
        None,
        "parse",
        "hash",
        "language",
        "worker",
        "shape",
        "missing",
        "findings",
        "line",
        "stderr",
        "exit",
    ],
)
def test_results_are_bound_and_incomplete_files_are_never_clean(monkeypatch, failure):
    value = report()
    scan = value["scans"][0]
    if failure == "parse":
        scan.update(complete=False, reason="parse_error", analyzers=[], findings=None)
    elif failure == "hash":
        scan["source_sha256"] = "0" * 64
    elif failure == "language":
        scan["language"] = "cpp"
    elif failure == "worker":
        value["adapter_sha256"] = "0" * 64
    elif failure == "shape":
        scan["complete"] = 1
    elif failure == "missing":
        value["scans"] = []
    elif failure in ("findings", "line"):
        scan["findings"] = [
            {
                "rule_id": "rule",
                "line": 3 if failure == "line" else 1,
                "confidence": "UNKNOWN" if failure == "findings" else "HIGH",
                "severity": "ERROR",
                "subcategory": "vuln",
            }
        ]
    environment = FakeSandbox(
        SimpleNamespace(
            returncode=1 if failure == "exit" else 0,
            stdout=json.dumps(value),
            stderr="private diagnostics" if failure == "stderr" else "",
        )
    )
    monkeypatch.setattr(client, "sandbox", lambda name: environment)
    if failure in (None, "parse"):
        assert asyncio.run(runner.scan_sources([SAFE_SOURCE])) == ["parse_error" if failure else ()]
    else:
        with pytest.raises(RuntimeError):
            asyncio.run(runner.scan_sources([SAFE_SOURCE]))
    assert len(environment.calls) == 1
    command, args = environment.calls[0]
    assert command == list(runner.SCANNER_COMMAND) == runner.scan_identity()["command"]
    assert command[-1] == "--batch"
    assert json.loads(args["input"]) == [[SAFE_SOURCE, "python"]]
    assert args["user"] == SEMGREP_SANDBOX_USER and args["cwd"] == client.WORKDIR
    assert args["timeout"] == runner.SEMGREP_TIMEOUT_SECONDS and args["timeout_retry"] is False


@pytest.mark.parametrize(
    "error",
    [
        TimeoutError(),
        OutputLimitExceededError("limit", "private output"),
        PermissionError("private path"),
        RuntimeError("private detail"),
    ],
)
def test_execution_errors_do_not_expose_source_or_provider_details(monkeypatch, error):
    monkeypatch.setattr(client, "sandbox", lambda name: FakeSandbox(error))
    with pytest.raises(RuntimeError) as caught:
        asyncio.run(runner.scan_sources([SAFE_SOURCE]))
    assert "private" not in str(caught.value)


def test_sandbox_loss_and_cancellation_are_preserved(monkeypatch):
    for error in (SandboxUnavailableError("gone"), asyncio.CancelledError()):
        monkeypatch.setattr(client, "sandbox", lambda name: FakeSandbox(error))
        with pytest.raises(type(error)) as caught:
            asyncio.run(runner.scan_sources([SAFE_SOURCE]))
        assert caught.value is error
