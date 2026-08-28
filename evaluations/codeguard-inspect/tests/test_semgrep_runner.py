from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Iterator, cast

import pytest
from inspect_ai.util import OutputLimitExceededError

import codeguard_evals.semgrep_runner as semgrep_runner
from codeguard_evals.sandbox_protocol import (
    MAX_PYTHON_SOURCE_BYTES,
    SEMGREP_SANDBOX_NAME,
    SEMGREP_SANDBOX_USER,
)
from codeguard_evals.semgrep_runner import (
    CONTAINER_RULES_PATH,
    CONTAINER_SOURCE_PATH,
    MAX_SEMGREP_REPORT_BYTES,
    SEMGREP_ENVIRONMENT,
    SEMGREP_JOBS,
    SEMGREP_MAX_MEMORY_MIB,
    SEMGREP_PACKAGE_VERSION,
    SEMGREP_REPORT_CAPTURE_BYTES,
    SEMGREP_RULE_TIMEOUT_SECONDS,
    SEMGREP_RULE_TIMEOUT_THRESHOLD,
    SEMGREP_TIMEOUT_SECONDS,
    scan_source,
)
from tests.conftest import SAFE_SOURCE


def _position(line: int) -> dict[str, int]:
    return {"line": line, "col": 1, "offset": 0}


def _finding(
    *,
    path: str = str(CONTAINER_SOURCE_PATH),
    severity: object = "HIGH",
    line: int = 1,
    end_line: int | None = None,
    rule_id: object = "python.security.test-rule",
    engine_kind: object = "OSS",
    category: object = "security",
    subcategory: object = ("vuln",),
    confidence: object = "MEDIUM",
) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "path": path,
        "start": _position(line),
        "end": _position(line if end_line is None else end_line),
        "extra": {
            "metadata": {
                "category": category,
                "subcategory": list(cast(tuple[object, ...], subcategory)),
                "confidence": confidence,
            },
            "severity": severity,
            "engine_kind": engine_kind,
        },
    }


def _report(
    *,
    results: list[dict[str, object]] | None = None,
    errors: list[object] | None = None,
    scanned: list[str] | None = None,
    skipped: list[object] | None = None,
    skipped_rules: list[object] | None = None,
    version: object = SEMGREP_PACKAGE_VERSION,
    engine_requested: object = "OSS",
    extras: dict[str, object] | None = None,
) -> str:
    value: dict[str, object] = {
        "results": [] if results is None else results,
        "errors": [] if errors is None else errors,
        "paths": {
            "scanned": (
                [str(CONTAINER_SOURCE_PATH)] if scanned is None else scanned
            ),
            "skipped": [] if skipped is None else skipped,
        },
        "version": version,
        "engine_requested": engine_requested,
        "skipped_rules": [] if skipped_rules is None else skipped_rules,
    }
    if extras:
        value.update(extras)
    return json.dumps(value)


class _Sandbox:
    def __init__(
        self,
        *,
        result: SimpleNamespace | None = None,
        write_error: BaseException | None = None,
        exec_error: BaseException | None = None,
    ) -> None:
        self.result = result or SimpleNamespace(
            returncode=0,
            stdout=_report(),
            stderr="",
        )
        self.write_error = write_error
        self.exec_error = exec_error
        self.requested: list[str] = []
        self.writes: list[tuple[str, bytes]] = []
        self.execs: list[tuple[list[str], dict[str, object]]] = []

    async def write_file(self, path: str, content: bytes) -> None:
        if self.write_error is not None:
            raise self.write_error
        self.writes.append((path, content))

    async def exec(
        self,
        command: list[str],
        **kwargs: object,
    ) -> SimpleNamespace:
        if self.exec_error is not None:
            raise self.exec_error
        self.execs.append((command, kwargs))
        return self.result


def _install_sandbox(
    monkeypatch: pytest.MonkeyPatch,
    environment: _Sandbox | None = None,
) -> tuple[_Sandbox, list[tuple[int, tuple[str, ...]]]]:
    installed = _Sandbox() if environment is None else environment
    output_limits: list[tuple[int, tuple[str, ...]]] = []

    def select(name: str) -> _Sandbox:
        installed.requested.append(name)
        return installed

    @contextmanager
    def limit(value: int, *targets: str) -> Iterator[None]:
        output_limits.append((value, targets))
        yield

    monkeypatch.setattr(semgrep_runner, "sandbox", select)
    monkeypatch.setattr(semgrep_runner, "override_sandbox_output_limit", limit)
    monkeypatch.setattr(
        semgrep_runner,
        "load_default_locked_rules_directory",
        lambda: Path("/trusted/python"),
    )
    return installed, output_limits


def test_scan_uses_exact_named_sandbox_contract_and_normalizes_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _report(
        results=[
            _finding(line=2, rule_id="rule.z"),
            _finding(severity="INFO", line=1, rule_id="rule.a"),
            _finding(line=2, rule_id="rule.audit", subcategory=("audit",)),
            _finding(
                category="correctness",
                rule_id="rule.ignored",
                subcategory=(),
                confidence=None,
            ),
        ],
        extras={"profiling_results": [], "future_top_level_field": {}},
    )
    environment, limits = _install_sandbox(
        monkeypatch,
        _Sandbox(
            result=SimpleNamespace(returncode=0, stdout=report, stderr="")
        ),
    )

    findings = asyncio.run(scan_source(SAFE_SOURCE))

    assert environment.requested == [SEMGREP_SANDBOX_NAME]
    assert environment.writes == [
        (str(CONTAINER_SOURCE_PATH), SAFE_SOURCE.encode("utf-8"))
    ]
    assert limits == [(SEMGREP_REPORT_CAPTURE_BYTES, ("exec",))]
    assert environment.execs == [
        (
            [
                "semgrep",
                "scan",
                f"--config={CONTAINER_RULES_PATH}",
                "--json",
                "--quiet",
                "--strict",
                "--oss-only",
                "--metrics=off",
                "--disable-version-check",
                "--no-git-ignore",
                "--disable-nosem",
                "--rewrite-rule-ids",
                f"--jobs={SEMGREP_JOBS}",
                f"--max-memory={SEMGREP_MAX_MEMORY_MIB}",
                f"--max-target-bytes={MAX_PYTHON_SOURCE_BYTES}",
                f"--timeout={SEMGREP_RULE_TIMEOUT_SECONDS}",
                f"--timeout-threshold={SEMGREP_RULE_TIMEOUT_THRESHOLD}",
                str(CONTAINER_SOURCE_PATH),
            ],
            {
                "input": b"",
                "cwd": "/rules",
                "env": dict(SEMGREP_ENVIRONMENT),
                "user": SEMGREP_SANDBOX_USER,
                "timeout": SEMGREP_TIMEOUT_SECONDS,
                "timeout_retry": False,
            },
        )
    ]
    assert [finding.record() for finding in findings] == [
        {
            "rule_id": "rule.a",
            "severity": "INFO",
            "line": 1,
            "subcategory": "vuln",
            "confidence": "MEDIUM",
        },
        {
            "rule_id": "rule.audit",
            "severity": "HIGH",
            "line": 2,
            "subcategory": "audit",
            "confidence": "MEDIUM",
        },
        {
            "rule_id": "rule.z",
            "severity": "HIGH",
            "line": 2,
            "subcategory": "vuln",
            "confidence": "MEDIUM",
        },
    ]
    assert SAFE_SOURCE not in " ".join(environment.execs[0][0])


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (cast(str, 1), "must be text"),
        ("", "must not be empty"),
        (" \n\t", "must not be empty"),
        ("\ud800", "valid UTF-8"),
        ("x" * (MAX_PYTHON_SOURCE_BYTES + 1), "exceeds"),
    ],
)
def test_scan_rejects_invalid_source_before_selecting_sandbox(
    source: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        semgrep_runner,
        "sandbox",
        lambda _name: pytest.fail("invalid source must not reach the sandbox"),
    )

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(scan_source(source))


def test_scan_accepts_exact_source_size_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment, _ = _install_sandbox(monkeypatch)
    source = "#" * MAX_PYTHON_SOURCE_BYTES

    assert asyncio.run(scan_source(source)) == ()
    assert environment.writes[0][1] == source.encode()


def test_scan_requires_the_verified_rules_cache_before_sandbox_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = False

    def select(_name: str) -> object:
        nonlocal selected
        selected = True
        raise AssertionError

    def missing() -> Path:
        raise FileNotFoundError("run prefetch")

    monkeypatch.setattr(semgrep_runner, "sandbox", select)
    monkeypatch.setattr(
        semgrep_runner,
        "load_default_locked_rules_directory",
        missing,
    )

    with pytest.raises(FileNotFoundError, match="prefetch"):
        asyncio.run(scan_source(SAFE_SOURCE))
    assert selected is False


def test_scan_ignores_unconsumed_finding_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _finding()
    finding["future_finding_field"] = {"shape": "irrelevant"}
    extra = cast(dict[str, object], finding["extra"])
    extra["message"] = "not part of the metric"
    environment = _Sandbox(
        result=SimpleNamespace(
            returncode=0,
            stdout=_report(results=[finding]),
            stderr="",
        )
    )
    _install_sandbox(monkeypatch, environment)

    assert [item.record() for item in asyncio.run(scan_source(SAFE_SOURCE))] == [
        {
            "rule_id": "python.security.test-rule",
            "severity": "HIGH",
            "line": 1,
            "subcategory": "vuln",
            "confidence": "MEDIUM",
        }
    ]


@pytest.mark.parametrize("field", ["metadata", "severity", "engine_kind"])
def test_scan_requires_every_consumed_finding_field(
    field: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _finding()
    cast(dict[str, object], finding["extra"]).pop(field)
    environment = _Sandbox(
        result=SimpleNamespace(
            returncode=0,
            stdout=_report(results=[finding]),
            stderr="",
        )
    )
    _install_sandbox(monkeypatch, environment)

    with pytest.raises(RuntimeError, match="malformed JSON"):
        asyncio.run(scan_source(SAFE_SOURCE))


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"version": "0.0.0"}, "unexpected version"),
        ({"engine_requested": "PRO"}, "unexpected engine"),
        ({"errors": [{"message": "parse"}]}, "could not analyse"),
        ({"skipped": [{"path": "/tmp/solution.py"}]}, "skipped the source"),
        ({"skipped_rules": [{"id": "rule"}]}, "skipped locked rules"),
        ({"scanned": []}, "unexpected scanned file"),
    ],
)
def test_scan_fails_closed_on_report_contract_changes(
    change: dict[str, object],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _Sandbox(
        result=SimpleNamespace(
            returncode=0,
            stdout=_report(**change),  # type: ignore[arg-type]
            stderr="",
        )
    )
    _install_sandbox(monkeypatch, environment)

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(scan_source(SAFE_SOURCE))


@pytest.mark.parametrize(
    ("finding", "message"),
    [
        (_finding(path="/tmp/other.py"), "unexpected finding file"),
        (_finding(line=3), "invalid source line"),
        (_finding(line=2, end_line=1), "invalid source line"),
        (_finding(engine_kind="PRO"), "unexpected finding engine"),
        (_finding(severity="UNKNOWN"), "unknown severity"),
        (_finding(category=1), "category is invalid"),
        (_finding(subcategory=()), "subcategory is invalid"),
        (_finding(subcategory=("vuln", "audit")), "subcategory is invalid"),
        (_finding(subcategory=("unknown",)), "subcategory is invalid"),
        (_finding(confidence=None), "confidence is invalid"),
        (_finding(confidence=[]), "confidence is invalid"),
        (_finding(confidence="UNKNOWN"), "confidence is invalid"),
    ],
)
def test_scan_fails_closed_on_invalid_consumed_finding_data(
    finding: dict[str, object],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _Sandbox(
        result=SimpleNamespace(
            returncode=0,
            stdout=_report(results=[finding]),
            stderr="",
        )
    )
    _install_sandbox(monkeypatch, environment)

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(scan_source(SAFE_SOURCE))


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (SimpleNamespace(returncode=2, stdout="{}", stderr=""), "status 2"),
        (SimpleNamespace(returncode=0, stdout="{}", stderr="warning"), "diagnostic"),
        (SimpleNamespace(returncode="0", stdout="{}", stderr=""), "invalid process"),
        (SimpleNamespace(returncode=0, stdout=b"{}", stderr=""), "invalid process"),
        (
            SimpleNamespace(
                returncode=0,
                stdout="x" * (MAX_SEMGREP_REPORT_BYTES + 1),
                stderr="",
            ),
            "exceeded its size limit",
        ),
        (SimpleNamespace(returncode=0, stdout="not json", stderr=""), "malformed JSON"),
    ],
)
def test_scan_rejects_process_and_output_failures(
    result: SimpleNamespace,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_sandbox(monkeypatch, _Sandbox(result=result))

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(scan_source(SAFE_SOURCE))


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (TimeoutError(), "exceeded 120 seconds"),
        (OutputLimitExceededError("too much", "truncated"), "output exceeded"),
        (PermissionError("private path"), "sandbox execution failed"),
        (RuntimeError("private provider detail"), "sandbox execution failed"),
    ],
)
def test_scan_translates_sandbox_failures(
    error: BaseException,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_sandbox(monkeypatch, _Sandbox(exec_error=error))

    with pytest.raises(RuntimeError, match=message) as raised:
        asyncio.run(scan_source(SAFE_SOURCE))
    assert "private" not in str(raised.value)


def test_scan_translates_source_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_sandbox(
        monkeypatch,
        _Sandbox(write_error=PermissionError("private path")),
    )

    with pytest.raises(RuntimeError, match="sandbox execution failed") as error:
        asyncio.run(scan_source(SAFE_SOURCE))
    assert "private path" not in str(error.value)
