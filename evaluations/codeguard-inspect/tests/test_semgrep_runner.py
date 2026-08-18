from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import codeguard_evals.semgrep_runner as semgrep_runner
from codeguard_evals.sandbox_protocol import (
    MAX_PYTHON_SOURCE_BYTES,
    SOURCE_FILENAME,
)
from codeguard_evals.semgrep_runner import (
    MAX_SEMGREP_REPORT_BYTES,
    SEMGREP_INSTALL_COMMAND,
    SEMGREP_JOBS,
    SEMGREP_MAX_MEMORY_MIB,
    SEMGREP_PACKAGE_VERSION,
    SEMGREP_REPORT_CAPTURE_BYTES,
    SEMGREP_RULESET,
    SEMGREP_TIMEOUT_SECONDS,
    scan_source,
)
from tests.conftest import SAFE_SOURCE


def _position(line: int, *, col: int = 1, offset: int = 0) -> dict[str, int]:
    return {"line": line, "col": col, "offset": offset}


def _finding(
    *,
    path: str = SOURCE_FILENAME,
    severity: str = "HIGH",
    line: int = 1,
    end_line: int | None = None,
    rule_id: str = "python.security.test-rule",
) -> dict[str, object]:
    return {
        "check_id": rule_id,
        "path": path,
        "start": _position(line),
        "end": _position(line if end_line is None else end_line, col=2, offset=1),
        "extra": {
            "message": "untrusted scanner message",
            "metadata": {},
            "severity": severity,
            "fingerprint": "opaque-fingerprint",
            "lines": "untrusted source line",
        },
    }


def _report(
    *,
    results: list[dict[str, object]] | None = None,
    errors: list[object] | None = None,
    scanned: list[str] | None = None,
    skipped: list[object] | None = None,
    version: str = SEMGREP_PACKAGE_VERSION,
) -> bytes:
    return json.dumps(
        {
            "results": [] if results is None else results,
            "errors": [] if errors is None else errors,
            "paths": {
                "scanned": [SOURCE_FILENAME] if scanned is None else scanned,
                "skipped": skipped,
            },
            "version": version,
            "skipped_rules": [],
            "profiling_results": [],
        }
    ).encode("utf-8")


def _install_semgrep_cli(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    executable = tmp_path / "semgrep"
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr(semgrep_runner.sys, "executable", str(tmp_path / "python"))
    return executable.resolve()


def test_scan_uses_a_fixed_bounded_command_and_private_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executable = _install_semgrep_cli(tmp_path, monkeypatch)
    observed: dict[str, object] = {}

    async def run(command: list[str], **arguments: object) -> SimpleNamespace:
        observed["command"] = command
        observed.update(arguments)
        cwd = cast(Path, arguments["cwd"])
        source_path = cwd / SOURCE_FILENAME
        observed["source"] = source_path.read_text(encoding="utf-8")
        observed["source_mode"] = stat.S_IMODE(source_path.stat().st_mode)
        return SimpleNamespace(
            returncode=0,
            stdout=_report(
                results=[
                    _finding(line=2, rule_id="rule.z"),
                    _finding(severity="INFO", line=1, rule_id="rule.a"),
                ]
            ),
            stderr=b"",
        )

    monkeypatch.setattr(semgrep_runner, "subprocess", run)

    findings = asyncio.run(scan_source(SAFE_SOURCE))

    assert observed["source"] == SAFE_SOURCE
    assert observed["source_mode"] == 0o600
    assert observed["text"] is False
    assert observed["capture_output"] is True
    assert observed["output_limit"] == SEMGREP_REPORT_CAPTURE_BYTES
    assert observed["timeout"] == SEMGREP_TIMEOUT_SECONDS
    assert "env" not in observed

    command = cast(list[str], observed["command"])
    assert command[:2] == [str(semgrep_runner.ENV_EXECUTABLE), "-i"]
    executable_index = command.index(str(executable))
    assignments = dict(
        assignment.split("=", 1) for assignment in command[2:executable_index]
    )
    cwd = cast(Path, observed["cwd"])
    assert assignments == {
        "HOME": str(cwd / "state" / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": f"{executable.parent}{os.pathsep}{os.defpath}",
        "PYTHONUTF8": "1",
        "TMPDIR": str(cwd / "state" / "tmp"),
    }
    assert command[executable_index:] == [
        str(executable),
        "scan",
        f"--config={SEMGREP_RULESET}",
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--disable-nosem",
        "--quiet",
        f"--jobs={SEMGREP_JOBS}",
        f"--max-memory={SEMGREP_MAX_MEMORY_MIB}",
        f"--max-target-bytes={MAX_PYTHON_SOURCE_BYTES}",
        SOURCE_FILENAME,
    ]
    assert [finding.record() for finding in findings] == [
        {"rule_id": "rule.a", "severity": "INFO", "line": 1},
        {"rule_id": "rule.z", "severity": "HIGH", "line": 2},
    ]


def test_scan_closes_source_descriptor_when_stream_creation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)
    wrapped_descriptor: int | None = None
    descriptor_closed = False
    real_close = os.close

    def fail_fdopen(
        descriptor: int,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal wrapped_descriptor
        del args, kwargs
        wrapped_descriptor = descriptor
        raise OSError("sensitive stream failure")

    def record_close(descriptor: int) -> None:
        nonlocal descriptor_closed
        if descriptor == wrapped_descriptor and not descriptor_closed:
            descriptor_closed = True
        real_close(descriptor)

    monkeypatch.setattr(semgrep_runner.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(semgrep_runner.os, "close", record_close)

    with pytest.raises(RuntimeError, match="Could not prepare source") as captured:
        asyncio.run(scan_source(SAFE_SOURCE))

    assert wrapped_descriptor is not None
    assert descriptor_closed
    assert "sensitive stream failure" not in str(captured.value)


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
def test_scan_rejects_invalid_sources_before_starting_semgrep(
    source: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = False

    async def run(*args: object, **kwargs: object) -> SimpleNamespace:
        nonlocal started
        started = True
        raise AssertionError((args, kwargs))

    monkeypatch.setattr(semgrep_runner, "subprocess", run)

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(scan_source(source))

    assert started is False


def test_scan_accepts_the_exact_source_size_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)

    async def run(*args: object, **arguments: object) -> SimpleNamespace:
        del args, arguments
        return SimpleNamespace(returncode=0, stdout=_report(), stderr=b"")

    monkeypatch.setattr(semgrep_runner, "subprocess", run)
    source = "#" * MAX_PYTHON_SOURCE_BYTES

    assert asyncio.run(scan_source(source)) == ()


def test_scan_timeout_and_start_failures_are_concise(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)

    async def time_out(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        raise TimeoutError

    monkeypatch.setattr(semgrep_runner, "subprocess", time_out)
    with pytest.raises(RuntimeError, match=f"exceeded {SEMGREP_TIMEOUT_SECONDS}"):
        asyncio.run(scan_source(SAFE_SOURCE))

    async def cannot_start(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        raise OSError("sensitive host path")

    monkeypatch.setattr(semgrep_runner, "subprocess", cannot_start)
    with pytest.raises(RuntimeError, match="could not be started") as captured:
        asyncio.run(scan_source(SAFE_SOURCE))
    assert "sensitive host path" not in str(captured.value)


def test_scan_does_not_mask_resource_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)

    async def exhaust_memory(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        raise MemoryError("resource exhausted")

    monkeypatch.setattr(semgrep_runner, "subprocess", exhaust_memory)

    with pytest.raises(MemoryError, match="resource exhausted"):
        asyncio.run(scan_source(SAFE_SOURCE))


def test_missing_semgrep_reports_only_the_install_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(semgrep_runner.sys, "executable", str(tmp_path / "python"))

    with pytest.raises(RuntimeError, match="Semgrep is not installed") as captured:
        asyncio.run(scan_source(SAFE_SOURCE))

    assert SEMGREP_INSTALL_COMMAND in str(captured.value)
    assert str(tmp_path) not in str(captured.value)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_scan_rejects_output_beyond_the_capture_sentinel(
    stream: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)
    output = b"x" * (MAX_SEMGREP_REPORT_BYTES + 1)

    async def run(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        return SimpleNamespace(
            returncode=0,
            stdout=output if stream == "stdout" else _report(),
            stderr=output if stream == "stderr" else b"",
        )

    monkeypatch.setattr(semgrep_runner, "subprocess", run)

    with pytest.raises(RuntimeError, match="size limit"):
        asyncio.run(scan_source(SAFE_SOURCE))


@pytest.mark.parametrize(
    ("result", "message"),
    [
        (SimpleNamespace(returncode=2, stdout=b"secret", stderr=b"secret"), "status 2"),
        (
            SimpleNamespace(returncode=0, stdout=_report(), stderr=b"secret"),
            "diagnostic output",
        ),
        (
            SimpleNamespace(returncode=0, stdout=b"secret", stderr=b""),
            "malformed JSON",
        ),
        (
            SimpleNamespace(
                returncode=0,
                stdout=_report(errors=[{"message": "secret"}]),
                stderr=b"",
            ),
            "could not analyse",
        ),
    ],
)
def test_scan_errors_do_not_echo_untrusted_process_output(
    result: SimpleNamespace,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)

    async def run(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        return result

    monkeypatch.setattr(semgrep_runner, "subprocess", run)

    with pytest.raises(RuntimeError, match=message) as captured:
        asyncio.run(scan_source(SAFE_SOURCE))
    assert "secret" not in str(captured.value)


@pytest.mark.parametrize(
    ("stdout", "message"),
    [
        (
            b'{"results":[],"results":[],"errors":[],"paths":'
            b'{"scanned":["solution.py"]},"version":"ignored"}',
            "malformed JSON",
        ),
        (
            json.dumps(
                {
                    "results": [],
                    "errors": [],
                    "paths": {"scanned": [SOURCE_FILENAME]},
                    "version": SEMGREP_PACKAGE_VERSION,
                    "unexpected": True,
                }
            ).encode(),
            "malformed JSON",
        ),
        (_report(version="0.0.0"), "unexpected version"),
        (_report(scanned=["other.py"]), "unexpected scanned file"),
        (
            _report(scanned=[SOURCE_FILENAME, SOURCE_FILENAME]),
            "unexpected scanned file",
        ),
        (_report(skipped=[{"path": SOURCE_FILENAME}]), "skipped the source"),
        (
            _report(results=[_finding(path="other.py")]),
            "unexpected finding file",
        ),
        (
            _report(results=[_finding(line=3)]),
            "invalid source line",
        ),
        (
            _report(results=[_finding(line=2, end_line=1)]),
            "malformed JSON",
        ),
        (
            _report(results=[_finding(severity="UNKNOWN")]),
            "unknown severity",
        ),
    ],
)
def test_scan_rejects_inconsistent_reports(
    stdout: bytes,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_semgrep_cli(tmp_path, monkeypatch)

    async def run(*args: object, **kwargs: object) -> SimpleNamespace:
        del args, kwargs
        return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")

    monkeypatch.setattr(semgrep_runner, "subprocess", run)

    with pytest.raises(RuntimeError, match=message):
        asyncio.run(scan_source(SAFE_SOURCE))
