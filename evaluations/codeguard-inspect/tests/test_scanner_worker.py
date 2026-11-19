"""Shared scanner protocol checks; no Docker or provider calls."""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from codeguard_evals.graders import scanner_worker as worker
from codeguard_evals.graders import semgrep_worker as securityeval
from codeguard_evals.sandbox_protocol import MAX_SOURCE_BYTES
from codeguard_evals.graders.scanner_worker import (
    ScannerError,
    read_limited,
    validate_semgrep_report,
)


def semgrep_report():
    return {
        "version": "1.173.0",
        "engine_requested": "OSS",
        "results": [],
        "errors": [],
        "paths": {"scanned": ["/tmp/solution.py"], "skipped": []},
        "skipped_rules": [],
    }


@pytest.mark.parametrize(
    "kind,code,reason",
    [
        ("Syntax error", 3, "parse_error"),
        ("Lexical error", 3, "parse_error"),
        ("Other syntax error", 2, "parse_error"),
        ("AST builder error", 2, "parse_error"),
        (["PartialParsing", [{"path": "/tmp/solution.py"}]], 3, "parse_error"),
        ("Timeout", 2, "rule_timeout"),
        ("Too many matches", 2, "resource_limit"),
        ("Fixpoint timeout", 2, "resource_limit"),
        ("Stack overflow", 2, "resource_limit"),
        ("Out of memory", 2, "resource_limit"),
    ],
)
def test_only_recognized_target_errors_are_terminal_outcomes(kind, code, reason):
    path = Path("/tmp/solution.py")
    report = semgrep_report()
    error = {"type": kind, "code": code, "level": "warn", "path": str(path)}
    if kind == "Timeout":
        error["rule_id"] = "fixture-rule"
    report["errors"] = [error]
    _, failures = validate_semgrep_report(json.dumps(report).encode(), {path: 2}, code)
    assert failures == {path: reason}
    # A crash or wrong-target error must never inherit the terminal classification.
    with pytest.raises(ScannerError):
        validate_semgrep_report(json.dumps(report).encode(), {path: 2}, -9)
    error["path"] = "/tmp/other.py"
    with pytest.raises(ScannerError):
        validate_semgrep_report(json.dumps(report).encode(), {path: 2}, code)


@pytest.mark.parametrize(
    "error",
    [
        {"type": "Timeout", "code": 2, "level": "warn"},  # No per-rule attribution.
        {"type": "Syntax error", "code": 2, "level": "warn"},
        {"type": ["PartialParsing", []], "code": 3, "level": "warn"},
        {"type": "Out of memory", "code": 3, "level": "error"},
        {"type": "Rule parse error", "code": 2, "level": "error"},
        {"type": "Unknown error", "code": 2, "level": "error"},
    ],
)
def test_target_error_cannot_hide_a_scanner_fault(error):
    path = Path("/tmp/solution.py")
    report = semgrep_report()
    report["errors"] = [
        {"type": "Syntax error", "code": 3, "level": "warn", "path": str(path)},
        {**error, "path": str(path)},
    ]
    with pytest.raises(ScannerError):
        validate_semgrep_report(json.dumps(report).encode(), {path: 2}, error["code"])


def test_fatal_errors_abort_the_batch():
    path = Path("/tmp/solution.py")
    report = semgrep_report()
    report["errors"] = [
        {
            "type": "Fatal error",
            "code": 2,
            "level": "error",
            "path": str(path),
        }
    ]
    with pytest.raises(ScannerError):
        validate_semgrep_report(json.dumps(report).encode(), {path: 2}, 2)
    report["errors"].append(
        {
            "type": "Rule parse error",
            "code": 2,
            "level": "error",
            "path": str(path),
        }
    )
    with pytest.raises(ScannerError):
        validate_semgrep_report(json.dumps(report).encode(), {path: 2}, 2)


@pytest.mark.parametrize(
    "changed",
    [
        {"errors": ["parse error"]},
        {"paths": {"scanned": []}},
        {"skipped_rules": ["rule"]},
        {"version": "different"},
        {"results": None},
        {"engine_requested": "PRO"},
    ],
)
def test_malformed_semgrep_reports_are_scanner_failures(changed):
    report = semgrep_report()
    report.update(changed)
    with pytest.raises(ScannerError):
        validate_semgrep_report(json.dumps(report).encode(), {Path("/tmp/solution.py"): 2})
    with pytest.raises(ScannerError):
        validate_semgrep_report(b"not JSON", {Path("/tmp/solution.py"): 2})


@pytest.mark.parametrize("field", ["skipped_rules", "skipped"])
@pytest.mark.parametrize("value", [False, 0, "", None, {}, ["skipped entry"]])
def test_semgrep_skips_must_be_empty_lists(field, value):
    report = semgrep_report()
    container = report if field == "skipped_rules" else report["paths"]
    container[field] = value
    with pytest.raises(ScannerError, match="incomplete or malformed"):
        validate_semgrep_report(json.dumps(report).encode(), {Path("/tmp/solution.py"): 2})


@pytest.mark.parametrize("omit_rules", [False, True])
@pytest.mark.parametrize("omit_paths", [False, True])
def test_semgrep_accepts_empty_or_omitted_skips(omit_rules, omit_paths):
    report = semgrep_report()
    if omit_rules:
        del report["skipped_rules"]
    if omit_paths:
        del report["paths"]["skipped"]
    raw = json.dumps(report).encode()
    assert validate_semgrep_report(raw, {Path("/tmp/solution.py"): 2}) == (report, {})


def test_scanner_stream_is_bounded_and_reads_until_eof():
    async def run():
        stream = asyncio.StreamReader()
        stream.feed_data(b"small ")
        stream.feed_data(b"chunks")
        stream.feed_eof()
        assert await read_limited(stream, 12) == b"small chunks"
        stream = asyncio.StreamReader()
        stream.feed_data(b"large")
        stream.feed_eof()
        with pytest.raises(ScannerError):
            await read_limited(stream, 2)

    asyncio.run(run())


def _position(line: int) -> dict[str, int]:
    return {"line": line, "col": 1, "offset": 0}


def _finding(
    *,
    path: str = "/tmp/solution.py",
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


@pytest.mark.parametrize(
    "changes",
    [
        {"path": "/tmp/other.py"},
        {"line": 3},
        {"line": 2, "end_line": 1},
        {"line": 0},
        {"engine_kind": "PRO"},
        {"severity": "UNKNOWN"},
        {"category": 1},
        {"subcategory": ()},
        {"subcategory": ("vuln", "audit")},
        {"subcategory": ("unknown",)},
        {"confidence": None},
        {"confidence": []},
        {"confidence": "UNKNOWN"},
    ],
)
def test_consumed_finding_fields_are_validated(changes):
    report = semgrep_report()
    report["results"] = [_finding(**changes)]
    with pytest.raises(ScannerError):
        checked, _ = validate_semgrep_report(
            json.dumps(report).encode(), {Path("/tmp/solution.py"): 2}
        )
        securityeval.normalize(checked["results"][0])


@pytest.mark.parametrize("field", ["metadata", "severity", "engine_kind"])
def test_consumed_finding_fields_cannot_be_missing(field):
    finding = _finding()
    finding["extra"].pop(field)
    report = semgrep_report()
    report["results"] = [finding]
    with pytest.raises(ScannerError):
        checked, _ = validate_semgrep_report(
            json.dumps(report).encode(), {Path("/tmp/solution.py"): 2}
        )
        securityeval.normalize(checked["results"][0])


def test_securityeval_preserves_filtering_and_normalization():
    assert securityeval.normalize(_finding(category="correctness", confidence=None)) is None
    assert securityeval.normalize(_finding()) == {
        "rule_id": "python.security.test-rule",
        "severity": "HIGH",
        "line": 1,
        "subcategory": "vuln",
        "confidence": "MEDIUM",
    }


@pytest.mark.parametrize("source", [None, b"x", "", " \n", "\ud800", "a" * (MAX_SOURCE_BYTES + 1)])
def test_invalid_source_is_rejected_before_execution(source):
    with pytest.raises(ValueError):
        worker.validate_sources([[source, "python"]])


def test_source_and_batch_bounds_accept_the_boundary(monkeypatch):
    source = "x" * MAX_SOURCE_BYTES
    worker.validate_sources([[source, "python"]])
    monkeypatch.setattr(worker, "MAX_SCAN_SOURCE_BYTES", MAX_SOURCE_BYTES)
    with pytest.raises(ValueError, match="batch size"):
        worker.validate_sources([[source, "python"], ["x", "cpp"]])
    for entry in (["x", "unknown"], ["x", []], ["x"], "x"):
        with pytest.raises(ValueError):
            worker.validate_sources([entry])


def test_shared_worker_rejects_a_source_without_an_analyzer():
    with pytest.raises(ScannerError, match="No analyzer configured"):
        asyncio.run(worker.analyze_sources(
            [["source is data", "python"]],
            rules_for=lambda language: None,
            normalize=securityeval.normalize,
        ))


@pytest.mark.parametrize("failure", [None, "stderr", "exit", "parse", "malformed-partial"])
def test_shared_process_runs_one_batch_and_rejects_global_faults(monkeypatch, failure):
    paths = {Path("/tmp/solution.py"): 2, Path("/tmp/second.py"): 2}
    report = semgrep_report()
    report["paths"]["scanned"] = [str(path) for path in paths]
    report["results"] = [_finding(), _finding(path="/tmp/second.py")]
    if failure in ("parse", "malformed-partial"):
        report["errors"] = [
            {"type": "Syntax error", "code": 3, "level": "warn", "path": "/tmp/second.py"}
        ]
    if failure == "malformed-partial":
        report["results"][1]["extra"]["metadata"]["confidence"] = "UNKNOWN"

    async def run():
        process = SimpleNamespace(
            stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(), returncode=None
        )
        process.stdout.feed_data(json.dumps(report).encode())
        process.stdout.feed_eof()
        process.stderr.feed_data(b"unexpected" if failure == "stderr" else b"")
        process.stderr.feed_eof()

        async def wait():
            process.returncode = 3 if report["errors"] else 1 if failure == "exit" else 0

        async def execute(*command, **kwargs):
            assert command[-2:] == tuple(str(path) for path in paths)
            assert {"--strict", "--oss-only", "--disable-nosem", "--rewrite-rule-ids"} <= set(
                command
            )
            assert kwargs["cwd"] == "/rules"
            return process

        process.wait = wait
        monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", execute)
        return await worker.semgrep_findings(
            paths,
            Path("/rules/python"),
            normalize=securityeval.normalize,
            cwd="/rules",
        )

    if failure in ("stderr", "exit", "malformed-partial"):
        with pytest.raises(ScannerError):
            asyncio.run(run())
    else:
        findings = asyncio.run(run())
        assert len(findings[Path("/tmp/solution.py")]) == 1
        assert (findings[Path("/tmp/second.py")] == "parse_error") == (failure == "parse")


def test_cancellation_kills_the_direct_scanner_process(monkeypatch):
    async def run():
        process = SimpleNamespace(
            stdout=asyncio.StreamReader(), stderr=asyncio.StreamReader(), returncode=None
        )

        def kill():
            process.returncode = -9

        async def wait():
            return process.returncode

        async def execute(*args, **kwargs):
            return process

        process.kill, process.wait = kill, wait
        monkeypatch.setattr(worker.asyncio, "create_subprocess_exec", execute)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(
                worker.semgrep_findings(
                    {Path("/tmp/solution.py"): 2},
                    Path("/rules/python"),
                    normalize=securityeval.normalize,
                ),
                timeout=0.01,
            )
        assert process.returncode == -9

    asyncio.run(run())
