"""Shared static scanner process; submitted source is data, never executable code."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
import tempfile
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path

from codeguard_evals.artifacts import files_sha256
from codeguard_evals.safe_io import load_strict_json
from codeguard_evals.sandbox_protocol import (
    LANGUAGE_FILENAMES,
    MAX_SCAN_REPORT_BYTES,
    MAX_SCAN_SOURCE_BYTES,
    MAX_SOURCE_BYTES,
)
from codeguard_evals.graders.semgrep_protocol import analysis_failures

SEMGREP_VERSION = "1.173.0"
# Multiple workers can exceed the scanner's 2 GiB memory budget.
SEMGREP_JOBS = 1
SEMGREP_MAX_MEMORY_MIB = 1536
SEMGREP_RULE_TIMEOUT_SECONDS = 5
SEMGREP_RULE_TIMEOUT_THRESHOLD = 1
WORKER_FILES = (
    "codeguard_evals/__init__.py",
    "codeguard_evals/graders/__init__.py",
    "codeguard_evals/graders/scanner_worker.py",
    "codeguard_evals/graders/semgrep_protocol.py",
    "codeguard_evals/sandbox_protocol.py",
    "codeguard_evals/safe_io.py",
    "codeguard_evals/artifacts.py",
)


class ScannerError(RuntimeError):
    """The scanner failed or returned untrustworthy evidence."""


class RegexTimeout(TimeoutError):
    """One source exhausted its regex budget; its findings are incomplete."""


def worker_sha256(entrypoint: str | Path, *, extra_files: tuple[str, ...] = ()) -> str:
    root = Path(__file__).parents[2]
    return files_sha256(
        root, (*WORKER_FILES, str(Path(entrypoint).relative_to(root)), *extra_files)
    )


def validate_sources(sources: object) -> None:
    if not isinstance(sources, list) or not sources:
        raise ValueError("Scanner batch must contain sources")
    total = 0
    for entry in sources:
        if not isinstance(entry, (list, tuple)) or len(entry) != 2:
            raise ValueError("Invalid scanner source entry")
        source, language = entry
        if (
            not isinstance(source, str)
            or not source.strip()
            or not isinstance(language, str)
            or language not in LANGUAGE_FILENAMES
        ):
            raise ValueError("Scanner requires nonempty source in a supported language")
        size = len(source.encode("utf-8"))
        if size > MAX_SOURCE_BYTES:
            raise ValueError("Scanner source exceeds the size limit")
        total += size
    if total > MAX_SCAN_SOURCE_BYTES:
        raise ValueError("Scanner sources exceed the batch size limit")


def semgrep_command(paths: Iterable[Path], rules: Path) -> list[str]:
    return [
        "/usr/bin/semgrep",
        "scan",
        "--oss-only",
        "--strict",
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        f"--jobs={SEMGREP_JOBS}",
        f"--max-memory={SEMGREP_MAX_MEMORY_MIB}",
        f"--max-target-bytes={MAX_SOURCE_BYTES}",
        f"--timeout={SEMGREP_RULE_TIMEOUT_SECONDS}",
        f"--timeout-threshold={SEMGREP_RULE_TIMEOUT_THRESHOLD}",
        "--rewrite-rule-ids",
        "--config",
        str(rules),
        *(str(path) for path in paths),
    ]


def validate_semgrep_report(
    raw: bytes, targets: dict[Path, int], returncode: int = 0
) -> tuple[dict, dict[Path, str]]:
    if len(raw) > MAX_SCAN_REPORT_BYTES:
        raise ScannerError("oversized scanner report")
    try:
        report = load_strict_json(raw)
        if (
            not isinstance(report, dict)
            or report.get("version") != SEMGREP_VERSION
            or report.get("engine_requested") != "OSS"
            or not isinstance(report.get("results"), list)
            or not isinstance(report.get("errors"), list)
        ):
            raise ValueError
        scanned = report["paths"]["scanned"]
        if (
            not isinstance(scanned, list)
            or len(scanned) != len(targets)
            or {Path("/", path) for path in scanned} != set(targets)
        ):
            raise ValueError
        for skipped in (report.get("skipped_rules", []), report["paths"].get("skipped", [])):
            if not isinstance(skipped, list) or skipped:
                raise ValueError
        for finding in report["results"]:
            path = Path("/", finding["path"])
            start, end = finding["start"]["line"], finding["end"]["line"]
            extra = finding["extra"]
            if (
                path not in targets
                or not isinstance(finding["check_id"], str)
                or not finding["check_id"]
                or type(start) is not int
                or type(end) is not int
                or not 1 <= start <= end <= targets[path]
                or extra["engine_kind"] != "OSS"
                or not isinstance(extra["severity"], str)
                or not extra["severity"]
                or not isinstance(extra.get("metadata", {}), dict)
            ):
                raise ValueError
        failures = analysis_failures(report["errors"], set(targets))
        expected_exit = report["errors"][-1]["code"] if report["errors"] else 0
        if type(returncode) is not int or returncode != expected_exit:
            raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise ScannerError("incomplete or malformed scanner report") from None
    return report, failures


async def read_limited(stream: asyncio.StreamReader, maximum: int) -> bytes:
    data = bytearray()
    while chunk := await stream.read(min(65536, maximum - len(data) + 1)):
        data.extend(chunk)
        if len(data) > maximum:
            raise ScannerError("oversized scanner output")
    return bytes(data)


async def semgrep_findings(
    targets: dict[Path, int],
    rules: Path,
    *,
    normalize: Callable[[dict], dict | None],
    cwd: str | None = None,
) -> dict[Path, list[dict] | str]:
    process = await asyncio.create_subprocess_exec(
        *semgrep_command(targets, rules),
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.gather(
            read_limited(process.stdout, MAX_SCAN_REPORT_BYTES),
            read_limited(process.stderr, 65536),
        )
        await process.wait()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    if stderr:
        raise ScannerError("scanner wrote unexpected diagnostics")
    report, failures = validate_semgrep_report(stdout, targets, process.returncode)
    findings = {path: [] for path in targets}
    for finding in report["results"]:
        # A file error must not hide malformed findings elsewhere in the report.
        normalized = normalize(finding)
        if normalized is not None:
            findings[Path("/", finding["path"])].append(normalized)
    return {path: failures.get(path, findings[path]) for path in targets}


async def analyze_sources(
    sources: list[list[str]],
    *,
    rules_for: Callable[[str], Path | None],
    normalize: Callable[[dict], dict | None],
    regex: Callable[[str, str], list[dict]] | None = None,
    cwd: str | None = None,
) -> list[dict]:
    results = []
    with tempfile.TemporaryDirectory(prefix="codeguard-scan-") as temporary:
        groups = {}
        for index, (source, language) in enumerate(sources):
            rules = rules_for(language)
            analyzers = (["regex"] if regex is not None else []) + (["semgrep"] if rules else [])
            if not analyzers:
                raise ScannerError("No analyzer configured for source language")
            results.append(
                {
                    "language": language,
                    "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                    "complete": True,
                    "reason": None,
                    "analyzers": analyzers,
                    "findings": [],
                }
            )
            if regex is not None:
                try:
                    results[index]["findings"] = regex(source, language)
                except RegexTimeout:
                    results[index].update(
                        complete=False, reason="rule_timeout", analyzers=[], findings=None
                    )
                    continue
            if rules is not None:
                directory = Path(temporary) / str(index)
                directory.mkdir()
                path = directory / LANGUAGE_FILENAMES[language]
                path.write_text(source, encoding="utf-8")
                groups.setdefault(rules, []).append((path, index, len(source.splitlines())))
        for rules, group in groups.items():
            findings = await semgrep_findings(
                {path: lines for path, _, lines in group},
                rules,
                normalize=normalize,
                cwd=cwd,
            )
            for path, index, _ in group:
                value = findings[path]
                if isinstance(value, str):
                    results[index].update(complete=False, reason=value, analyzers=[], findings=None)
                else:
                    results[index]["findings"].extend(value)
    return results


def main(
    analyze: Callable[[list[list[str]]], Awaitable[list[dict]]],
    entrypoint: str,
    *,
    verify: Callable[[], object] | None = None,
    extra_files: tuple[str, ...] = (),
    maximum: int = MAX_SCAN_REPORT_BYTES,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--batch", action="store_true")
    mode.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    identity = {"adapter_sha256": worker_sha256(entrypoint, extra_files=extra_files)}
    if args.verify_only:
        if verify is not None:
            verify()
        sys.stdout.write(json.dumps(identity, sort_keys=True))
        return 0
    # JSON escaping can expand each source byte to six bytes; allow envelope overhead.
    limit = 6 * MAX_SCAN_SOURCE_BYTES + 1024 * 1024
    raw = sys.stdin.buffer.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Scanner batch exceeds the input limit")
    sources = load_strict_json(raw)
    del raw
    validate_sources(sources)
    report = json.dumps(
        {**identity, "scans": asyncio.run(analyze(sources))},
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(report.encode()) > maximum:
        raise ScannerError("oversized scanner report")
    sys.stdout.write(report)
    return 0
