"""Run one bounded Semgrep scan in its Inspect-managed sandbox."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Final, cast

from inspect_ai.util import (
    OutputLimitExceededError,
    override_sandbox_output_limit,
    sandbox,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from codeguard_evals.safe_io import load_strict_json
from codeguard_evals.sandbox_protocol import (
    MAX_PYTHON_SOURCE_BYTES,
    SEMGREP_SANDBOX_NAME,
    SEMGREP_SANDBOX_USER,
    SOURCE_FILENAME,
)
from codeguard_evals.semgrep_artifacts import (
    ALL_SEMGREP_SUBCATEGORIES,
    ALL_SEVERITIES,
    SEMGREP_ENGINE,
    SEMGREP_LOCK,
    SemgrepFinding,
    SemgrepFindingSubcategory,
    SemgrepSeverity,
    load_default_locked_rules_directory,
)

SEMGREP_PACKAGE_VERSION: Final = SEMGREP_LOCK.image.version
SEMGREP_TIMEOUT_SECONDS: Final = 120
SEMGREP_MAX_MEMORY_MIB: Final = 1536
SEMGREP_JOBS: Final = 4
SEMGREP_RULE_TIMEOUT_SECONDS: Final = 5
SEMGREP_RULE_TIMEOUT_THRESHOLD: Final = 1
MAX_SEMGREP_REPORT_BYTES: Final = 8 * 1024 * 1024
SEMGREP_REPORT_CAPTURE_BYTES: Final = MAX_SEMGREP_REPORT_BYTES + 1
CONTAINER_SOURCE_PATH: Final = PurePosixPath("/tmp") / SOURCE_FILENAME
CONTAINER_RULES_PATH: Final = PurePosixPath("/rules/python")
SEMGREP_ENVIRONMENT: Final = {
    "HOME": "/home/semgrep",
    "TMPDIR": "/tmp",
    "PYTHONUTF8": "1",
    "SEMGREP_SEND_METRICS": "off",
}


class _ReportModel(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)


class _Position(_ReportModel):
    line: Annotated[int, Field(ge=1)]


class _Extra(_ReportModel):
    metadata: dict[str, object]
    severity: Annotated[str, Field(min_length=1)]
    engine_kind: Annotated[str, Field(min_length=1)]


class _Finding(_ReportModel):
    check_id: Annotated[str, Field(min_length=1)]
    path: Annotated[str, Field(min_length=1)]
    start: _Position
    end: _Position
    extra: _Extra


class _Paths(_ReportModel):
    scanned: list[str]
    skipped: list[object] = Field(default_factory=list)


class _Report(_ReportModel):
    results: list[_Finding]
    errors: list[object]
    paths: _Paths
    version: Annotated[str, Field(min_length=1)]
    engine_requested: Annotated[str, Field(min_length=1)]
    skipped_rules: list[object] = Field(default_factory=list)


async def scan_source(source: str) -> tuple[SemgrepFinding, ...]:
    """Scan one source string without running Semgrep on the host."""
    source_raw = _validated_source(source)
    load_default_locked_rules_directory()
    try:
        environment = sandbox(SEMGREP_SANDBOX_NAME)
        await environment.write_file(str(CONTAINER_SOURCE_PATH), source_raw)
        with override_sandbox_output_limit(SEMGREP_REPORT_CAPTURE_BYTES, "exec"):
            result = await environment.exec(
                _semgrep_command(),
                input=b"",
                cwd="/rules",
                env=dict(SEMGREP_ENVIRONMENT),
                user=SEMGREP_SANDBOX_USER,
                timeout=SEMGREP_TIMEOUT_SECONDS,
                timeout_retry=False,
            )
    except TimeoutError:
        raise RuntimeError(
            f"Semgrep exceeded {SEMGREP_TIMEOUT_SECONDS} seconds"
        ) from None
    except OutputLimitExceededError:
        raise RuntimeError("Semgrep output exceeded its size limit") from None
    except (OSError, RuntimeError, UnicodeDecodeError):
        raise RuntimeError("Semgrep sandbox execution failed") from None

    _validate_scan_process(result)
    report = _parse_report(result.stdout)
    return _validated_scan(report, source_line_count=len(source.splitlines()))


def _semgrep_command() -> list[str]:
    return [
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
    ]


def _validated_source(source: object) -> bytes:
    if not isinstance(source, str):
        raise RuntimeError("Semgrep source must be text")
    try:
        raw = source.encode("utf-8")
    except UnicodeEncodeError:
        raise RuntimeError("Semgrep source must be valid UTF-8") from None
    if not source.strip():
        raise RuntimeError("Semgrep source must not be empty")
    if len(raw) > MAX_PYTHON_SOURCE_BYTES:
        raise RuntimeError(
            f"Semgrep source exceeds {MAX_PYTHON_SOURCE_BYTES} bytes"
        )
    return raw


def _validate_scan_process(result: object) -> None:
    try:
        stdout = result.stdout
        stderr = result.stderr
        returncode = result.returncode
        stdout_size = len(stdout.encode("utf-8"))
        stderr_size = len(stderr.encode("utf-8"))
    except (AttributeError, UnicodeEncodeError):
        raise RuntimeError("Semgrep returned an invalid process result") from None
    if (
        stdout_size > MAX_SEMGREP_REPORT_BYTES
        or stderr_size > MAX_SEMGREP_REPORT_BYTES
    ):
        raise RuntimeError("Semgrep output exceeded its size limit")
    if type(returncode) is not int:
        raise RuntimeError("Semgrep returned an invalid process result")
    if returncode != 0:
        raise RuntimeError(f"Semgrep exited with status {returncode}")
    if stderr:
        raise RuntimeError("Semgrep wrote unexpected diagnostic output")


def _parse_report(raw: str) -> _Report:
    try:
        return _Report.model_validate(load_strict_json(raw))
    except (UnicodeDecodeError, ValueError, ValidationError):
        raise RuntimeError("Semgrep returned malformed JSON") from None


def _validated_scan(
    report: _Report,
    *,
    source_line_count: int,
) -> tuple[SemgrepFinding, ...]:
    if report.version != SEMGREP_PACKAGE_VERSION:
        raise RuntimeError("Semgrep reported an unexpected version")
    if report.engine_requested != SEMGREP_ENGINE:
        raise RuntimeError("Semgrep reported an unexpected engine")
    if report.errors:
        raise RuntimeError("Semgrep could not analyse the source")
    if report.paths.skipped:
        raise RuntimeError("Semgrep skipped the source")
    if report.skipped_rules:
        raise RuntimeError("Semgrep skipped locked rules")
    if report.paths.scanned != [str(CONTAINER_SOURCE_PATH)]:
        raise RuntimeError("Semgrep reported an unexpected scanned file")

    findings: list[SemgrepFinding] = []
    for result in report.results:
        if result.path != str(CONTAINER_SOURCE_PATH):
            raise RuntimeError("Semgrep reported an unexpected finding file")
        if (
            result.start.line > source_line_count
            or result.end.line > source_line_count
            or result.end.line < result.start.line
        ):
            raise RuntimeError("Semgrep reported an invalid source line")
        if result.extra.engine_kind != SEMGREP_ENGINE:
            raise RuntimeError("Semgrep reported an unexpected finding engine")
        if result.extra.severity not in ALL_SEVERITIES:
            raise RuntimeError("Semgrep reported an unknown severity")
        category = result.extra.metadata.get("category")
        if not isinstance(category, str):
            raise RuntimeError("Semgrep finding category is invalid")
        if category != SEMGREP_LOCK.rules.finding_category:
            continue
        subcategory = result.extra.metadata.get("subcategory")
        if (
            not isinstance(subcategory, list)
            or len(subcategory) != 1
            or subcategory[0] not in ALL_SEMGREP_SUBCATEGORIES
        ):
            raise RuntimeError("Semgrep finding subcategory is invalid")
        findings.append(
            SemgrepFinding(
                rule_id=result.check_id,
                severity=cast(SemgrepSeverity, result.extra.severity),
                line=result.start.line,
                subcategory=cast(SemgrepFindingSubcategory, subcategory[0]),
            )
        )
    return tuple(
        sorted(
            findings,
            key=lambda finding: (
                finding.line,
                finding.rule_id,
                finding.severity,
            ),
        )
    )
