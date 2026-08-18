"""Capture one untrusted solution out of the agent sandbox."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Annotated, Final, Literal, TypeAlias

from inspect_ai.util import (
    OutputLimitExceededError,
    SandboxEnvironment,
    override_sandbox_output_limit,
    sandbox,
)
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from codeguard_evals.safe_io import load_strict_json
from codeguard_evals.sandbox_protocol import (
    MAX_EXPORT_REPORT_BYTES,
    MAX_PYTHON_SOURCE_BYTES,
    MAX_REASON_LENGTH,
    SANDBOX_NAME,
    SANDBOX_USER,
)

EXPORT_TIMEOUT_SECONDS: Final = 10
# The agent container mounts this as a private, bounded tmpfs.
SANDBOX_TEMP_DIR: Final = "/tmp"
EXPORT_COMMAND: Final = (
    "/usr/local/bin/python",
    "-I",
    "-m",
    "codeguard_evals.export_solution",
)

_Reason = Annotated[StrictStr, Field(min_length=1, max_length=MAX_REASON_LENGTH)]
_Sha256Hex: TypeAlias = Annotated[
    StrictStr,
    Field(pattern=r"^[0-9a-f]{64}$"),
]


class BenchmarkInfrastructureError(RuntimeError):
    """An error in Docker, transfer, or the export protocol."""


@dataclass(frozen=True)
class ExportedSolution:
    """The agent's output bytes, or the reason there are none."""

    content: bytes | None
    reason: str | None


class _ExportReport(BaseModel):
    # Reject malformed or incompatible exporter responses before trusting them.
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["valid", "invalid"]
    reason: _Reason | None
    size_bytes: Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
    sha256: _Sha256Hex | None
    content_base64: StrictStr | None


async def export_solution() -> ExportedSolution:
    """Read the agent's solution file out of its sandbox under a size bound."""
    raw = await _run_exporter(sandbox(SANDBOX_NAME))
    try:
        return _parse_export_report(raw)
    except ValueError:
        raise BenchmarkInfrastructureError(
            "Solution exporter returned an invalid report"
        ) from None


async def _run_exporter(environment: SandboxEnvironment) -> str:
    try:
        with override_sandbox_output_limit(MAX_EXPORT_REPORT_BYTES, "exec"):
            result = await environment.exec(
                list(EXPORT_COMMAND),
                input=b"",
                cwd="/",
                env={
                    "HOME": "/nonexistent",
                    "LANG": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                    "TMPDIR": SANDBOX_TEMP_DIR,
                },
                user=SANDBOX_USER,
                timeout=EXPORT_TIMEOUT_SECONDS,
                timeout_retry=False,
            )
    except TimeoutError:
        raise BenchmarkInfrastructureError(
            f"Solution exporter exceeded {EXPORT_TIMEOUT_SECONDS} seconds"
        ) from None
    except OutputLimitExceededError:
        # Inspect bounds the stream itself; this is the only way to observe it.
        raise BenchmarkInfrastructureError(
            "Solution exporter report is too large"
        ) from None
    if not result.success:
        raise BenchmarkInfrastructureError(
            f"Solution exporter exited with status {result.returncode}"
        )
    if result.stderr:
        raise BenchmarkInfrastructureError("Solution exporter wrote unexpected stderr")
    try:
        result.stdout.encode("utf-8")
    except UnicodeEncodeError:
        raise BenchmarkInfrastructureError(
            "Solution exporter returned invalid UTF-8 output"
        ) from None
    return result.stdout


def _parse_export_report(raw: str) -> ExportedSolution:
    try:
        report = _ExportReport.model_validate(load_strict_json(raw))
    except (RecursionError, ValueError):
        raise ValueError("wire report is malformed") from None
    if report.status == "invalid":
        if report.reason is None or report.sha256 is not None:
            raise ValueError("invalid export metadata")
        if report.content_base64 is not None:
            raise ValueError("invalid export contains source")
        return ExportedSolution(None, report.reason)
    if report.reason is not None or report.sha256 is None:
        raise ValueError("valid export metadata")
    if report.content_base64 is None:
        raise ValueError("valid export is missing source")
    try:
        content = base64.b64decode(report.content_base64, validate=True)
        content.decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
        raise ValueError("invalid exported source") from None
    if len(content) > MAX_PYTHON_SOURCE_BYTES:
        raise ValueError("export exceeds source limit")
    if (
        len(content) != report.size_bytes
        or hashlib.sha256(content).hexdigest() != report.sha256
    ):
        raise ValueError("export identity mismatch")
    return ExportedSolution(content, None)
