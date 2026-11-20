"""One bounded Inspect transport for trusted static-scanner workers."""

import hashlib
import json
import math
import os

from inspect_ai.util import (
    OutputLimitExceededError,
    SandboxUnavailableError,
    override_sandbox_output_limit,
    sandbox,
)

from codeguard_evals.safe_io import load_strict_json
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import MAX_SCAN_REPORT_BYTES, SEMGREP_SANDBOX_USER
from codeguard_evals.graders.scanner_worker import validate_sources

PYTHON_COMMAND = ("/usr/bin/python3", "-E", "-s", "-B", "-m")
WORKDIR = "/opt/codeguard"
ENVIRONMENT = {
    "HOME": "/home/semgrep",
    "TMPDIR": "/tmp",
    "PYTHONDONTWRITEBYTECODE": "1",
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "PYTHONUTF8": "1",
}


def scanner_cpus() -> float:
    """Read the CPU ceiling once for provenance and Inspect sample metadata."""
    try:
        cpus = float(os.environ.get("CODEGUARD_SCANNER_CPUS") or "4.0")
        if not math.isfinite(cpus) or cpus <= 0:
            raise ValueError
        return cpus
    except ValueError:
        raise BenchmarkInfrastructureError(
            "CODEGUARD_SCANNER_CPUS must be a finite positive number"
        ) from None


async def scan_batch(
    sources: list, *, name: str, command: tuple[str, ...], timeout: int, expected_adapter: str
) -> list[dict]:
    """Run the supplied batch command and bind each returned scan to its input."""
    if not sources:
        return []
    validate_sources(sources)
    environment = sandbox(name)
    try:
        with override_sandbox_output_limit(MAX_SCAN_REPORT_BYTES + 1, "exec"):
            result = await environment.exec(
                list(command),
                input=json.dumps(sources, ensure_ascii=False).encode(),
                cwd=WORKDIR,
                user=SEMGREP_SANDBOX_USER,
                timeout=timeout,
                timeout_retry=False,
                env=dict(ENVIRONMENT),
            )
    except SandboxUnavailableError:
        raise
    except (TimeoutError, OutputLimitExceededError, OSError, RuntimeError) as error:
        raise BenchmarkInfrastructureError(
            f"Scanner sandbox execution failed: {type(error).__name__}"
        ) from error
    try:
        if (
            type(result.returncode) is not int
            or result.returncode != 0
            or result.stderr
            or not isinstance(result.stdout, str)
            or len(result.stdout.encode()) > MAX_SCAN_REPORT_BYTES
        ):
            raise ValueError
        report = load_strict_json(result.stdout)
        if (
            not isinstance(report, dict)
            or set(report) != {"adapter_sha256", "scans"}
            or report["adapter_sha256"] != expected_adapter
            or not isinstance(report["scans"], list)
            or len(report["scans"]) != len(sources)
        ):
            raise ValueError
        for scan, (source, language) in zip(report["scans"], sources, strict=True):
            if (
                scan["language"] != language
                or scan["source_sha256"] != hashlib.sha256(source.encode()).hexdigest()
            ):
                raise ValueError
    except (AttributeError, KeyError, TypeError, ValueError):
        raise BenchmarkInfrastructureError(
            "Scanner returned an invalid or mismatched report"
        ) from None
    return report["scans"]
