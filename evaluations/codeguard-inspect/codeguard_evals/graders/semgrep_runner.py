"""SecurityEval scanner identity and typed findings; execution is shared."""

from pathlib import Path
from typing import Final

from pydantic import ValidationError

from codeguard_evals.graders import scanner_client
from codeguard_evals.artifacts import files_sha256
from codeguard_evals.graders import semgrep_worker
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.graders.scanner_worker import worker_sha256
from codeguard_evals.graders.semgrep_artifacts import SemgrepFinding, semgrep_provenance

SEMGREP_TIMEOUT_SECONDS = 120
SCANNER_COMMAND = (
    *scanner_client.PYTHON_COMMAND,
    "codeguard_evals.graders.semgrep_worker",
    "--batch",
)

COLLECTOR_FILES: Final = (
    "codeguard_evals/graders/semgrep_runner.py",
    "codeguard_evals/graders/scanner_client.py",
    "codeguard_evals/graders/scanner_worker.py",
    "codeguard_evals/graders/semgrep_worker.py",
    "sandbox/Dockerfile.semgrep",
    "codeguard_evals/graders/semgrep_protocol.py",
    "codeguard_evals/graders/semgrep.py",
    "codeguard_evals/graders/semgrep_artifacts.py",
    "codeguard_evals/artifacts.py",
    "codeguard_evals/artifact_locks.py",
    "codeguard_evals/securityeval/python_output.py",
    "codeguard_evals/output_artifact.py",
    "codeguard_evals/safe_io.py",
    "codeguard_evals/sandbox_protocol.py",
    "sandbox/semgrep.yaml",
    "sandbox/base.yaml",
)


def scan_identity() -> dict[str, object]:
    return {
        **semgrep_provenance(),
        "command": list(SCANNER_COMMAND),
        "environment": dict(scanner_client.ENVIRONMENT),
        "timeout_seconds": SEMGREP_TIMEOUT_SECONDS,
        "cpus": scanner_client.scanner_cpus(),
        "collector_sha256": files_sha256(Path(__file__).parents[2], COLLECTOR_FILES),
    }


async def scan_sources(sources: list[str]) -> list[tuple[SemgrepFinding, ...] | str]:
    scans = await scanner_client.scan_batch(
        [(source, "python") for source in sources],
        name="semgrep",
        command=SCANNER_COMMAND,
        timeout=SEMGREP_TIMEOUT_SECONDS,
        expected_adapter=worker_sha256(semgrep_worker.__file__),
    )
    outcomes = []
    try:
        for source, scan in zip(sources, scans, strict=True):
            if set(scan) != {
                "language",
                "source_sha256",
                "complete",
                "reason",
                "analyzers",
                "findings",
            }:
                raise ValueError
            if scan["complete"] is True:
                if (
                    scan["reason"] is not None
                    or scan["analyzers"] != ["semgrep"]
                    or not isinstance(scan["findings"], list)
                ):
                    raise ValueError
                findings = [SemgrepFinding.model_validate(item) for item in scan["findings"]]
                if any(item.line > len(source.splitlines()) for item in findings):
                    raise ValueError
                outcomes.append(
                    tuple(sorted(findings, key=lambda f: (f.line, f.rule_id, f.severity)))
                )
            elif (
                scan["complete"] is False
                and scan["findings"] is None
                and scan["analyzers"] == []
                and scan["reason"] in ("parse_error", "rule_timeout", "resource_limit")
            ):
                outcomes.append(scan["reason"])
            else:
                raise ValueError
    except (KeyError, TypeError, ValueError, ValidationError):
        raise BenchmarkInfrastructureError("Semgrep returned invalid findings") from None
    return outcomes
