"""Pinned detector identity and replayable ICD evidence."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Final, Literal

from inspect_ai.scorer import Scorer
from inspect_ai.solver import TaskState
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from codeguard_evals.graders import scanner_client
from codeguard_evals.artifact_locks import (
    MAX_FILES_LOCK_BYTES,
    SHA256,
    GitCommit,
    GitFilesLock,
    manifest_sha256,
)
from codeguard_evals.artifacts import (
    cached_directory,
    files_sha256,
    require_directory,
    verify_tree,
)
from codeguard_evals.graders.base import StaticGrader
from codeguard_evals.graders.icd_worker import (
    ICD_LOCK_FILE,
    analyzers_for,
)
from codeguard_evals.output_artifact import SavedOutput, load_saved_output
from codeguard_evals.safe_io import load_strict_json, read_bounded
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import (
    LANGUAGE_FILENAMES,
    Language,
)
from codeguard_evals.graders.scanner_worker import worker_sha256
from codeguard_evals.graders.semgrep_artifacts import SEMGREP_LOCK
from codeguard_evals.graders.semgrep_protocol import AnalysisFailure


class IcdSourceLock(GitFilesLock):
    repository: Literal["https://github.com/meta-llama/PurpleLlama"]


class IcdLock(BaseModel):
    """Pin the upstream files and the JSON bundle produced from them."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[2]
    source: IcdSourceLock
    prepared_tree_sha256: SHA256


EVIDENCE_KEY: Final = "codeguard_evals.icd_evidence"
SCANNER_SCRIPT: Final = Path(__file__).with_name("icd_worker.py")
ROOT = Path(__file__).parents[2]
SANDBOX_CONFIG = ROOT / "sandbox/icd.yaml"
SOURCE_CACHE_ROOT = ROOT / ".cache/codeguard-evals/meta-icd-rules"
CACHE_ROOT = ROOT / ".cache/codeguard-evals/meta-icd-json"
ICD_LOCK = IcdLock.model_validate(
    load_strict_json(
        read_bounded(ROOT / ICD_LOCK_FILE, MAX_FILES_LOCK_BYTES, label="ICD lock")
    )
)
DETECTOR_SUBDIRECTORY = "CodeShield/insecure_code_detector"
Analyzer = Literal["regex", "semgrep"]


def expected_analyzers(language: Language) -> tuple[Analyzer, ...]:
    return tuple(analyzers_for(language))


def detector_path(cache_root: Path = CACHE_ROOT) -> Path:
    return cache_root / ICD_LOCK.prepared_tree_sha256 / DETECTOR_SUBDIRECTORY


def verify_detector(cache_root: Path = CACHE_ROOT) -> Path:
    root = cached_directory(cache_root, ICD_LOCK.prepared_tree_sha256)
    return verify_tree(root, ICD_LOCK.prepared_tree_sha256) / DETECTOR_SUBDIRECTORY


def load_detector() -> Path:
    """Diagnose a missing build context; the image build verifies its contents."""
    try:
        path = detector_path()
        require_directory(path)
        return path
    except FileNotFoundError:
        raise FileNotFoundError(
            "Prepare the pinned detector with: python -m codeguard_evals.prefetch "
            "--benchmark cyberseceval"
        ) from None


def adapter_sha256() -> str:
    return worker_sha256(SCANNER_SCRIPT, extra_files=(ICD_LOCK_FILE,))


def implementation_sha256() -> str:
    """Fingerprint scanner code and configuration, not the running image."""
    return files_sha256(
        ROOT,
        (
            ICD_LOCK_FILE,
            "sandbox/Dockerfile.icd",
            "sandbox/icd.yaml",
            "sandbox/base.yaml",
            "codeguard_evals/graders/icd.py",
            "codeguard_evals/graders/icd_worker.py",
            "codeguard_evals/graders/scanner_client.py",
            "codeguard_evals/graders/scanner_worker.py",
            "codeguard_evals/graders/semgrep_protocol.py",
            "codeguard_evals/__init__.py",
            "codeguard_evals/graders/__init__.py",
            "codeguard_evals/artifacts.py",
            "codeguard_evals/artifact_locks.py",
            "codeguard_evals/output_artifact.py",
            "codeguard_evals/safe_io.py",
            "codeguard_evals/sandbox_protocol.py",
        ),
    )


def provenance() -> dict[str, object]:
    return {
        "schema_version": 1,
        "implementation": "codeguard-icd-rules",
        "detector_repository": ICD_LOCK.source.repository,
        "detector_revision": ICD_LOCK.source.commit,
        "detector_tree_sha256": ICD_LOCK.source.tree_sha256,
        "detector_manifest_sha256": manifest_sha256(ICD_LOCK.source),
        "adapter_sha256": adapter_sha256(),
        "base_image_digest": SEMGREP_LOCK.image.index_digest,
        "semgrep_version": SEMGREP_LOCK.image.version,
        "rules_tree_sha256": ICD_LOCK.prepared_tree_sha256,
        "usecase": "cyberseceval",
        "implementation_sha256": implementation_sha256(),
        "command": list(SCANNER_COMMAND),
        "timeout_seconds": TIMEOUT_SECONDS,
        "max_batch_sources": MAX_BATCH_SOURCES,
        "cpus": scanner_client.scanner_cpus(),
        "environment": dict(scanner_client.ENVIRONMENT),
    }


class _Identity(BaseModel):
    """Validate recorded provenance without depending on the current checkout."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    schema_version: Literal[1]
    implementation: Literal["codeguard-icd-rules"]
    detector_repository: Literal["https://github.com/meta-llama/PurpleLlama"]
    detector_revision: GitCommit
    detector_tree_sha256: SHA256
    detector_manifest_sha256: SHA256
    adapter_sha256: SHA256
    implementation_sha256: SHA256
    base_image_digest: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    semgrep_version: Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]
    rules_tree_sha256: SHA256
    usecase: Literal["cyberseceval"]
    command: list[str] = Field(min_length=1)
    timeout_seconds: int = Field(gt=0)
    max_batch_sources: int = Field(gt=0)
    cpus: float = Field(gt=0, allow_inf_nan=False)
    environment: dict[str, str]


class IcdFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    rule_id: str = Field(min_length=1, max_length=256)
    cwe: str = Field(max_length=128)
    analyzer: Analyzer
    severity: str = Field(min_length=1, max_length=32)
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)


class IcdScan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    language: Language
    source_sha256: SHA256 | None
    complete: bool
    reason: Literal["missing_output", "empty_output"] | AnalysisFailure | None
    analyzers: list[Analyzer]
    findings: list[IcdFinding] | None

    @model_validator(mode="after")
    def consistent_result(self) -> IcdScan:
        if self.complete:
            if self.reason is not None or self.source_sha256 is None or self.findings is None:
                raise ValueError("Complete scans must contain source identity and findings")
            if tuple(self.analyzers) != expected_analyzers(self.language):
                raise ValueError("ICD did not complete every required analyzer")
            if any(finding.analyzer not in self.analyzers for finding in self.findings):
                raise ValueError("ICD finding names an analyzer that did not run")
        elif self.reason is None or self.findings is not None or self.analyzers:
            raise ValueError("Incomplete scans must not contain successful findings")
        return self


class IcdEvidence(IcdScan):
    identity: dict[str, object]

    @field_validator("identity")
    @classmethod
    def recorded_identity(cls, value: dict) -> dict:
        return _Identity.model_validate(value).model_dump()


def save_evidence(
    state: TaskState, scan: IcdScan, *, identity: dict[str, object] | None = None
) -> None:
    if EVIDENCE_KEY in state.store:
        raise BenchmarkInfrastructureError("ICD evidence already exists")
    evidence = IcdEvidence(
        **scan.model_dump(), identity=provenance() if identity is None else identity
    )
    state.store.set(EVIDENCE_KEY, evidence.model_dump(mode="json"))


def load_evidence(
    state: TaskState,
    language: Language,
    *,
    saved: SavedOutput | None = None,
    expected_identity: dict[str, object] | None = None,
) -> IcdEvidence:
    try:
        evidence = IcdEvidence.model_validate(state.store.get(EVIDENCE_KEY))
    except ValidationError:
        raise BenchmarkInfrastructureError("ICD evidence is missing or invalid") from None
    saved = load_saved_output(state) if saved is None else saved
    if (
        (expected_identity is not None and evidence.identity != expected_identity)
        or evidence.language != language
        or evidence.source_sha256 != saved.source_sha256
        or saved.filename != LANGUAGE_FILENAMES[language]
    ):
        raise BenchmarkInfrastructureError(
            "ICD evidence does not match the captured source or pinned detector"
        )
    output_reason = (
        "missing_output"
        if saved.source is None
        else "empty_output"
        if not saved.source.strip()
        else None
    )
    # Every language can exhaust its regex budget. Parse and resource errors
    # require Semgrep; missing/empty output must retain its capture outcome.
    allowed_reasons = (output_reason,)
    if output_reason is None:
        allowed_reasons = (None, "rule_timeout")
        if "semgrep" in expected_analyzers(language):
            allowed_reasons += ("parse_error", "resource_limit")
    if evidence.reason not in allowed_reasons:
        raise BenchmarkInfrastructureError("ICD scan status does not match the captured output")
    if saved.source is not None and evidence.findings is not None:
        line_count = len(saved.source.splitlines())
        if any(f.line is not None and f.line > line_count for f in evidence.findings):
            raise BenchmarkInfrastructureError("ICD finding is outside the captured source")
    return evidence


SCANNER_NAME = "icd"
TIMEOUT_SECONDS = 300
# At most 2 MiB of source and 160 seconds of regex matching per invocation.
MAX_BATCH_SOURCES = 32
SCANNER_COMMAND = (
    *scanner_client.PYTHON_COMMAND,
    "codeguard_evals.graders.icd_worker",
    "--batch",
)


async def scan_sources(
    sources: list[tuple[str, Language]], *, expected_adapter: str | None = None
) -> list[IcdScan]:
    """Scan bounded chunks sequentially in the log's existing sandbox."""
    expected_adapter = adapter_sha256() if expected_adapter is None else expected_adapter
    scans = []
    for start in range(0, len(sources), MAX_BATCH_SOURCES):
        reports = await scanner_client.scan_batch(
            sources[start : start + MAX_BATCH_SOURCES],
            name=SCANNER_NAME,
            command=SCANNER_COMMAND,
            timeout=TIMEOUT_SECONDS,
            expected_adapter=expected_adapter,
        )
        try:
            chunk = [IcdScan.model_validate(value) for value in reports]
            if any(scan.reason in ("missing_output", "empty_output") for scan in chunk):
                raise ValueError
        except (ValueError, ValidationError):
            raise BenchmarkInfrastructureError("ICD returned invalid findings") from None
        scans.extend(chunk)
    return scans


def icd_grader(scorer: Scorer, language: Callable[[TaskState], Language]) -> StaticGrader:
    identity = provenance()

    def validate(state: TaskState) -> None:
        load_evidence(state, language(state), expected_identity=identity)

    async def collect(states: list[TaskState]) -> dict[tuple[str | int, int], str]:
        pending, sources = [], []
        for state in states:
            selected = language(state)
            saved = load_saved_output(state)
            source = saved.source
            if source is None or not source.strip():
                save_evidence(
                    state,
                    IcdScan(
                        language=selected,
                        source_sha256=saved.source_sha256,
                        complete=False,
                        reason="missing_output" if source is None else "empty_output",
                        analyzers=[],
                        findings=None,
                    ),
                    identity=identity,
                )
            else:
                pending.append(state)
                sources.append((source, selected))
        scans = await scan_sources(sources, expected_adapter=identity["adapter_sha256"])
        for state, scan in zip(pending, scans, strict=True):
            save_evidence(state, scan, identity=identity)
        return {}

    return StaticGrader(
        filename=lambda state: LANGUAGE_FILENAMES[language(state)],
        collect=collect,
        validate=validate,
        scorer=scorer,
        prepare=load_detector,
        sandbox_config=SANDBOX_CONFIG,
        evidence_key=EVIDENCE_KEY,
        identity=identity,
    )
