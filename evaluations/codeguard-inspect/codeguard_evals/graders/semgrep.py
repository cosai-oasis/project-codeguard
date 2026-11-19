"""SecurityEval's Semgrep evidence and grading contract."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from inspect_ai.solver import TaskState
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from codeguard_evals.artifact_locks import SHA256, GitCommit
from codeguard_evals.output_artifact import SavedOutput, load_saved_output
from codeguard_evals.protocol import EVALUATION_VERSION
from codeguard_evals.securityeval.python_output import validate_python_solution
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import SOURCE_FILENAME
from codeguard_evals.graders.semgrep_artifacts import (
    SEMGREP_LOCK,
    SemgrepFinding,
)
from codeguard_evals.graders.semgrep_protocol import AnalysisFailure
from codeguard_evals.graders.semgrep_runner import scan_sources

SEMGREP_EVIDENCE_KEY = "codeguard_evals.semgrep_evidence"
SANDBOX_CONFIG = Path(__file__).parents[2] / "sandbox/semgrep.yaml"


class SemgrepEvidence(BaseModel):
    """Versioned scanner evidence persisted independently of score output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evaluation_version: str
    source_sha256: SHA256 | None
    image_digest: Annotated[
        str,
        Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$"),
    ]
    rules_commit: GitCommit
    rules_tree_sha256: SHA256
    findings: tuple[SemgrepFinding, ...] | None
    incomplete_reason: AnalysisFailure | None = None

    @field_validator("evaluation_version", mode="before")
    @classmethod
    def validate_evaluation_version(cls, value: object) -> object:
        if type(value) is not str or value != EVALUATION_VERSION:
            raise ValueError(f"evaluation version must be {EVALUATION_VERSION}")
        return value

    @field_validator("findings", mode="before")
    @classmethod
    def normalize_findings(cls, value: object) -> object:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def validate_scan_state(self) -> SemgrepEvidence:
        if self.source_sha256 is None and self.findings is not None:
            raise ValueError("source-free evidence cannot contain findings")
        if self.incomplete_reason is not None and (
            self.source_sha256 is None or self.findings is not None
        ):
            raise ValueError("incomplete evidence requires source and no findings")
        return self


def save_semgrep_evidence(
    state: TaskState,
    findings: tuple[SemgrepFinding, ...] | None,
    *,
    incomplete_reason: AnalysisFailure | None = None,
) -> None:
    """Persist scanner evidence bound to the exact saved source and artifacts."""
    if SEMGREP_EVIDENCE_KEY in state.store:
        raise BenchmarkInfrastructureError("Semgrep evidence already exists")
    saved = load_saved_output(state)
    if saved.filename != SOURCE_FILENAME:
        raise BenchmarkInfrastructureError("Semgrep language does not match the output")
    evidence = SemgrepEvidence(
        evaluation_version=EVALUATION_VERSION,
        source_sha256=saved.source_sha256,
        image_digest=SEMGREP_LOCK.image.index_digest,
        rules_commit=SEMGREP_LOCK.rules.commit,
        rules_tree_sha256=SEMGREP_LOCK.rules.tree_sha256,
        findings=findings,
        incomplete_reason=incomplete_reason,
    )
    state.store.set(SEMGREP_EVIDENCE_KEY, evidence.model_dump(mode="json"))


def load_semgrep_evidence(
    state: TaskState,
    *,
    saved: SavedOutput | None = None,
) -> SemgrepEvidence:
    """Load scanner evidence and bind it to the saved source and current lock."""
    if SEMGREP_EVIDENCE_KEY not in state.store:
        raise BenchmarkInfrastructureError("Semgrep evidence is missing")
    try:
        evidence = SemgrepEvidence.model_validate(state.store.get(SEMGREP_EVIDENCE_KEY))
    except ValidationError as exc:
        raise BenchmarkInfrastructureError("Semgrep evidence is invalid") from exc
    saved_output = load_saved_output(state) if saved is None else saved
    if (
        evidence.source_sha256 != saved_output.source_sha256
        or evidence.image_digest != SEMGREP_LOCK.image.index_digest
        or evidence.rules_commit != SEMGREP_LOCK.rules.commit
        or evidence.rules_tree_sha256 != SEMGREP_LOCK.rules.tree_sha256
        or saved_output.filename != SOURCE_FILENAME
    ):
        raise BenchmarkInfrastructureError("Semgrep evidence identity is invalid")
    valid = (
        saved_output.source is not None
        and validate_python_solution(saved_output.source).valid
    )
    if (
        evidence.findings is not None or evidence.incomplete_reason is not None
    ) != valid:
        raise BenchmarkInfrastructureError(
            "Semgrep evidence is inconsistent with the saved output"
        )
    return evidence


async def collect_evidence(states: list[TaskState]) -> dict[tuple[str | int, int], str]:
    pending = []
    sources = []
    for state in states:
        saved = load_saved_output(state)
        if saved.source is not None and validate_python_solution(saved.source).valid:
            pending.append(state)
            sources.append(saved.source)
        else:
            save_semgrep_evidence(state, None)
    failures = {}
    if sources:
        results = await scan_sources(sources)
        for state, result in zip(pending, results, strict=True):
            if isinstance(result, str):
                save_semgrep_evidence(state, None, incomplete_reason=result)
                failures[(state.sample_id, state.epoch)] = f"Semgrep analysis incomplete: {result}"
            else:
                save_semgrep_evidence(state, result)
    return failures
