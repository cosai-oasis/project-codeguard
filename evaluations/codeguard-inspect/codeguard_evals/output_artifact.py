"""Capture and replay one bounded benchmark output through Inspect logs."""

from __future__ import annotations

import hashlib
from typing import Annotated, Final

from inspect_ai.solver import TaskState
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
    export_solution,
)
from codeguard_evals.sandbox_protocol import MAX_PYTHON_SOURCE_BYTES, MAX_REASON_LENGTH
from codeguard_evals.securityeval.protocol import EVALUATION_VERSION
from codeguard_evals.semgrep_artifacts import SEMGREP_LOCK, SemgrepFinding

SAVED_OUTPUT_KEY: Final = "codeguard_evals.saved_output"
SEMGREP_EVIDENCE_KEY: Final = "codeguard_evals.semgrep_evidence"

_Reason = Annotated[str, Field(min_length=1, max_length=MAX_REASON_LENGTH)]


class SavedOutput(BaseModel):
    """One strictly validated solution artifact persisted in Inspect's store."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evaluation_version: str
    source: str | None
    capture_error: _Reason | None

    @field_validator("evaluation_version", mode="before")
    @classmethod
    def validate_evaluation_version(cls, value: object) -> object:
        if type(value) is not str or value != EVALUATION_VERSION:
            raise ValueError(f"evaluation version must be {EVALUATION_VERSION}")
        return value

    @field_validator("source")
    @classmethod
    def validate_source(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("saved source must be valid UTF-8") from exc
        if len(encoded) > MAX_PYTHON_SOURCE_BYTES:
            raise ValueError("saved source exceeds the source limit")
        return value

    @model_validator(mode="after")
    def validate_capture_result(self) -> SavedOutput:
        if (self.source is None) == (self.capture_error is None):
            raise ValueError("saved output must contain source or a capture error")
        return self


class SemgrepEvidence(BaseModel):
    """Versioned scanner evidence persisted independently of score output."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evaluation_version: str
    source_sha256: Annotated[
        str,
        Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
    ] | None
    image_digest: Annotated[
        str,
        Field(min_length=71, max_length=71, pattern=r"^sha256:[0-9a-f]{64}$"),
    ]
    rules_commit: Annotated[
        str,
        Field(min_length=40, max_length=40, pattern=r"^[0-9a-f]{40}$"),
    ]
    findings: tuple[SemgrepFinding, ...] | None

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
        return self


async def capture_generated_output(state: TaskState) -> None:
    """Capture the exact solution bytes before sandbox teardown."""
    if SAVED_OUTPUT_KEY in state.store:
        raise BenchmarkInfrastructureError("Saved output evidence already exists")

    exported = await export_solution()
    try:
        saved = _saved_output_from_export(exported)
    except ValueError as exc:
        raise BenchmarkInfrastructureError(
            "Sandbox returned inconsistent saved output evidence"
        ) from exc

    state.store.set(SAVED_OUTPUT_KEY, saved.model_dump(mode="json"))


def load_saved_output(state: TaskState) -> SavedOutput:
    """Load one bounded source artifact from the sample store."""
    if SAVED_OUTPUT_KEY not in state.store:
        raise BenchmarkInfrastructureError("Saved output evidence is missing")
    try:
        return SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY))
    except ValidationError as exc:
        raise BenchmarkInfrastructureError("Saved output evidence is invalid") from exc


def save_semgrep_evidence(
    state: TaskState,
    findings: tuple[SemgrepFinding, ...] | None,
) -> None:
    """Persist scanner evidence bound to the exact saved source and artifacts."""
    if SEMGREP_EVIDENCE_KEY in state.store:
        raise BenchmarkInfrastructureError("Semgrep evidence already exists")
    saved = load_saved_output(state)
    evidence = SemgrepEvidence(
        evaluation_version=EVALUATION_VERSION,
        source_sha256=_source_sha256(saved.source),
        image_digest=SEMGREP_LOCK.image.index_digest,
        rules_commit=SEMGREP_LOCK.rules.commit,
        findings=findings,
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
        evidence = SemgrepEvidence.model_validate(
            state.store.get(SEMGREP_EVIDENCE_KEY)
        )
    except ValidationError as exc:
        raise BenchmarkInfrastructureError("Semgrep evidence is invalid") from exc
    saved_output = load_saved_output(state) if saved is None else saved
    if (
        evidence.source_sha256 != _source_sha256(saved_output.source)
        or evidence.image_digest != SEMGREP_LOCK.image.index_digest
        or evidence.rules_commit != SEMGREP_LOCK.rules.commit
    ):
        raise BenchmarkInfrastructureError("Semgrep evidence identity is invalid")
    return evidence


def _saved_output_from_export(
    exported: ExportedSolution,
) -> SavedOutput:
    source = (
        None if exported.content is None else exported.content.decode("utf-8")
    )
    return SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        source=source,
        capture_error=exported.reason,
    )


def _source_sha256(source: str | None) -> str | None:
    return (
        None
        if source is None
        else hashlib.sha256(source.encode("utf-8")).hexdigest()
    )
