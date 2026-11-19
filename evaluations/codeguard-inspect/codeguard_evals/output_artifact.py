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

from codeguard_evals.protocol import EVALUATION_VERSION
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
    export_solution,
)
from codeguard_evals.sandbox_protocol import (
    MAX_PYTHON_SOURCE_BYTES,
    MAX_REASON_LENGTH,
    SOURCE_FILENAME,
    validate_source_filename,
)

SAVED_OUTPUT_KEY: Final = "codeguard_evals.saved_output"

_Reason = Annotated[str, Field(min_length=1, max_length=MAX_REASON_LENGTH)]


class SavedOutput(BaseModel):
    """One strictly validated solution artifact persisted in Inspect's store."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    evaluation_version: str
    filename: str = SOURCE_FILENAME
    source: str | None
    capture_error: _Reason | None

    @property
    def source_sha256(self) -> str | None:
        """Derive identity from exact UTF-8 source without adding a stored field."""
        return (
            None
            if self.source is None
            else hashlib.sha256(self.source.encode("utf-8")).hexdigest()
        )

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        return validate_source_filename(value)

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


async def capture_generated_output(
    state: TaskState, filename: str
) -> None:
    """Capture the exact solution bytes before sandbox teardown."""
    if SAVED_OUTPUT_KEY in state.store:
        raise BenchmarkInfrastructureError("Saved output evidence already exists")

    validate_source_filename(filename)
    exported = await export_solution(filename)
    try:
        saved = _saved_output_from_export(exported, filename=filename)
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


def _saved_output_from_export(
    exported: ExportedSolution,
    *,
    filename: str,
) -> SavedOutput:
    source = None if exported.content is None else exported.content.decode("utf-8")
    return SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        filename=filename,
        source=source,
        capture_error=exported.reason,
    )
