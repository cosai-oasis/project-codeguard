"""Capture and replay one bounded benchmark output through Inspect logs."""

from __future__ import annotations

from typing import Annotated, Final, Literal, cast, get_args

from inspect_ai.solver import Generate, Solver, TaskState, solver
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

GenerationLimit = Literal["token", "turn", "time"]

SAVED_OUTPUT_KEY: Final = "codeguard_evals.saved_output"
GENERATION_LIMIT_KEY: Final = "codeguard_evals.generation_limit"
GENERATION_LIMITS: Final[frozenset[str]] = frozenset(get_args(GenerationLimit))

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


@solver
def capture_generated_output() -> Solver:
    """Capture the exact solution bytes before sandbox teardown."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
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
        return state

    return solve


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
) -> SavedOutput:
    source = (
        None if exported.content is None else exported.content.decode("utf-8")
    )
    return SavedOutput(
        evaluation_version=EVALUATION_VERSION,
        source=source,
        capture_error=exported.reason,
    )


def validated_generation_limit(value: object) -> GenerationLimit | None:
    """Accept only the budgets this harness applies to generation."""
    if value is None:
        return None
    if type(value) is not str or value not in GENERATION_LIMITS:
        raise ValueError(f"unsupported generation limit: {value!r}")
    return cast(GenerationLimit, value)
