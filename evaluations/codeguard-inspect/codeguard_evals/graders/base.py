"""Host-side grading contract, independent of generation and sandbox transports."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from inspect_ai.scorer import Scorer
    from inspect_ai.solver import TaskState



@dataclass(frozen=True)
class StaticGrader:
    """A trusted collector, evidence validator, and scorer for offline replay."""

    filename: Callable[[TaskState], str]
    collect: Callable[[list[TaskState]], Awaitable[dict[tuple[str | int, int], str]]]
    validate: Callable[[TaskState], None]
    scorer: Scorer
    sandbox_config: Path
    evidence_key: str
    identity: dict[str, object]  # Includes the selected "cpus" ceiling.
    prepare: Callable[[], object] | None = None
