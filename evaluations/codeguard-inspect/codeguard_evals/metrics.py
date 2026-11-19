"""Shared attempt aggregation and skill-read evidence."""

import hashlib
import json
import math
from collections.abc import Mapping
from typing import Literal

from inspect_ai.model import ChatMessageAssistant, ChatMessageTool
from inspect_ai.scorer import MetricProtocol, SampleScore, mean, metric, stderr
from inspect_ai.solver import TaskState
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from codeguard_evals.artifact_locks import (
    SHA256,
)
from codeguard_evals.skill_files import (
    CODEGUARD_SKILL_NAME, MAX_SKILL_FILE_BYTES, skill_content_sha256, skill_front_matter,
)
from codeguard_evals.skill_catalog import SkillName
from codeguard_evals.sandbox_protocol import CODEX_SKILLS_DIR
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import LANGUAGE_FILENAMES

SKILL_SNAPSHOT_KEY = "codeguard_evals.skill_snapshot"


class _SkillSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[2]
    skill_name: SkillName
    content_sha256: SHA256
    document_sha256: SHA256
    document: str = Field(min_length=1, max_length=MAX_SKILL_FILE_BYTES)

    @model_validator(mode="after")
    def verify_document(self) -> "_SkillSnapshot":
        raw = self.document.encode("utf-8")
        if (
            len(raw) > MAX_SKILL_FILE_BYTES
            or hashlib.sha256(raw).hexdigest() != self.document_sha256
        ):
            raise ValueError(
                "Skill document does not match its size/hash contract"
            )
        return self


def save_skill_snapshot(state: TaskState, snapshot: Mapping[str, bytes]) -> None:
    """Retain the trusted installation's original document for offline scoring."""
    if SKILL_SNAPSHOT_KEY in state.store:
        raise BenchmarkInfrastructureError("Skill snapshot already exists")
    document = snapshot["SKILL.md"]
    evidence = _SkillSnapshot(
        schema_version=2,
        skill_name=skill_front_matter(snapshot)["name"],
        content_sha256=skill_content_sha256(snapshot),
        document_sha256=hashlib.sha256(document).hexdigest(),
        document=document.decode("utf-8"),
    )
    state.store.set(SKILL_SNAPSHOT_KEY, evidence.model_dump(mode="json"))


@metric
def total() -> MetricProtocol:
    """Sum numeric sample scores after Inspect removes unscored values."""

    def compute(scores: list[SampleScore]) -> float:
        return float(sum(score.score.as_float() for score in scores))

    return compute


@metric(scores="unreduced")
def by_language() -> MetricProtocol:
    """Group attempt means and case-clustered standard errors by language."""

    def compute(scores: list[SampleScore]) -> dict[str, float]:
        result = {}
        for language in LANGUAGE_FILENAMES:
            selected = [
                sample
                for sample in scores
                if (sample.sample_metadata or {}).get("language") == language
                and math.isfinite(sample.score.as_float())
            ]
            if selected:
                result[f"{language}_mean"] = mean()(selected)
                result[f"{language}_stderr"] = stderr(cluster="case_id")(selected)
        return result

    return compute


def load_skill_snapshot(record: object) -> _SkillSnapshot:
    """Require the original installation evidence for a skill sample."""
    if record is None:
        raise BenchmarkInfrastructureError("Skill snapshot is missing")
    # Version 1 evidence predates selectable skills and always installed CodeGuard.
    if isinstance(record, dict) and record.get("schema_version") == 1 and "skill_name" not in record:
        record = {**record, "schema_version": 2, "skill_name": CODEGUARD_SKILL_NAME}
    try:
        return _SkillSnapshot.model_validate(record)
    except ValidationError:
        raise BenchmarkInfrastructureError(
            "Skill snapshot is invalid"
        ) from None


def skill_was_read(state: TaskState) -> int:
    """Score a skill read against the validated original installation."""
    evidence = load_skill_snapshot(state.store.get(SKILL_SNAPSHOT_KEY))
    skill_document = evidence.document
    # Match plain text and the supported single-layer JSON encodings:
    # literal Unicode or Python-style ASCII escapes.
    representations = dict.fromkeys((
        skill_document,
        json.dumps(skill_document, ensure_ascii=False)[1:-1],
        json.dumps(skill_document, ensure_ascii=True)[1:-1],
    ))
    # A complete returned document counts even if a later shell command fails.
    successful_reads: set[str] = set()
    for message in state.messages:
        if (
            not isinstance(message, ChatMessageTool)
            or message.tool_call_id is None
            or message.error is not None
        ):
            continue
        text = message.text
        if any(document in text for document in representations):
            successful_reads.add(message.tool_call_id)
    return int(
        any(
            isinstance(message, ChatMessageAssistant)
            and message.tool_calls is not None
            and any(
                call.id in successful_reads
                and call.parse_error is None
                and _reads_skill(call.arguments, evidence.skill_name)
                for call in message.tool_calls
            )
            for message in state.messages
        )
    )


def _reads_skill(arguments: dict[str, object], skill_name: str) -> bool:
    skill_path = f"{CODEX_SKILLS_DIR}/{skill_name}/SKILL.md"
    return any(
        type(value) is str and skill_path in value for value in arguments.values()
    )
