"""Select reviewed local skill snapshots and read their saved experiment identity."""

import argparse
import re

from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import Annotated, Final

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from codeguard_evals.artifact_locks import RelativePath, SHA256
from codeguard_evals.artifacts import require_directory
from codeguard_evals.protocol import condition_has_skill
from codeguard_evals.safe_io import load_strict_json, read_bounded
from codeguard_evals.skill_files import (
    CODEGUARD_SKILL_NAME, PROJECT_ROOT, SKILL_NAME_PATTERN, load_skill_files,
    skill_content_sha256, skill_front_matter, skill_version,
)

CATALOG_PATH = Path(__file__).parents[1] / "skill_snapshots/catalog.json"
# The benchmark packages' CodeGuard tasks select this entry; add a snapshot for each release.
CODEGUARD_VARIANT: Final = "codeguard-1.5"
VariantId = Annotated[str, Field(pattern=re.compile(r"\A[a-z0-9]+(?:[.-][a-z0-9]+)*\Z"), max_length=80)]
SkillName = Annotated[str, Field(pattern=SKILL_NAME_PATTERN, max_length=64)]
Label = Annotated[str, Field(pattern=re.compile(r"\A[A-Za-z0-9][A-Za-z0-9 ._()+-]*\Z"), max_length=80)]


class RecordedSkill(BaseModel):
    """Skill identity a saved log proves; historical CodeGuard logs have no catalog ID."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    id: VariantId | None
    label: Label
    name: SkillName
    content_sha256: SHA256
    version: str | None = Field(default=None, max_length=128)


class SkillProvenance(RecordedSkill):
    id: VariantId


class _CatalogEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    label: Label
    path: RelativePath
    content_sha256: SHA256


_CATALOG = TypeAdapter(dict[VariantId, _CatalogEntry])


def load_skill_directory(
    relative: str, *, expected_hash: str | None = None,
) -> tuple[dict[str, bytes], dict]:
    """Freeze a repository-relative skill and return its validated front matter."""
    relative = TypeAdapter(RelativePath).validate_python(relative)
    path = PROJECT_ROOT
    for part in PurePosixPath(relative).parts:
        path /= part
        require_directory(path)
    snapshot = load_skill_files(path)
    # Check the reviewed bytes before parsing their metadata.
    if expected_hash is not None and skill_content_sha256(snapshot) != expected_hash:
        raise ValueError("Skill contents do not match the pinned fingerprint")
    fields = skill_front_matter(snapshot)
    if fields["name"] != path.name:
        raise ValueError("The skill name must match its directory name")
    return snapshot, fields


def load_skill_catalog() -> dict[str, _CatalogEntry]:
    """Read the catalog without loading any skill contents."""
    try:
        return _CATALOG.validate_python(load_strict_json(
            read_bounded(CATALOG_PATH, 64 * 1024, label="Skill catalog")
        ))
    except (OSError, ValueError):
        raise ValueError("The skill catalog is missing or invalid") from None


def load_skill_variant(variant: str) -> tuple[dict[str, bytes], SkillProvenance]:
    """Verify only the selected input, then pass frozen bytes to task setup."""
    entries = load_skill_catalog()
    if not isinstance(variant, str) or variant not in entries:
        raise ValueError("Select a skill variant ID from skill_snapshots/catalog.json")
    spec = entries[variant]
    snapshot, fields = load_skill_directory(spec.path, expected_hash=spec.content_sha256)
    version = skill_version(fields)
    return snapshot, SkillProvenance(
        id=variant, label=spec.label, name=fields["name"],
        content_sha256=spec.content_sha256,
        version=None if version == "unspecified" else version,
    )


def recorded_skill(metadata: Mapping) -> RecordedSkill | None:
    """Normalize saved skill identity without loading the current catalog or files."""
    condition = metadata.get("condition")
    if not condition_has_skill(condition):
        return None
    try:
        if condition == "skill":
            return SkillProvenance.model_validate(metadata.get("skill"))
        legacy = metadata.get("codeguard")
        if not isinstance(legacy, dict) or not isinstance(legacy.get("version"), str):
            raise ValueError
        version = legacy["version"]
        return RecordedSkill(
            id=None, label=f"CodeGuard {version}", name=CODEGUARD_SKILL_NAME,
            content_sha256=legacy.get("content_sha256"), version=version,
        )
    except ValueError:
        raise ValueError("The recorded skill identity is missing or invalid") from None


def main() -> None:
    parser = argparse.ArgumentParser(description="Fingerprint a local Agent Skill without running it.")
    parser.add_argument("path", help="Skill directory relative to the repository root")
    args = parser.parse_args()
    try:
        snapshot, _ = load_skill_directory(args.path)
        print(skill_content_sha256(snapshot))
    except (OSError, ValueError):
        parser.exit(2, "Cannot fingerprint the skill: check its path, files and frontmatter.\n")


if __name__ == "__main__":
    main()
