"""Load and fingerprint bounded Markdown skill snapshots without rewriting them."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import yaml

from codeguard_evals.artifacts import require_directory
from codeguard_evals.safe_io import read_bounded

PROJECT_ROOT: Final = Path(__file__).resolve().parents[3]
# Historical CodeGuard logs record this installed skill name.
CODEGUARD_SKILL_NAME: Final = "codeguard"
MAX_SKILL_FILES: Final = 128
MAX_SKILL_FILE_BYTES: Final = 256 * 1024
MAX_SKILL_TOTAL_BYTES: Final = 1024 * 1024

_RULE_NAME_RE: Final = re.compile(r"\Acodeguard-[A-Za-z0-9._-]+\.md\Z")
_REFERENCE_NAME_RE: Final = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\.md\Z")
SKILL_NAME_PATTERN: Final = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_METADATA_FIELDS: Final = frozenset({"codeguard-version", "framework", "purpose"})
_BASE_FRONT_MATTER_FIELDS: Final = frozenset({"name", "description"})
_FRONT_MATTER_FIELDS: Final = _BASE_FRONT_MATTER_FIELDS | _METADATA_FIELDS | {
    "license", "compatibility", "metadata", "allowed-tools",
}


def load_skill_files(source: Path) -> dict[str, bytes]:
    """Freeze an allowlisted skill layout into memory."""
    skill_path = source / "SKILL.md"
    require_directory(source)
    if not skill_path.exists():
        raise ValueError(f"Skill source is missing SKILL.md: {source}")
    entries = {entry.name for entry in source.iterdir()}
    guidance_dirs = entries & {"rules", "references"}
    if len(guidance_dirs) > 1 or entries != {"SKILL.md", *guidance_dirs}:
        raise ValueError(f"Skill source contains unexpected entries: {source}")
    guidance_dir = next(iter(guidance_dirs), None)
    guidance = []
    if guidance_dir is not None:
        guidance_path = source / guidance_dir
        require_directory(guidance_path)
        guidance = sorted(guidance_path.iterdir())
    if len(guidance) > MAX_SKILL_FILES - 1:
        raise ValueError(f"Skill source exceeds {MAX_SKILL_FILES} files")
    loaded = {"SKILL.md": _read_skill_file(skill_path)}
    total_bytes = len(loaded["SKILL.md"])
    if total_bytes > MAX_SKILL_TOTAL_BYTES:
        raise ValueError(f"Skill source exceeds {MAX_SKILL_TOTAL_BYTES} bytes")
    name_pattern = _RULE_NAME_RE if guidance_dir == "rules" else _REFERENCE_NAME_RE
    for guidance_file in guidance:
        if name_pattern.fullmatch(guidance_file.name) is None:
            raise ValueError(
                f"Skill source contains unexpected guidance: {guidance_file}"
            )
        content = _read_skill_file(guidance_file)
        total_bytes += len(content)
        if total_bytes > MAX_SKILL_TOTAL_BYTES:
            raise ValueError(
                f"Skill source exceeds {MAX_SKILL_TOTAL_BYTES} bytes"
            )
        loaded[f"{guidance_dir}/{guidance_file.name}"] = content
    for path, content in loaded.items():
        if not content:
            raise ValueError(f"Skill file is empty: {source / path}")
    return loaded


def _read_skill_file(path: Path) -> bytes:
    try:
        return read_bounded(
            path,
            MAX_SKILL_FILE_BYTES,
            label="Skill file",
        )
    except OSError as exc:
        raise ValueError(f"Cannot safely open Skill file: {path}") from exc


def skill_content_sha256(snapshot: Mapping[str, bytes]) -> str:
    """Hash the original skill paths and bytes in canonical order."""
    _require_expected_layout(snapshot)
    digest = hashlib.sha256()
    for path in sorted(snapshot):
        content = snapshot[path]
        encoded_path = path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(8, "big"))
        digest.update(encoded_path)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def skill_front_matter(snapshot: Mapping[str, bytes]) -> dict:
    """Validate Agent Skills metadata and Markdown, preserving the original bytes."""
    guidance_paths = _require_expected_layout(snapshot)
    content = _decode_utf8(snapshot["SKILL.md"], "SKILL.md")
    lines = content.splitlines(keepends=True)
    if not lines or lines[0].rstrip("\r\n") != "---":
        raise ValueError("Skill SKILL.md is missing YAML front matter")
    end = next((i for i, line in enumerate(lines[1:], 1) if line.rstrip("\r\n") == "---"), None)
    if end is None:
        raise ValueError("Skill SKILL.md has malformed YAML front matter")
    try:
        fields = yaml.safe_load("".join(lines[1:end]))
    except (yaml.YAMLError, RecursionError):
        raise ValueError("Skill SKILL.md has malformed YAML front matter") from None
    if (not isinstance(fields, dict) or not _BASE_FRONT_MATTER_FIELDS <= fields.keys()
            or not fields.keys() <= _FRONT_MATTER_FIELDS):
        raise ValueError("Skill SKILL.md has unexpected front matter")
    name, description = fields["name"], fields["description"]
    if (not isinstance(name, str) or len(name) > 64
            or SKILL_NAME_PATTERN.fullmatch(name) is None):
        raise ValueError("Skill SKILL.md has an invalid name")
    if (not isinstance(description, str) or not description.strip()
            or len(description) > 1024):
        raise ValueError("Skill SKILL.md has an invalid description")
    for field in _METADATA_FIELDS | {"license", "compatibility", "allowed-tools"}:
        if field in fields and (not isinstance(fields[field], str) or not fields[field].strip()):
            raise ValueError("Skill metadata values must be non-empty strings")
    if len(fields.get("compatibility", "")) > 500:
        raise ValueError("Skill compatibility exceeds 500 characters")
    metadata = fields.get("metadata", {})
    if not isinstance(metadata, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in metadata.items()
    ):
        raise ValueError("Skill metadata must map strings to strings")
    if not "".join(lines[end + 1:]).strip():
        raise ValueError("Skill SKILL.md has empty instructions")
    for path in guidance_paths:
        _decode_utf8(snapshot[path], path)
    return fields


def skill_version(fields: Mapping) -> str:
    """Read the declared version from validated skill front matter."""
    metadata = fields.get("metadata", {})
    return fields.get(
        "codeguard-version", metadata.get("codeguard-version", metadata.get("version", "unspecified"))
    )


def _require_expected_layout(snapshot: Mapping[str, bytes]) -> list[str]:
    """Return guidance paths, rejecting any mixed or unexpected layout."""
    if len(snapshot) > MAX_SKILL_FILES:
        raise ValueError(f"Skill snapshot exceeds {MAX_SKILL_FILES} files")
    guidance_paths: list[str] = []
    guidance_dir: str | None = None
    total_bytes = 0
    for path, content in snapshot.items():
        if not isinstance(path, str):
            raise ValueError("Skill snapshot contains an invalid path")
        if not isinstance(content, bytes) or not content:
            raise ValueError(f"Skill snapshot has invalid content: {path}")
        if len(content) > MAX_SKILL_FILE_BYTES:
            raise ValueError(
                f"Skill snapshot file exceeds {MAX_SKILL_FILE_BYTES} bytes"
            )
        total_bytes += len(content)
        if total_bytes > MAX_SKILL_TOTAL_BYTES:
            raise ValueError(
                f"Skill snapshot exceeds {MAX_SKILL_TOTAL_BYTES} bytes"
            )
        if path == "SKILL.md":
            continue
        prefix = next(
            (
                candidate
                for candidate in ("rules/", "references/")
                if path.startswith(candidate)
            ),
            None,
        )
        if prefix is None:
            raise ValueError(f"Skill snapshot contains an unexpected path: {path}")
        current_dir = prefix.removesuffix("/")
        if guidance_dir is None:
            guidance_dir = current_dir
        elif current_dir != guidance_dir:
            raise ValueError("Skill snapshot mixes guidance layouts")
        name = path.removeprefix(prefix)
        pattern = _RULE_NAME_RE if current_dir == "rules" else _REFERENCE_NAME_RE
        if pattern.fullmatch(name) is None:
            raise ValueError(f"Skill snapshot contains invalid guidance: {path}")
        guidance_paths.append(path)
    if "SKILL.md" not in snapshot:
        raise ValueError("Skill snapshot has an unexpected layout")
    return sorted(guidance_paths)


def _decode_utf8(content: object, path: str) -> str:
    if not isinstance(content, bytes):
        raise ValueError(f"Skill {path} content must be bytes")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Skill {path} is not valid UTF-8") from exc
