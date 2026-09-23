"""Load a bounded, immutable copy of the repository's CodeGuard skill."""

from __future__ import annotations

import hashlib
import re
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Final

import yaml

from codeguard_evals.safe_io import read_bounded

PROJECT_ROOT: Final = Path(__file__).resolve().parents[3]
CODEGUARD_SOURCE: Final = PROJECT_ROOT / "skills/codeguard"
CODEGUARD_SKILL_NAME: Final = "codeguard"
MAX_CODEGUARD_FILES: Final = 128
MAX_CODEGUARD_FILE_BYTES: Final = 256 * 1024
MAX_CODEGUARD_TOTAL_BYTES: Final = 1024 * 1024

_RULE_NAME_RE: Final = re.compile(r"\Acodeguard-[A-Za-z0-9._-]+\.md\Z")
_REFERENCE_NAME_RE: Final = re.compile(r"\A[a-z0-9]+(?:-[a-z0-9]+)*\.md\Z")
_METADATA_FIELDS: Final = frozenset({"codeguard-version", "framework", "purpose"})
_BASE_FRONT_MATTER_FIELDS: Final = frozenset({"name", "description"})
_FRONT_MATTER_FIELDS: Final = _BASE_FRONT_MATTER_FIELDS | _METADATA_FIELDS


def load_codeguard(source: Path = CODEGUARD_SOURCE) -> dict[str, bytes]:
    """Freeze the allowlisted CodeGuard layout into memory."""
    skill_path = source / "SKILL.md"
    _require_directory(source)
    if not skill_path.exists():
        raise ValueError(f"CodeGuard source is missing SKILL.md: {source}")
    entries = {entry.name for entry in source.iterdir()}
    guidance_dirs = entries & {"rules", "references"}
    if len(guidance_dirs) != 1 or entries != {"SKILL.md", *guidance_dirs}:
        raise ValueError(f"CodeGuard source contains unexpected entries: {source}")
    guidance_dir = guidance_dirs.pop()
    guidance_path = source / guidance_dir
    _require_directory(guidance_path)

    guidance = sorted(guidance_path.iterdir())
    if len(guidance) > MAX_CODEGUARD_FILES - 1:
        raise ValueError(f"CodeGuard source exceeds {MAX_CODEGUARD_FILES} files")
    loaded = {"SKILL.md": _read_codeguard_file(skill_path)}
    total_bytes = len(loaded["SKILL.md"])
    if total_bytes > MAX_CODEGUARD_TOTAL_BYTES:
        raise ValueError(f"CodeGuard source exceeds {MAX_CODEGUARD_TOTAL_BYTES} bytes")
    name_pattern = _RULE_NAME_RE if guidance_dir == "rules" else _REFERENCE_NAME_RE
    for guidance_file in guidance:
        if name_pattern.fullmatch(guidance_file.name) is None:
            raise ValueError(
                f"CodeGuard source contains unexpected guidance: {guidance_file}"
            )
        content = _read_codeguard_file(guidance_file)
        total_bytes += len(content)
        if total_bytes > MAX_CODEGUARD_TOTAL_BYTES:
            raise ValueError(
                f"CodeGuard source exceeds {MAX_CODEGUARD_TOTAL_BYTES} bytes"
            )
        loaded[f"{guidance_dir}/{guidance_file.name}"] = content
    if len(loaded) == 1:
        raise ValueError(f"CodeGuard source has no guidance files: {source}")
    for path, content in loaded.items():
        if not content:
            raise ValueError(f"CodeGuard file is empty: {source / path}")
    return loaded


def _require_directory(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as exc:
        raise ValueError(f"Cannot inspect CodeGuard directory: {path}") from exc
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"CodeGuard path is not a directory: {path}")


def _read_codeguard_file(path: Path) -> bytes:
    try:
        return read_bounded(
            path,
            MAX_CODEGUARD_FILE_BYTES,
            label="CodeGuard file",
        )
    except OSError as exc:
        raise ValueError(f"Cannot safely open CodeGuard file: {path}") from exc


def codeguard_content_sha256(snapshot: Mapping[str, bytes]) -> str:
    """Hash the original CodeGuard paths and bytes in canonical order."""
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


def codeguard_version(snapshot: Mapping[str, bytes]) -> str:
    """Validate the skill and return its declared version, or 'unspecified'."""
    guidance_paths = _require_expected_layout(snapshot)
    content = _decode_utf8(snapshot["SKILL.md"], "SKILL.md")
    if not content.startswith("---\n"):
        raise ValueError("CodeGuard SKILL.md is missing YAML front matter")
    parts = content.split("---\n", 2)
    if len(parts) != 3:
        raise ValueError("CodeGuard SKILL.md has malformed YAML front matter")
    front_matter = yaml.safe_load(parts[1])
    if not isinstance(front_matter, dict):
        raise ValueError("CodeGuard SKILL.md has unexpected front matter")
    front_matter_fields = frozenset(front_matter)
    if front_matter_fields not in {
        _FRONT_MATTER_FIELDS,
        _BASE_FRONT_MATTER_FIELDS,
    }:
        raise ValueError("CodeGuard SKILL.md has unexpected front matter")
    if front_matter["name"] != CODEGUARD_SKILL_NAME:
        raise ValueError("CodeGuard SKILL.md has an unexpected name")
    description = front_matter["description"]
    if not isinstance(description, str) or not description:
        raise ValueError("CodeGuard SKILL.md has an invalid description")
    if not parts[2].strip():
        raise ValueError("CodeGuard SKILL.md has empty instructions")
    for path in guidance_paths:
        _decode_utf8(snapshot[path], path)
    if front_matter_fields == _BASE_FRONT_MATTER_FIELDS:
        return "unspecified"
    metadata = {field: front_matter[field] for field in sorted(_METADATA_FIELDS)}
    if any(not isinstance(value, str) or not value for value in metadata.values()):
        raise ValueError("CodeGuard SKILL.md metadata values must be non-empty strings")
    return metadata["codeguard-version"]


def _require_expected_layout(snapshot: Mapping[str, bytes]) -> list[str]:
    """Return guidance paths, rejecting any mixed or unexpected layout."""
    if len(snapshot) > MAX_CODEGUARD_FILES:
        raise ValueError(f"CodeGuard snapshot exceeds {MAX_CODEGUARD_FILES} files")
    guidance_paths: list[str] = []
    guidance_dir: str | None = None
    total_bytes = 0
    for path, content in snapshot.items():
        if not isinstance(path, str):
            raise ValueError("CodeGuard snapshot contains an invalid path")
        if not isinstance(content, bytes) or not content:
            raise ValueError(f"CodeGuard snapshot has invalid content: {path}")
        if len(content) > MAX_CODEGUARD_FILE_BYTES:
            raise ValueError(
                f"CodeGuard snapshot file exceeds {MAX_CODEGUARD_FILE_BYTES} bytes"
            )
        total_bytes += len(content)
        if total_bytes > MAX_CODEGUARD_TOTAL_BYTES:
            raise ValueError(
                f"CodeGuard snapshot exceeds {MAX_CODEGUARD_TOTAL_BYTES} bytes"
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
            raise ValueError(f"CodeGuard snapshot contains an unexpected path: {path}")
        current_dir = prefix.removesuffix("/")
        if guidance_dir is None:
            guidance_dir = current_dir
        elif current_dir != guidance_dir:
            raise ValueError("CodeGuard snapshot mixes guidance layouts")
        name = path.removeprefix(prefix)
        pattern = _RULE_NAME_RE if current_dir == "rules" else _REFERENCE_NAME_RE
        if pattern.fullmatch(name) is None:
            raise ValueError(f"CodeGuard snapshot contains invalid guidance: {path}")
        guidance_paths.append(path)
    if "SKILL.md" not in snapshot:
        raise ValueError("CodeGuard snapshot has an unexpected layout")
    if not guidance_paths:
        raise ValueError("CodeGuard snapshot contains no guidance")
    return sorted(guidance_paths)


def _decode_utf8(content: object, path: str) -> str:
    if not isinstance(content, bytes):
        raise ValueError(f"CodeGuard {path} content must be bytes")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"CodeGuard {path} is not valid UTF-8") from exc
