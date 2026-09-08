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
_METADATA_FIELDS: Final = frozenset({"codeguard-version", "framework", "purpose"})
_FRONT_MATTER_FIELDS: Final = frozenset({"name", "description"}) | _METADATA_FIELDS


def load_codeguard(source: Path = CODEGUARD_SOURCE) -> dict[str, bytes]:
    """Freeze the allowlisted CodeGuard layout into memory."""
    skill_path = source / "SKILL.md"
    rules_path = source / "rules"
    _require_directory(source)
    _require_directory(rules_path)
    if not skill_path.exists():
        raise ValueError(f"CodeGuard source is missing SKILL.md: {source}")
    if {entry.name for entry in source.iterdir()} != {"SKILL.md", "rules"}:
        raise ValueError(f"CodeGuard source contains unexpected entries: {source}")

    rules = sorted(rules_path.iterdir())
    if len(rules) > MAX_CODEGUARD_FILES - 1:
        raise ValueError(f"CodeGuard source exceeds {MAX_CODEGUARD_FILES} files")
    loaded = {"SKILL.md": _read_codeguard_file(skill_path)}
    total_bytes = len(loaded["SKILL.md"])
    if total_bytes > MAX_CODEGUARD_TOTAL_BYTES:
        raise ValueError(f"CodeGuard source exceeds {MAX_CODEGUARD_TOTAL_BYTES} bytes")
    for rule in rules:
        if _RULE_NAME_RE.fullmatch(rule.name) is None:
            raise ValueError(f"CodeGuard source contains an unexpected rule: {rule}")
        content = _read_codeguard_file(rule)
        total_bytes += len(content)
        if total_bytes > MAX_CODEGUARD_TOTAL_BYTES:
            raise ValueError(
                f"CodeGuard source exceeds {MAX_CODEGUARD_TOTAL_BYTES} bytes"
            )
        loaded[f"rules/{rule.name}"] = content
    if len(loaded) == 1:
        raise ValueError(f"CodeGuard source has no rules/codeguard-*.md files: {source}")
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
    """Validate the frozen repository skill and return its declared version."""
    rule_names = _require_expected_layout(snapshot)
    content = _decode_utf8(snapshot["SKILL.md"], "SKILL.md")
    if not content.startswith("---\n"):
        raise ValueError("CodeGuard SKILL.md is missing YAML front matter")
    parts = content.split("---\n", 2)
    if len(parts) != 3:
        raise ValueError("CodeGuard SKILL.md has malformed YAML front matter")
    front_matter = yaml.safe_load(parts[1])
    if not isinstance(front_matter, dict) or set(front_matter) != _FRONT_MATTER_FIELDS:
        raise ValueError("CodeGuard SKILL.md has unexpected front matter")
    if front_matter["name"] != CODEGUARD_SKILL_NAME:
        raise ValueError("CodeGuard SKILL.md has an unexpected name")
    description = front_matter["description"]
    if not isinstance(description, str) or not description:
        raise ValueError("CodeGuard SKILL.md has an invalid description")
    metadata = {field: front_matter[field] for field in sorted(_METADATA_FIELDS)}
    if any(not isinstance(value, str) or not value for value in metadata.values()):
        raise ValueError("CodeGuard SKILL.md metadata values must be non-empty strings")
    if not parts[2].strip():
        raise ValueError("CodeGuard SKILL.md has empty instructions")
    for name in rule_names:
        path = f"rules/{name}"
        _decode_utf8(snapshot[path], path)
    return metadata["codeguard-version"]


def _require_expected_layout(snapshot: Mapping[str, bytes]) -> list[str]:
    """Return the snapshot's rule names, rejecting any unexpected path."""
    if len(snapshot) > MAX_CODEGUARD_FILES:
        raise ValueError(f"CodeGuard snapshot exceeds {MAX_CODEGUARD_FILES} files")
    names: list[str] = []
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
        if not path.startswith("rules/"):
            raise ValueError(f"CodeGuard snapshot contains an unexpected path: {path}")
        name = path.removeprefix("rules/")
        if _RULE_NAME_RE.fullmatch(name) is None:
            raise ValueError(f"CodeGuard snapshot contains an invalid rule: {path}")
        names.append(name)
    if "SKILL.md" not in snapshot:
        raise ValueError("CodeGuard snapshot has an unexpected layout")
    if not names:
        raise ValueError("CodeGuard snapshot contains no rules")
    return sorted(names)


def _decode_utf8(content: object, path: str) -> str:
    if not isinstance(content, bytes):
        raise ValueError(f"CodeGuard {path} content must be bytes")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"CodeGuard {path} is not valid UTF-8") from exc
