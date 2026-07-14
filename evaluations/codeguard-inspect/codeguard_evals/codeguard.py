"""Load an immutable copy of the repository's CodeGuard skill."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Final

PROJECT_ROOT: Final = Path(__file__).resolve().parents[3]
CODEGUARD_SOURCE: Final = PROJECT_ROOT / "skills/software-security"
MAX_CODEGUARD_FILES: Final = 128
MAX_CODEGUARD_FILE_BYTES: Final = 256 * 1024
MAX_CODEGUARD_TOTAL_BYTES: Final = 1024 * 1024

_RULE_NAME_RE: Final = re.compile(r"\Acodeguard-[A-Za-z0-9._-]+\.md\Z")
_CLOSE_ON_EXEC: Final = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOSE_ON_EXEC
)
_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOSE_ON_EXEC


def load_codeguard(source: Path = CODEGUARD_SOURCE) -> dict[str, bytes]:
    """Freeze the allowlisted CodeGuard layout into memory."""
    root_descriptor = _open_directory(source)
    try:
        root_stat = os.fstat(root_descriptor)
        root_names = set(_list_directory(root_descriptor, source))
        if "SKILL.md" not in root_names:
            raise ValueError(f"CodeGuard source is missing SKILL.md: {source}")
        if "rules" not in root_names:
            raise ValueError(f"CodeGuard source is missing rules: {source}")
        if root_names != {"SKILL.md", "rules"}:
            raise ValueError(f"CodeGuard source contains unexpected entries: {source}")

        rules_path = source / "rules"
        rules_descriptor = _open_directory(
            rules_path,
            name="rules",
            parent_descriptor=root_descriptor,
        )
        try:
            rules_stat = os.fstat(rules_descriptor)
            rule_names = _rule_names(rules_descriptor, rules_path)
            loaded: dict[str, bytes] = {}
            total_bytes = 0
            files = [("SKILL.md", "SKILL.md", root_descriptor)]
            files.extend(
                (f"rules/{name}", name, rules_descriptor) for name in rule_names
            )
            for relative_path, name, parent_descriptor in files:
                path = source / relative_path
                content = _read_regular_file(
                    name,
                    path,
                    parent_descriptor,
                    MAX_CODEGUARD_TOTAL_BYTES - total_bytes,
                )
                if not content:
                    raise ValueError(f"CodeGuard file is empty: {path}")
                total_bytes += len(content)
                loaded[relative_path] = content

            _require_unchanged_directory(rules_descriptor, rules_stat, rules_path)
            _require_unchanged_directory(root_descriptor, root_stat, source)
            return loaded
        finally:
            os.close(rules_descriptor)
    finally:
        os.close(root_descriptor)


def _open_directory(
    path: Path,
    *,
    name: str | None = None,
    parent_descriptor: int | None = None,
) -> int:
    try:
        if parent_descriptor is None:
            descriptor = os.open(path, _DIRECTORY_FLAGS)
        else:
            if name is None:
                raise ValueError("relative directory opens require a name")
            descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_descriptor)
    except OSError as exc:
        raise ValueError(f"Cannot safely open CodeGuard directory: {path}") from exc
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError(f"CodeGuard path is not a regular directory: {path}")
    return descriptor


def _list_directory(descriptor: int, path: Path) -> list[str]:
    try:
        names = os.listdir(descriptor)
    except OSError as exc:
        raise ValueError(f"Cannot inspect CodeGuard directory: {path}") from exc
    if any(not isinstance(name, str) for name in names):
        raise ValueError(f"CodeGuard directory contains an invalid name: {path}")
    return names


def _rule_names(descriptor: int, path: Path) -> list[str]:
    names = _list_directory(descriptor, path)
    if len(names) > MAX_CODEGUARD_FILES - 1:
        raise ValueError(f"CodeGuard source exceeds {MAX_CODEGUARD_FILES} files")
    for name in names:
        if _RULE_NAME_RE.fullmatch(name) is None:
            raise ValueError(f"CodeGuard source contains an unexpected rule: {path / name}")
    if not names:
        raise ValueError(f"CodeGuard source has no rules/codeguard-*.md files: {path.parent}")
    return sorted(names)


def _read_regular_file(
    name: str,
    path: Path,
    parent_descriptor: int,
    remaining_bytes: int,
) -> bytes:
    try:
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_descriptor)
    except OSError as exc:
        raise ValueError(f"Cannot safely open CodeGuard file: {path}") from exc
    with os.fdopen(descriptor, "rb", closefd=True) as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"CodeGuard path is not a regular file: {path}")
        if before.st_size > MAX_CODEGUARD_FILE_BYTES:
            raise ValueError(
                f"CodeGuard file exceeds {MAX_CODEGUARD_FILE_BYTES} bytes: {path}"
            )
        if before.st_size > remaining_bytes:
            raise ValueError(
                f"CodeGuard source exceeds {MAX_CODEGUARD_TOTAL_BYTES} bytes"
            )
        content = source.read(before.st_size + 1)
        after = os.fstat(source.fileno())
    if len(content) != before.st_size or _changed(before, after):
        raise ValueError(f"CodeGuard file changed while being read: {path}")
    return content


def _require_unchanged_directory(
    descriptor: int,
    before: os.stat_result,
    path: Path,
) -> None:
    if _changed(before, os.fstat(descriptor)):
        raise ValueError(f"CodeGuard directory changed while being read: {path}")


def _changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
