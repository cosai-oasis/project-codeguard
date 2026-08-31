"""Bounded, stability-checked file reads and strict JSON parsing.

Standard library only: this module is installed into the agent sandbox image,
where the exporter uses it to read untrusted, possibly-changing output.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Final

READ_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def read_bounded(path: Path, maximum: int, *, label: str) -> bytes:
    """Read a stable regular file of at most ``maximum`` bytes."""
    descriptor = os.open(path, READ_FLAGS)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file: {path}")
        if before.st_size > maximum:
            raise ValueError(f"{label} exceeds {maximum} bytes")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(maximum + 1)
            after = os.fstat(source.fileno())
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise ValueError(f"{label} exceeds {maximum} bytes")
    if len(raw) != before.st_size or stat_changed(before, after):
        raise ValueError(f"{label} changed while being read: {path}")
    return raw


def stat_changed(before: os.stat_result, after: os.stat_result) -> bool:
    """Report whether a file's identity, size, or timestamps moved."""
    return _identity(before) != _identity(after)


def load_strict_json(raw: str | bytes) -> object:
    """Parse JSON, rejecting duplicate keys and non-standard constants."""
    return json.loads(
        raw,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")
