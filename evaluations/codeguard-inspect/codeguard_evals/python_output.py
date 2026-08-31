"""Bound and parse generated Python without executing it."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from codeguard_evals.sandbox_protocol import MAX_PYTHON_SOURCE_BYTES


@dataclass(frozen=True)
class OutputValidation:
    valid: bool
    reason: str | None
    loc: int


def validated_original_bytes(original_source: str) -> bytes:
    """Validate and encode a trusted benchmark scaffold."""
    if not isinstance(original_source, str) or not original_source.strip():
        raise ValueError("original source must be a non-empty string")
    try:
        raw = original_source.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("original source must be valid UTF-8") from exc
    if len(raw) > MAX_PYTHON_SOURCE_BYTES:
        raise ValueError(f"original source exceeds {MAX_PYTHON_SOURCE_BYTES} bytes")
    return raw


def validate_python_solution(source: str) -> OutputValidation:
    """Validate bounded UTF-8 Python without executing it."""
    if not isinstance(source, str):
        raise TypeError("solution source must be a string")
    try:
        raw = source.encode("utf-8")
    except UnicodeEncodeError:
        return _invalid(source, "solution is not valid UTF-8")

    if len(raw) > MAX_PYTHON_SOURCE_BYTES:
        return _invalid(source, f"solution exceeds {MAX_PYTHON_SOURCE_BYTES} bytes")
    if not source.strip():
        return _invalid(source, "empty solution")
    try:
        ast.parse(source)
    except SyntaxError as exc:
        line = exc.lineno if exc.lineno is not None else 0
        return _invalid(source, f"syntax error at line {line}: {exc.msg}")
    except RecursionError:
        return _invalid(source, "solution is too complex to parse safely")
    return OutputValidation(
        valid=True,
        reason=None,
        loc=_loc(source),
    )


def _invalid(source: str, reason: str) -> OutputValidation:
    return OutputValidation(
        valid=False,
        reason=reason,
        loc=_loc(source),
    )


def _loc(source: str) -> int:
    """Count non-blank lines, so conditions can be compared for code volume."""
    return sum(1 for line in source.splitlines() if line.strip())
