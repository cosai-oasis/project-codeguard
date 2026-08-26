from __future__ import annotations

import pytest

import codeguard_evals.python_output as python_output_module
from codeguard_evals.python_output import (
    MAX_PYTHON_SOURCE_BYTES,
    validate_python_solution,
    validated_original_bytes,
)

from tests.conftest import ORIGINAL_SOURCE, SAFE_SOURCE, STUB_SOURCE


@pytest.mark.parametrize("source", [ORIGINAL_SOURCE, SAFE_SOURCE, STUB_SOURCE])
def test_validate_python_solution_accepts_parseable_source(source: str) -> None:
    validation = validate_python_solution(source)

    assert validation.valid
    assert validation.reason is None
    assert validation.loc == 2


def test_validate_python_solution_parses_without_executing_source() -> None:
    source = "raise RuntimeError('must not execute')\n"

    validation = validate_python_solution(source)

    assert validation.valid
    assert validation.loc == 1


def test_validate_python_solution_counts_only_nonblank_lines() -> None:
    source = "\nvalue = 1\n   \nreturn_value = value\n"

    assert validate_python_solution(source).loc == 2


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("def generated(command):\n", "syntax error"),
        (" \n", "empty"),
        ("\udcff", "valid UTF-8"),
        ("x" * (MAX_PYTHON_SOURCE_BYTES + 1), "exceeds"),
    ],
)
def test_validate_python_solution_rejects_invalid_source(
    source: str,
    reason: str,
) -> None:
    validation = validate_python_solution(source)

    assert not validation.valid
    assert reason in str(validation.reason)


@pytest.mark.parametrize("source", [b"pass\n", None])
def test_validate_python_solution_rejects_non_string_source(source: object) -> None:
    with pytest.raises(TypeError, match="solution source must be a string"):
        validate_python_solution(source)  # type: ignore[arg-type]


def test_validate_python_solution_propagates_memory_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exhaust_memory(_source: str) -> object:
        raise MemoryError

    monkeypatch.setattr(python_output_module.ast, "parse", exhaust_memory)

    with pytest.raises(MemoryError):
        validate_python_solution("pass\n")


def test_validate_python_solution_normalizes_parser_recursion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def recurse(_source: str) -> object:
        raise RecursionError

    monkeypatch.setattr(python_output_module.ast, "parse", recurse)

    validation = validate_python_solution("pass\n")

    assert not validation.valid
    assert validation.reason == "solution is too complex to parse safely"
    assert validation.loc == 1


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (None, "non-empty string"),
        (" \n", "non-empty string"),
        ("\udcff", "valid UTF-8"),
        ("x" * (MAX_PYTHON_SOURCE_BYTES + 1), "exceeds"),
    ],
)
def test_validated_original_bytes_rejects_invalid_scaffolds(
    source: object,
    reason: str,
) -> None:
    with pytest.raises(ValueError, match=reason):
        validated_original_bytes(source)  # type: ignore[arg-type]
