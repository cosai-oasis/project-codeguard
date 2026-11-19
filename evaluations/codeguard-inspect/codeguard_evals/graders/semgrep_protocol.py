"""Shared Semgrep error semantics; standard library only."""

from pathlib import Path
from typing import Final, Literal

AnalysisFailure = Literal["parse_error", "rule_timeout", "resource_limit"]

# Recognized per-file error types: (exit code at warn/error level, failure reason).
_FILE_ERRORS: Final[dict[str, tuple[int, AnalysisFailure]]] = {
    "Syntax error": (3, "parse_error"),
    "Lexical error": (3, "parse_error"),
    "Other syntax error": (2, "parse_error"),
    "AST builder error": (2, "parse_error"),
    "Timeout": (2, "rule_timeout"),
    "Too many matches": (2, "resource_limit"),
    "Fixpoint timeout": (2, "resource_limit"),
    "Stack overflow": (2, "resource_limit"),
    "Out of memory": (2, "resource_limit"),
}
# A file with several errors keeps its most severe reason.
_SEVERITY: Final[dict[AnalysisFailure, int]] = {
    "parse_error": 0,
    "rule_timeout": 1,
    "resource_limit": 2,
}


def analysis_failures(errors: list, paths: set[Path]) -> dict[Path, AnalysisFailure]:
    """Bind recognized incomplete analyses to submitted files; reject global faults."""
    failures: dict[Path, AnalysisFailure] = {}
    for error in errors:
        kind = error["type"]
        locations = [error["path"]] if "path" in error else []
        if isinstance(kind, list) and len(kind) == 2 and kind[0] == "PartialParsing":
            if not isinstance(kind[1], list) or not kind[1]:
                raise ValueError
            locations.extend(location["path"] for location in kind[1])
            kind = "Syntax error"

        if not isinstance(kind, str) or kind not in _FILE_ERRORS:
            raise ValueError
        code, reason = _FILE_ERRORS[kind]
        rule_id = error.get("rule_id")
        if kind == "Timeout" and (not isinstance(rule_id, str) or not rule_id):
            raise ValueError

        level = error.get("level")
        if level not in ("info", "warn", "error"):
            raise ValueError
        expected_code = 0 if level == "info" else code
        if type(error.get("code")) is not int or error["code"] != expected_code:
            raise ValueError

        if not locations or not all(isinstance(value, str) for value in locations):
            raise ValueError
        files = {Path("/", value) for value in locations}
        if not files <= paths:
            raise ValueError

        for file in files:
            if file not in failures or _SEVERITY[reason] > _SEVERITY[failures[file]]:
                failures[file] = reason
    return failures
