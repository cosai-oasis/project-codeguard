"""Validate Python source returned directly by a model."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Final

MAX_PYTHON_SOURCE_BYTES: Final = 64 * 1024


@dataclass(frozen=True)
class OutputValidation:
    valid: bool
    reason: str | None
    text: str | None
    size_bytes: int
    sha256: str


def validate_output(
    output: str | None,
    *,
    prompt: str,
    stop_reason: str,
    generation_error: str | None = None,
) -> OutputValidation:
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    try:
        prompt_bytes = prompt.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("prompt must be valid UTF-8") from exc
    if len(prompt_bytes) > MAX_PYTHON_SOURCE_BYTES:
        raise ValueError(f"prompt exceeds {MAX_PYTHON_SOURCE_BYTES} bytes")
    try:
        prompt_tree = ast.parse(prompt)
    except SyntaxError as exc:
        raise ValueError("prompt must be valid Python") from exc
    except (MemoryError, RecursionError) as exc:
        raise ValueError("prompt is too complex to parse safely") from exc

    if output is None:
        return _invalid(b"", "missing output")
    if not isinstance(output, str):
        raise TypeError("output must be a string or None")
    try:
        raw = output.encode("utf-8")
    except UnicodeEncodeError:
        return _invalid(b"", "output is not valid UTF-8")

    if generation_error is not None:
        if not isinstance(generation_error, str) or not generation_error.strip():
            raise ValueError("generation_error must be a non-empty string")
        return _invalid(raw, f"generation failed: {generation_error[:4096]}")
    if not isinstance(stop_reason, str) or not stop_reason:
        raise ValueError("stop_reason must be a non-empty string")
    if stop_reason != "stop":
        return _invalid(raw, f"generation stopped with {stop_reason}")
    if len(raw) > MAX_PYTHON_SOURCE_BYTES:
        return _invalid(raw, f"output exceeds {MAX_PYTHON_SOURCE_BYTES} bytes")
    if not output.strip():
        return _invalid(raw, "empty output")
    if output == prompt:
        return _invalid(raw, "output is unchanged from the prompt")
    try:
        output_tree = ast.parse(output)
    except SyntaxError as exc:
        line = exc.lineno if exc.lineno is not None else 0
        return _invalid(raw, f"syntax error at line {line}: {exc.msg}")
    except (MemoryError, RecursionError):
        return _invalid(raw, "output is too complex to parse safely")
    if not _preserves_interface(prompt_tree, output_tree):
        return _invalid(raw, "output does not preserve the requested interface")
    try:
        equivalent = ast.dump(output_tree, include_attributes=False) == ast.dump(
            prompt_tree, include_attributes=False
        )
    except (MemoryError, RecursionError):
        return _invalid(raw, "output is too complex to compare safely")
    if equivalent:
        return _invalid(raw, "output is AST-equivalent to the prompt")
    return OutputValidation(
        valid=True,
        reason=None,
        text=output,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _preserves_interface(prompt: ast.Module, output: ast.Module) -> bool:
    output_definitions = {
        (type(node), node.name): node
        for node in output.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    required_definition = False
    for node in prompt.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        required_definition = True
        candidate = output_definitions.get((type(node), node.name))
        if candidate is None:
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
            if ast.dump(node.args, include_attributes=False) != ast.dump(
                candidate.args, include_attributes=False
            ):
                return False
    if required_definition:
        return True

    required_imports = {
        ast.dump(node, include_attributes=False)
        for node in prompt.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }
    output_imports = {
        ast.dump(node, include_attributes=False)
        for node in output.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }
    return bool(required_imports) and required_imports <= output_imports


def _invalid(raw: bytes, reason: str) -> OutputValidation:
    return OutputValidation(
        valid=False,
        reason=reason,
        text=None,
        size_bytes=len(raw),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
