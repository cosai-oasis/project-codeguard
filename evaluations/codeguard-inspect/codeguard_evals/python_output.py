"""Validate a Python solution against its original source scaffold."""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

from codeguard_evals.sandbox_protocol import MAX_PYTHON_SOURCE_BYTES

ImplementationStatus = Literal["non_stub", "obvious_stub", "unassessed"]
STUB_CLASSIFIER_NAME: Final = "python-ast-obvious-stub"


@dataclass(frozen=True)
class OutputValidation:
    valid: bool
    reason: str | None
    loc: int
    implementation_status: ImplementationStatus


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


def validate_python_solution(source: str, *, original: str) -> OutputValidation:
    """Validate and classify bounded UTF-8 Python without executing it."""
    validated_original_bytes(original)
    try:
        original_tree = ast.parse(original)
    except SyntaxError as exc:
        raise ValueError("original source must be valid Python") from exc
    except RecursionError as exc:
        raise ValueError("original source is too complex to parse safely") from exc

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
    if source == original:
        return _invalid(source, "solution is unchanged from the original")
    try:
        source_tree = ast.parse(source)
    except SyntaxError as exc:
        line = exc.lineno if exc.lineno is not None else 0
        return _invalid(source, f"syntax error at line {line}: {exc.msg}")
    except RecursionError:
        return _invalid(source, "solution is too complex to parse safely")
    try:
        preserves_interface = _preserves_interface(original_tree, source_tree)
    except RecursionError:
        return _invalid(source, "solution is too complex to inspect safely")
    if not preserves_interface:
        return _invalid(source, "solution does not preserve the requested interface")
    try:
        equivalent = _dump(source_tree) == _dump(original_tree)
    except RecursionError:
        return _invalid(source, "solution is too complex to compare safely")
    if equivalent:
        return _invalid(source, "solution is AST-equivalent to the original")
    try:
        implementation_status = _implementation_status(original_tree, source_tree)
    except RecursionError as exc:
        raise ValueError("solution is too complex to classify safely") from exc
    return OutputValidation(
        valid=True,
        reason=None,
        loc=_loc(source),
        implementation_status=implementation_status,
    )


def _dump(node: ast.AST) -> str:
    """Structural comparison key; attributes are excluded so line numbers do
    not make two structurally identical trees compare unequal."""
    return ast.dump(node, include_attributes=False)


def _dump_optional(node: ast.AST | None) -> str | None:
    return None if node is None else _dump(node)


def _dump_all(nodes: Iterable[ast.AST]) -> tuple[str, ...]:
    return tuple(_dump(node) for node in nodes)


def _preserves_interface(original: ast.Module, solution: ast.Module) -> bool:
    solution_definitions = {
        (type(node), node.name): node
        for node in solution.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    required_definition = False
    for node in original.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        required_definition = True
        candidate = solution_definitions.get((type(node), node.name))
        if candidate is None:
            return False
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return False
            if (
                _dump(node.args) != _dump(candidate.args)
                or (
                    _dump_optional(node.returns)
                    != _dump_optional(candidate.returns)
                )
                or not _preserves_decorators(
                    node.decorator_list,
                    candidate.decorator_list,
                )
            ):
                return False
        elif isinstance(node, ast.ClassDef):
            if not isinstance(candidate, ast.ClassDef):
                return False
            if (
                _dump_all(node.bases) != _dump_all(candidate.bases)
                or _dump_all(node.keywords) != _dump_all(candidate.keywords)
                or not _preserves_decorators(
                    node.decorator_list,
                    candidate.decorator_list,
                )
            ):
                return False
    if required_definition:
        return True

    required_imports = {
        _dump(node)
        for node in original.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }
    solution_imports = {
        _dump(node)
        for node in solution.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
    }
    return required_imports <= solution_imports


def _preserves_decorators(
    required: list[ast.expr],
    observed: list[ast.expr],
) -> bool:
    """Require original decorators in order while allowing new decorators."""
    remaining = iter(observed)
    for required_decorator in required:
        for observed_decorator in remaining:
            if _dump(required_decorator) == _dump(observed_decorator):
                break
        else:
            return False
    return True


def _invalid(source: str, reason: str) -> OutputValidation:
    return OutputValidation(
        valid=False,
        reason=reason,
        loc=_loc(source),
        implementation_status="unassessed",
    )


def _loc(source: str) -> int:
    """Count non-blank lines, so conditions can be compared for code volume."""
    return sum(1 for line in source.splitlines() if line.strip())


def _implementation_status(
    original: ast.Module,
    solution: ast.Module,
) -> ImplementationStatus:
    original_callables = _callable_definitions(original)
    stub_sites = {
        path: node
        for path, node in original_callables.items()
        if _is_stub_body(node.body)
    }
    documented_sites = {
        path: node
        for path, node in stub_sites.items()
        if _has_docstring(node.body)
    }
    completion_sites = documented_sites or stub_sites
    if completion_sites:
        solution_callables = _callable_definitions(solution)
        for path, original_node in completion_sites.items():
            candidate = solution_callables.get(path)
            if candidate is None or type(candidate) is not type(original_node):
                return "obvious_stub"
            if _dump(original_node.args) != _dump(candidate.args):
                return "obvious_stub"
            if _is_stub_body(candidate.body):
                return "obvious_stub"
        return "non_stub"

    if not _has_new_module_execution(original, solution):
        return "obvious_stub"
    return "non_stub"


def _callable_definitions(
    module: ast.Module,
) -> dict[tuple[str, ...], ast.FunctionDef | ast.AsyncFunctionDef]:
    definitions: dict[
        tuple[str, ...],
        ast.FunctionDef | ast.AsyncFunctionDef,
    ] = {}

    def collect(node: ast.AST, prefix: tuple[str, ...]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                path = (*prefix, child.name)
                definitions[path] = child
                collect(child, path)
            elif isinstance(child, ast.ClassDef):
                collect(child, (*prefix, child.name))
            else:
                collect(child, prefix)

    collect(module, ())
    return definitions


def _is_stub_body(body: list[ast.stmt]) -> bool:
    statements = body[1:] if _has_docstring(body) else body
    return not statements or all(
        _is_stub_statement(statement) for statement in statements
    )


def _has_docstring(body: list[ast.stmt]) -> bool:
    return bool(body) and _is_docstring(body[0])


def _is_docstring(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _is_stub_statement(statement: ast.stmt) -> bool:
    if isinstance(statement, ast.Pass):
        return True
    if isinstance(statement, ast.Expr):
        return isinstance(statement.value, ast.Constant)
    if isinstance(statement, ast.Return):
        return statement.value is None or (
            isinstance(statement.value, ast.Constant)
            and statement.value.value in {None, Ellipsis}
        )
    if not isinstance(statement, ast.Raise) or statement.exc is None:
        return False
    exception = statement.exc.func if isinstance(statement.exc, ast.Call) else statement.exc
    return isinstance(exception, ast.Name) and exception.id == "NotImplementedError"


def _has_new_module_execution(original: ast.Module, solution: ast.Module) -> bool:
    original_statements = {
        _dump(node)
        for node in original.body
        if _is_module_execution(node)
    }
    return any(
        _is_module_execution(node)
        and _dump(node) not in original_statements
        for node in solution.body
    )


def _is_module_execution(node: ast.stmt) -> bool:
    if isinstance(
        node,
        (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
    ):
        return False
    if isinstance(node, ast.Pass):
        return False
    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
        return False
    return not _is_stub_statement(node)
