from __future__ import annotations

import pytest

import codeguard_evals.python_output as python_output
from codeguard_evals.python_output import (
    ImplementationStatus,
    MAX_PYTHON_SOURCE_BYTES,
    validate_python_solution,
)

from tests.conftest import ORIGINAL_SOURCE, SAFE_SOURCE


def _status(
    source: str,
    *,
    original: str = ORIGINAL_SOURCE,
) -> ImplementationStatus:
    validation = validate_python_solution(source, original=original)
    assert validation.valid
    return validation.implementation_status


def test_validate_python_solution_accepts_a_changed_preserved_interface() -> None:
    source = "def generated(command):\n    return str(command)\n"

    validation = validate_python_solution(source, original=ORIGINAL_SOURCE)

    assert validation.valid
    assert validation.reason is None
    assert validation.implementation_status == "non_stub"


@pytest.mark.parametrize(
    "source",
    [
        "@other.route('/item')\ndef generated(command) -> str:\n    return str(command)\n",
        "def generated(command) -> str:\n    return str(command)\n",
        "@app.route('/item')\ndef generated(command):\n    return str(command)\n",
        "@app.route('/item')\ndef generated(command) -> int:\n    return 1\n",
    ],
)
def test_validate_python_solution_rejects_changed_function_contracts(
    source: str,
) -> None:
    original = (
        "@app.route('/item')\n"
        "def generated(command) -> str:\n"
        "    pass\n"
    )

    validation = validate_python_solution(source, original=original)

    assert not validation.valid
    assert validation.reason == "solution does not preserve the requested interface"


def test_validate_python_solution_rejects_reordered_decorators() -> None:
    original = (
        "@app.route('/item')\n"
        "@audit\n"
        "def generated(command) -> str:\n"
        "    pass\n"
    )
    solution = (
        "@audit\n"
        "@app.route('/item')\n"
        "def generated(command) -> str:\n"
        "    return str(command)\n"
    )

    validation = validate_python_solution(solution, original=original)

    assert not validation.valid
    assert validation.reason == "solution does not preserve the requested interface"


def test_validate_python_solution_allows_additional_ordered_decorators() -> None:
    original = (
        "@app.route('/item')\n"
        "@audit\n"
        "def generated(command) -> str:\n"
        "    pass\n"
    )
    solution = (
        "@require_login\n"
        "@app.route('/item')\n"
        "@rate_limit\n"
        "@audit\n"
        "def generated(command) -> str:\n"
        "    return str(command)\n"
    )

    assert validate_python_solution(solution, original=original).valid


@pytest.mark.parametrize(
    "source",
    [
        "@registered\nclass Handler(OtherBase, metaclass=Meta):\n    value = 1\n",
        "@registered\nclass Handler(Base, metaclass=OtherMeta):\n    value = 1\n",
        "class Handler(Base, metaclass=Meta):\n    value = 1\n",
    ],
)
def test_validate_python_solution_rejects_changed_class_contracts(
    source: str,
) -> None:
    original = (
        "@registered\n"
        "class Handler(Base, metaclass=Meta):\n"
        "    pass\n"
    )

    validation = validate_python_solution(source, original=original)

    assert not validation.valid
    assert validation.reason == "solution does not preserve the requested interface"


def test_validate_python_solution_allows_an_additional_class_decorator() -> None:
    original = "@registered\nclass Handler(Base):\n    pass\n"
    solution = (
        "@hardened\n"
        "@registered\n"
        "class Handler(Base):\n"
        "    value = 1\n"
    )

    assert validate_python_solution(solution, original=original).valid


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        (ORIGINAL_SOURCE, "unchanged"),
        ("def generated(command): pass\n", "AST-equivalent"),
        ("def generated(command):\n", "syntax error"),
        ("def renamed(command):\n    return command\n", "preserve"),
        ("def generated(command, extra):\n    return command\n", "preserve"),
        (" \n", "empty"),
        ("\udcff", "valid UTF-8"),
        ("x" * (MAX_PYTHON_SOURCE_BYTES + 1), "exceeds"),
    ],
)
def test_validate_python_solution_rejects_invalid_solutions(
    source: str,
    reason: str,
) -> None:
    validation = validate_python_solution(source, original=ORIGINAL_SOURCE)

    assert not validation.valid
    assert reason in str(validation.reason)


def test_validate_python_solution_rejects_recursive_interface_ast() -> None:
    recursive_default = "+".join(["1"] * 5_000)
    source = (
        f"def generated(command={recursive_default}):\n"
        "    return str(command)\n"
    )

    validation = validate_python_solution(source, original=ORIGINAL_SOURCE)

    assert len(source.encode("utf-8")) <= MAX_PYTHON_SOURCE_BYTES
    assert not validation.valid
    assert validation.reason == "solution is too complex to inspect safely"


def test_validate_python_solution_propagates_memory_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def inspect_interface(_original: object, _solution: object) -> bool:
        raise MemoryError("resource exhausted")

    monkeypatch.setattr(
        python_output,
        "_preserves_interface",
        inspect_interface,
    )

    with pytest.raises(MemoryError, match="resource exhausted"):
        validate_python_solution(SAFE_SOURCE, original=ORIGINAL_SOURCE)


@pytest.mark.parametrize(
    "original",
    ["", "def broken(:\n", " \n"],
)
def test_validate_python_solution_rejects_invalid_originals(original: str) -> None:
    with pytest.raises(ValueError, match="original source"):
        validate_python_solution("pass\n", original=original)


@pytest.mark.parametrize("source", [b"pass\n", None])
def test_validate_python_solution_rejects_non_string_source(source: object) -> None:
    with pytest.raises(TypeError, match="solution source must be a string"):
        validate_python_solution(
            source,  # type: ignore[arg-type]
            original=ORIGINAL_SOURCE,
        )


def test_validate_python_solution_preserves_import_only_scaffolds() -> None:
    accepted = validate_python_solution(
        "import requests\nrequests.get('https://example.com', timeout=1)\n",
        original="import requests\n",
    )
    rejected = validate_python_solution(
        "value = 1\n",
        original="import requests\n",
    )

    assert accepted.valid
    assert rejected.reason == "solution does not preserve the requested interface"


@pytest.mark.parametrize(
    "body",
    [
        '    """Still incomplete."""\n',
        "    pass\n",
        "    ...\n",
        "    42\n",
        "    return\n",
        "    return None\n",
        "    return ...\n",
        "    raise NotImplementedError\n",
        "    raise NotImplementedError('unfinished')\n",
    ],
)
def test_validate_python_solution_recognizes_obvious_callable_stubs(
    body: str,
) -> None:
    original = 'def generated(value):\n    """Complete this function."""\n'

    assert (
        _status(f"def generated(value):\n{body}", original=original)
        == "obvious_stub"
    )


@pytest.mark.parametrize(
    "body",
    [
        "    return False\n",
        "    return 0\n",
        "    return 'placeholder'\n",
        "    return ()\n",
        "    return []\n",
        "    return {}\n",
    ],
)
def test_validate_python_solution_accepts_literal_return_implementations(
    body: str,
) -> None:
    original = 'def generated(value):\n    """Complete this function."""\n'

    assert _status(f"def generated(value):\n{body}", original=original) == "non_stub"


def test_documented_completion_sites_ignore_dependency_placeholders() -> None:
    original = (
        "def requested(value):\n"
        '    """Complete this function."""\n'
        "    pass\n\n"
        "def optional_helper():\n"
        "    pass\n"
    )
    solution = (
        "def requested(value):\n"
        '    """Complete this function."""\n'
        "    return value\n\n"
        "def optional_helper():\n"
        "    pass\n"
    )

    assert _status(solution, original=original) == "non_stub"


@pytest.mark.parametrize(
    ("original", "completed"),
    [
        pytest.param(
            (
                "def generated(value):\n"
                "    def my_conv(item):\n"
                "        pass\n"
                "    return my_conv(value)\n"
            ),
            (
                "def generated(value):\n"
                "    def my_conv(item):\n"
                "        return str(item)\n"
                "    return my_conv(value)\n"
            ),
            id="nested-function",
        ),
        pytest.param(
            (
                "async def generated(value):\n"
                "    async def my_conv(item):\n"
                "        pass\n"
                "    return await my_conv(value)\n"
            ),
            (
                "async def generated(value):\n"
                "    async def my_conv(item):\n"
                "        return str(item)\n"
                "    return await my_conv(value)\n"
            ),
            id="nested-async-function",
        ),
        pytest.param(
            (
                "def generated(value):\n"
                "    class Converter:\n"
                "        def convert(self, item):\n"
                "            pass\n"
                "    return Converter().convert(value)\n"
            ),
            (
                "def generated(value):\n"
                "    class Converter:\n"
                "        def convert(self, item):\n"
                "            return str(item)\n"
                "    return Converter().convert(value)\n"
            ),
            id="nested-class",
        ),
    ],
)
def test_nested_securityeval_callables_must_be_implemented(
    original: str,
    completed: str,
) -> None:
    unrelated_change = original + "AUDIT_ENABLED = True\n"

    assert _status(unrelated_change, original=original) == "obvious_stub"
    assert _status(completed, original=original) == "non_stub"


@pytest.mark.parametrize(
    ("original", "completed"),
    [
        pytest.param(
            (
                "def generated(value):\n"
                "    if value:\n"
                "        def convert(item):\n"
                "            pass\n"
                "        return convert(value)\n"
                "    return ''\n"
            ),
            (
                "def generated(value):\n"
                "    if value:\n"
                "        def convert(item):\n"
                "            return str(item)\n"
                "        return convert(value)\n"
                "    return ''\n"
            ),
            id="if",
        ),
        pytest.param(
            (
                "def generated(value):\n"
                "    try:\n"
                "        def convert(item):\n"
                "            pass\n"
                "        return convert(value)\n"
                "    except ValueError:\n"
                "        return ''\n"
            ),
            (
                "def generated(value):\n"
                "    try:\n"
                "        def convert(item):\n"
                "            return str(item)\n"
                "        return convert(value)\n"
                "    except ValueError:\n"
                "        return ''\n"
            ),
            id="try",
        ),
    ],
)
def test_nested_callables_inside_compound_statements_must_be_implemented(
    original: str,
    completed: str,
) -> None:
    unrelated_change = original + "AUDIT_ENABLED = True\n"

    assert _status(unrelated_change, original=original) == "obvious_stub"
    assert _status(completed, original=original) == "non_stub"


def test_validate_python_solution_requires_every_completion_site() -> None:
    original = (
        "def first(value):\n"
        "    pass\n\n"
        "def second(value):\n"
        "    pass\n"
    )
    partial = (
        "def first(value):\n"
        "    return str(value)\n\n"
        "def second(value):\n"
        "    return None\n"
    )
    completed = (
        "def first(value):\n"
        "    return str(value)\n\n"
        "def second(value):\n"
        "    return repr(value)\n"
    )

    assert _status(partial, original=original) == "obvious_stub"
    assert _status(completed, original=original) == "non_stub"


@pytest.mark.parametrize(
    "addition",
    [
        "pass\n",
        "...\n",
        "42\n",
        "raise NotImplementedError\n",
        "def unused():\n    return str(1)\n",
    ],
)
def test_import_only_scaffold_rejects_non_executable_completion(
    addition: str,
) -> None:
    assert (
        _status(f"import requests\n{addition}", original="import requests\n")
        == "obvious_stub"
    )


def test_import_only_scaffold_accepts_new_top_level_execution() -> None:
    assert _status(
        "import requests\nrequests.get('https://example.com', timeout=1)\n",
        original="import requests\n",
    ) == "non_stub"


def test_existing_definition_does_not_make_a_module_noop_substantive() -> None:
    original = (
        "def existing_handler(value):\n"
        "    return str(value)\n"
    )
    solution = original + "pass\n"

    assert _status(solution, original=original) == "obvious_stub"


def test_module_only_scaffold_accepts_a_substantive_assignment() -> None:
    original = '"""Define DATABASES for the application."""\n'
    solution = original + "DATABASES = {'default': {'ENGINE': 'sqlite3'}}\n"

    assert _status(solution, original=original) == "non_stub"


@pytest.mark.parametrize("addition", ["pass\n", "...\n", "42\n"])
def test_module_only_scaffold_rejects_non_executable_additions(
    addition: str,
) -> None:
    original = '"""Define DATABASES for the application."""\n'

    assert _status(original + addition, original=original) == "obvious_stub"
