"""Shared test data and fixtures.

Nearly every test in this suite is built on one pair: a SecurityEval scaffold
with an unfilled function body, and a solution that fills it. Keeping them here
means a change to the shape of a scaffold does not have to be mirrored across
three modules.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from inspect_ai.model import ChatMessage, ModelName, ModelOutput
from inspect_ai.scorer import Target
from inspect_ai.solver import TaskState

from codeguard_evals.sandbox_protocol import (
    CODEX_HOME_DIR,
    CODEX_SKILLS_DIR,
    SANDBOX_WORKDIR,
)
from codeguard_evals.securityeval.protocol import TASK_PROMPT

# A scaffold as the dataset supplies it: signature present, body unfilled.
ORIGINAL_SOURCE = "def generated(command):\n    pass\n"
# The same scaffold with a real implementation.
SAFE_SOURCE = "def generated(command):\n    return str(command)\n"
# A parse-valid no-op body used to verify that validation does not infer intent.
STUB_SOURCE = "def generated(command):\n    return None\n"

CASE_ID = "CWE-078_author_1.py"
SAMPLE_CWE = "CWE-78"
SAMPLE_ID = f"static_safety/baseline/{CASE_ID}"

TMPFS_REQUIRED_OPTIONS: Final[Mapping[str, frozenset[str]]] = MappingProxyType(
    {
        SANDBOX_WORKDIR: frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=32m",
                "uid=65532",
                "gid=0",
                "mode=0730",
            }
        ),
        CODEX_HOME_DIR: frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=32m",
                "uid=65532",
                "gid=0",
                "mode=0730",
            }
        ),
        CODEX_SKILLS_DIR: frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=2m",
                "uid=0",
                "gid=0",
                "mode=0755",
            }
        ),
        "/tmp": frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "noexec",
                "size=16m",
                "uid=0",
                "gid=0",
                "mode=1777",
            }
        ),
        "/var/tmp": frozenset(
            {
                "rw",
                "nosuid",
                "nodev",
                "exec",
                "size=384m",
                "uid=0",
                "gid=0",
                "mode=1777",
            }
        ),
    }
)


def task_state(
    *,
    sample_id: str = SAMPLE_ID,
    target: str = ORIGINAL_SOURCE,
    input_text: str | list[ChatMessage] = TASK_PROMPT,
    output: ModelOutput | None = None,
    messages: list[ChatMessage] | None = None,
    metadata: dict[str, object] | None = None,
) -> TaskState:
    """Build the common SecurityEval state used by solver and scorer tests."""
    return TaskState(
        model=ModelName("mockllm/model"),
        sample_id=sample_id,
        epoch=1,
        input=input_text,
        target=Target(target),
        messages=[] if messages is None else messages,
        output=(
            ModelOutput.from_content("mockllm/model", "done")
            if output is None
            else output
        ),
        metadata=(
            {
                "case_id": CASE_ID,
                "cwe": SAMPLE_CWE,
                "condition": "baseline",
            }
            if metadata is None
            else metadata
        ),
    )


def assert_tmpfs_policy(
    tmpfs: Mapping[str, str],
    expected: Mapping[str, frozenset[str]] = TMPFS_REQUIRED_OPTIONS,
) -> None:
    """Assert the writable mounts shared by static and live container tests."""
    assert set(tmpfs) == set(expected)
    for path, expected_options in expected.items():
        observed = set(tmpfs[path].split(","))
        assert observed == expected_options, path


class FakeSandbox:
    """Minimal queued sandbox used by solver and exporter tests."""

    def __init__(self, *results: object) -> None:
        self._results = iter(results)
        self.calls: list[tuple[list[str], dict[str, object]]] = []

    async def exec(self, command: list[str], **arguments: object) -> object:
        self.calls.append((command, arguments))
        result = next(self._results)
        if isinstance(result, BaseException):
            raise result
        return result
