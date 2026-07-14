from __future__ import annotations

import importlib
from pathlib import Path
from typing import Any

import pytest
from inspect_ai import eval as inspect_eval
from inspect_ai.model import ChatMessage, GenerateConfig, ModelOutput, get_model
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.tool import ToolChoice, ToolInfo

from codeguard_evals.securityeval.dataset import SecurityEvalCase
from codeguard_evals.securityeval.securityeval import (
    MAX_GENERATION_TOKENS,
    TIME_LIMIT,
)

task_module = importlib.import_module("codeguard_evals.securityeval.securityeval")


@solver
def _fake_solver() -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
        return state

    return solve


def _codeguard_snapshot() -> dict[str, bytes]:
    return {
        "SKILL.md": (
            b"# CodeGuard\n- `codeguard-1-always.md`\n\n"
            b"| Language | Rules |\n| --- | --- |\n"
            b"| python | codeguard-0-python.md |\n"
        ),
        "rules/codeguard-1-always.md": b"# Always\n",
        "rules/codeguard-0-python.md": b"# Python\n",
    }


def test_task_is_one_tool_free_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    observed_generate: dict[str, Any] = {}
    sentinel = _fake_solver()

    def load_codeguard() -> dict[str, bytes]:
        events.append("codeguard")
        return _codeguard_snapshot()

    def load_cases() -> list[SecurityEvalCase]:
        events.append("dataset")
        return [SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", "pass\n")]

    def generate(**kwargs: Any) -> Solver:
        observed_generate.update(kwargs)
        return sentinel

    monkeypatch.setattr(task_module, "load_codeguard", load_codeguard)
    monkeypatch.setattr(task_module, "load_securityeval_cases", load_cases)
    monkeypatch.setattr(task_module, "bandit_securityeval_cases", list)
    monkeypatch.setattr(task_module, "generate", generate)

    task = task_module.securityeval()

    assert events == ["codeguard", "dataset"]
    assert observed_generate == {
        "tool_calls": "none",
        "max_tokens": MAX_GENERATION_TOKENS,
    }
    assert task.solver is sentinel
    assert task.sandbox is None
    assert task.time_limit == TIME_LIMIT
    assert task.token_limit is None
    assert task.turn_limit is None
    assert task.fail_on_error is False
    assert task.score_on_error is True
    assert task.scorer is not None
    assert len(task.dataset) == 3
    assert all(sample.files is None for sample in task.dataset)


def test_task_records_pinned_dataset_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(task_module, "load_codeguard", _codeguard_snapshot)
    monkeypatch.setattr(task_module, "bandit_securityeval_cases", list)
    monkeypatch.setattr(
        task_module,
        "load_securityeval_cases",
        lambda: [SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", "pass\n")],
    )

    task = task_module.securityeval()

    assert task.metadata == {
        "benchmark": "SecurityEval",
        "dataset": {
            "repository": task_module.SECURITYEVAL_REPO_ID,
            "filename": task_module.SECURITYEVAL_FILENAME,
            "revision": task_module.SECURITYEVAL_REVISION,
            "sha256": task_module.SECURITYEVAL_SOURCE_SHA256,
            "selection": "bandit-oracle-detectable",
            "selected_cases": len(task_module.BANDIT_CASE_IDS),
        },
    }


def test_task_runs_with_mockllm_without_a_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prompt = "def render(value):\n    pass\n"
    completion = "def render(value):\n    return str(value)\n"
    seen: list[list[ChatMessage]] = []

    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "inspect-trace.log"))
    monkeypatch.setattr(task_module, "load_codeguard", _codeguard_snapshot)
    monkeypatch.setattr(task_module, "bandit_securityeval_cases", list)
    monkeypatch.setattr(
        task_module,
        "load_securityeval_cases",
        lambda: [SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", prompt)],
    )

    def output(
        messages: list[ChatMessage],
        tools: list[ToolInfo],
        tool_choice: ToolChoice,
        config: GenerateConfig,
    ) -> ModelOutput:
        assert tools == []
        assert tool_choice == "none"
        assert config.max_tokens == MAX_GENERATION_TOKENS
        seen.append(messages)
        return ModelOutput.from_content("mockllm/model", completion)

    task = task_module.securityeval()
    log = inspect_eval(
        task,
        model=get_model("mockllm/model", custom_outputs=output),
        log_dir=str(tmp_path / "logs"),
        log_realtime=False,
        display="none",
    )[0]

    assert task.sandbox is None
    assert log.status == "success"
    assert len(seen) == 3
    assert all(
        [message.role for message in messages] == ["system", "user"]
        for messages in seen
    )
