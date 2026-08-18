from __future__ import annotations

import asyncio
import importlib
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.agent import Agent, AgentState, agent
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.model import get_model
from inspect_ai.solver import Generate, TaskState, generate

import codeguard_evals.output_artifact as artifact_module
from codeguard_evals.codeguard import codeguard_content_sha256
from codeguard_evals.output_artifact import (
    GENERATION_LIMIT_KEY,
    SAVED_OUTPUT_KEY,
    SavedOutput,
    validated_generation_limit,
)
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
)
from codeguard_evals.scorers import static_safety_scorer
from codeguard_evals.sandbox_protocol import (
    CODEX_HOME_DIR,
    CODEX_SKILLS_DIR,
    SANDBOX_NAME,
    SANDBOX_ROOT_USER,
    SANDBOX_USER,
    SANDBOX_WORKDIR,
    SOURCE_FILENAME,
)
from codeguard_evals.securityeval.dataset import (
    SECURITYEVAL_FILENAME,
    SECURITYEVAL_REPO_ID,
    SECURITYEVAL_REVISION,
    SECURITYEVAL_SOURCE_SHA256,
    SecurityEvalCase,
)
from codeguard_evals.securityeval.protocol import (
    EVALUATION_VERSION,
    Condition,
    condition_skill_name,
    securityeval_prompt,
    securityeval_task_name,
)
from codeguard_evals.securityeval.securityeval import (
    AGENT_TIME_LIMIT,
    CODEX_VERSION,
    CODEGUARD_DIRECTORY_MODE,
    CODEGUARD_FILE_MODE,
    CODEGUARD_RULES_DIR,
    CODEGUARD_SKILL_DIR,
    MAX_GENERATION_TOKENS,
    SAMPLE_TIME_LIMIT,
    bounded_generation,
)
from tests.conftest import FakeSandbox, ORIGINAL_SOURCE, task_state

task_module = importlib.import_module("codeguard_evals.securityeval.securityeval")


@agent
def _fake_codex_agent() -> Agent:
    async def execute(state: AgentState) -> AgentState:
        return state

    return execute


def _codeguard_snapshot() -> dict[str, bytes]:
    return {
        "SKILL.md": (
            b"---\n"
            b"name: codeguard\n"
            b"description: Secure coding rules for generated code.\n"
            b'codeguard-version: "1.4.0"\n'
            b"framework: Project CodeGuard\n"
            b"purpose: Secure code generation guidance\n"
            b"---\n"
            b"# CodeGuard\n"
            b"Read the relevant file in the `rules/` directory.\n"
        ),
        "rules/codeguard-0-python.md": b"# Python\nAvoid shell=True.\n",
    }


def _stub_loaders(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(task_module, "load_codeguard", _codeguard_snapshot)
    monkeypatch.setattr(
        task_module,
        "load_securityeval_cases",
        lambda: [
            SecurityEvalCase(
                "CWE-078_author_1.py",
                "CWE-78",
                "def generated(command):\n    pass\n",
            )
        ],
    )


@pytest.mark.parametrize(
    ("factory", "condition"),
    [
        ("securityeval_static_safety_baseline", "baseline"),
        ("securityeval_static_safety_secure_prompt", "secure_prompt"),
        ("securityeval_static_safety_codeguard", "codeguard"),
    ],
)
def test_tasks_use_one_static_safety_path_and_explicit_codex_home(
    factory: str,
    condition: Condition,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_loaders(monkeypatch)
    observed: dict[str, object] = {}
    capture_calls = 0

    def fake_codex_cli(**kwargs: object) -> Agent:
        observed.update(kwargs)
        return _fake_codex_agent()

    def fake_capture_generated_output() -> Callable[..., object]:
        nonlocal capture_calls
        capture_calls += 1
        return generate()

    monkeypatch.setattr(task_module, "codex_cli", fake_codex_cli)
    monkeypatch.setattr(
        task_module,
        "capture_generated_output",
        fake_capture_generated_output,
    )

    task = getattr(task_module, factory)()

    skill_name = condition_skill_name(condition)
    assert task.name == securityeval_task_name(condition)
    assert task.setup is not None
    assert len(task.setup) == (2 if condition == "codeguard" else 1)
    assert task.sandbox is not None
    assert task.sandbox.type == "docker"
    assert task.sandbox.config == str(task_module.SANDBOX_CONFIG)
    assert task.config.max_tokens == MAX_GENERATION_TOKENS
    assert task.config.max_connections == 1
    # Generation budgets are scoped to the agent so a truncated sample still
    # reaches capture; only the wedged-sandbox backstop stays at task level. It
    # has to stay looser than the agent's own budget, or it would abort the
    # chain first and drop the sample from every metric.
    assert task.time_limit == SAMPLE_TIME_LIMIT
    assert AGENT_TIME_LIMIT < SAMPLE_TIME_LIMIT
    assert task.token_limit is None
    assert task.turn_limit is None
    assert task.fail_on_error is True
    assert task.continue_on_fail is True
    assert task.score_on_error is False
    assert task.checkpoint == Task(checkpoint=False).checkpoint
    assert task.version == EVALUATION_VERSION
    assert capture_calls == 1
    assert task.scorer is not None and len(task.scorer) == 1
    assert len(task.dataset) == 1
    sample = task.dataset[0]
    assert sample.files is None
    assert sample.input == securityeval_prompt(condition)

    assert observed["version"] == CODEX_VERSION
    assert observed["cwd"] == SANDBOX_WORKDIR
    assert observed["home_dir"] == CODEX_HOME_DIR
    assert observed["user"] == SANDBOX_USER
    assert observed["sandbox"] == SANDBOX_NAME
    assert observed["web_search"] == "disabled"
    assert observed["goals"] is False
    assert observed["attempts"] == 1
    assert observed["retry_refusals"] == 0
    assert observed["auto_review"] is False
    assert observed["skills"] is None
    assert task.metadata["skill_available"] is (skill_name is not None)
    assert (task.metadata["codeguard"] is not None) == (skill_name is not None)
    assert task.metadata["python_version"] == task_module.PYTHON_VERSION


def _setup_state(target: str = ORIGINAL_SOURCE) -> TaskState:
    return task_state(
        sample_id="setup",
        target=target,
        input_text="",
        metadata={},
    )


def test_solution_setup_writes_the_validated_target_as_the_agent_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = FakeSandbox(SimpleNamespace(success=True))
    monkeypatch.setattr(task_module, "sandbox", lambda _name: environment)
    state = _setup_state()

    result = asyncio.run(
        task_module.prepare_solution_file()(state, cast(Generate, None))
    )

    assert result is state
    assert len(environment.calls) == 1
    command, arguments = environment.calls[0]
    assert command == [
        "/usr/bin/dd",
        f"of={SOURCE_FILENAME}",
        "status=none",
        "conv=excl",
    ]
    assert arguments["input"] == ORIGINAL_SOURCE.encode()
    assert arguments["cwd"] == SANDBOX_WORKDIR
    assert arguments["user"] == SANDBOX_USER
    assert arguments["timeout_retry"] is False


def test_solution_setup_fails_closed_when_the_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = FakeSandbox(SimpleNamespace(success=False))
    monkeypatch.setattr(task_module, "sandbox", lambda _name: environment)

    with pytest.raises(BenchmarkInfrastructureError, match="Could not prepare"):
        asyncio.run(
            task_module.prepare_solution_file()(
                _setup_state(),
                cast(Generate, None),
            )
        )


def test_solution_setup_rejects_an_invalid_target_before_exec(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = FakeSandbox()
    monkeypatch.setattr(task_module, "sandbox", lambda _name: environment)
    state = _setup_state("")

    with pytest.raises(ValueError, match="non-empty"):
        asyncio.run(
            task_module.prepare_solution_file()(
                state,
                cast(Generate, None),
            )
        )
    assert environment.calls == []


def test_codeguard_setup_installs_the_exact_repository_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = SimpleNamespace(success=True)
    snapshot = _codeguard_snapshot()
    environment = FakeSandbox(success, success, success, success, success)
    monkeypatch.setattr(task_module, "sandbox", lambda _name: environment)
    state = _setup_state()

    result = asyncio.run(
        task_module.install_codeguard_skill(snapshot)(state, cast(Generate, None))
    )

    assert result is state
    assert environment.calls[0] == (
        ["/usr/bin/mkdir", "-p", task_module.CODEGUARD_RULES_DIR],
        {
            "user": SANDBOX_ROOT_USER,
            "timeout": 10,
            "timeout_retry": False,
        },
    )
    writes = environment.calls[1 : 1 + len(snapshot)]
    assert [arguments["input"] for _command, arguments in writes] == [
        snapshot[path] for path in sorted(snapshot)
    ]
    assert [command for command, _arguments in writes] == [
        ["/usr/bin/dd", f"of={path}", "status=none", "conv=excl"]
        for path in sorted(snapshot)
    ]
    for _command, arguments in writes:
        assert arguments["cwd"] == CODEGUARD_SKILL_DIR
        assert arguments["user"] == SANDBOX_ROOT_USER
        assert arguments["timeout"] == 10
        assert arguments["timeout_retry"] is False
    assert environment.calls[-2] == (
        [
            "/usr/bin/chmod",
            CODEGUARD_FILE_MODE,
            *(f"{CODEGUARD_SKILL_DIR}/{path}" for path in sorted(snapshot)),
        ],
        {
            "user": SANDBOX_ROOT_USER,
            "timeout": 10,
            "timeout_retry": False,
        },
    )
    assert environment.calls[-1] == (
        [
            "/usr/bin/chmod",
            CODEGUARD_DIRECTORY_MODE,
            CODEX_SKILLS_DIR,
            CODEGUARD_SKILL_DIR,
            CODEGUARD_RULES_DIR,
        ],
        {
            "user": SANDBOX_ROOT_USER,
            "timeout": 10,
            "timeout_retry": False,
        },
    )


@pytest.mark.parametrize(
    "results",
    [
        (SimpleNamespace(success=False),),
        (SimpleNamespace(success=True), SimpleNamespace(success=False)),
        (
            SimpleNamespace(success=True),
            SimpleNamespace(success=True),
            SimpleNamespace(success=True),
            SimpleNamespace(success=False),
        ),
        (
            SimpleNamespace(success=True),
            SimpleNamespace(success=True),
            SimpleNamespace(success=True),
            SimpleNamespace(success=True),
            SimpleNamespace(success=False),
        ),
    ],
)
def test_codeguard_setup_fails_closed_when_installation_fails(
    results: tuple[SimpleNamespace, ...],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = FakeSandbox(*results)
    monkeypatch.setattr(task_module, "sandbox", lambda _name: environment)

    with pytest.raises(BenchmarkInfrastructureError, match="Could not install"):
        asyncio.run(
            task_module.install_codeguard_skill(_codeguard_snapshot())(
                _setup_state(),
                cast(Generate, None),
            )
        )


@pytest.mark.parametrize(
    ("budget", "budget_value", "expected"),
    [
        ("TURN_LIMIT", 2, "turn"),
        ("OUTPUT_TOKEN_LIMIT", 40, "token"),
        ("AGENT_TIME_LIMIT", 0.01, "time"),
    ],
)
def test_bounded_generation_records_the_budget_that_truncated_the_agent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    budget: str,
    budget_value: int | float,
    expected: str,
) -> None:
    """A truncated sample must count as a weak generation, not disappear.

    Applied as task limits these would abort the chain before capture, so the
    scorer would find no evidence and the sample would leave every denominator.
    """
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    monkeypatch.setattr(task_module, budget, budget_value)

    async def export() -> ExportedSolution:
        # Truncated before the agent changed anything the setup wrote.
        return ExportedSolution(ORIGINAL_SOURCE.encode(), None)

    monkeypatch.setattr(artifact_module, "export_solution", export)

    @agent
    def overruns_its_budget() -> Agent:
        async def execute(state: AgentState) -> AgentState:
            if expected == "time":
                await asyncio.sleep(1)
                return state
            for _ in range(8):
                state.output = await get_model().generate(state.messages)
                state.messages.append(state.output.message)
            return state

        return execute

    case_id = "CWE-078_author_1.py"
    task = Task(
        name="static_safety_truncated_generation",
        dataset=MemoryDataset(
            [
                Sample(
                    id=f"static_safety/baseline/{case_id}",
                    input=securityeval_prompt("baseline"),
                    target=ORIGINAL_SOURCE,
                    metadata={
                        "case_id": case_id,
                        "cwe": "CWE-78",
                        "condition": "baseline",
                    },
                )
            ]
        ),
        solver=bounded_generation(overruns_its_budget()),
        scorer=static_safety_scorer(),
        time_limit=SAMPLE_TIME_LIMIT,
    )

    log = inspect_eval(
        task,
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
        log_realtime=False,
        ctl_server=False,
    )[0]

    assert log.status == "success", log.error
    assert log.samples is not None and len(log.samples) == 1
    sample = log.samples[0]
    assert sample.error is None
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == (
        ORIGINAL_SOURCE
    )
    assert sample.store[GENERATION_LIMIT_KEY] == expected

    assert sample.scores is not None
    score = sample.scores["static_safety_scorer"]
    assert score.answer == ORIGINAL_SOURCE
    assert score.metadata is not None
    assert score.metadata["generation_limit"] == expected
    score_values = cast(dict[str, object], score.value)
    assert score_values["valid_output"] == 0
    assert score_values["implemented_output"] == 0

    assert log.results is not None
    results = {result.name: result for result in log.results.scores}
    assert results["valid_output"].scored_samples == 1
    assert results["implemented_output"].scored_samples == 1


def test_bounded_generation_propagates_unrelated_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exported = False

    async def export() -> ExportedSolution:
        nonlocal exported
        exported = True
        return ExportedSolution(ORIGINAL_SOURCE.encode(), None)

    monkeypatch.setattr(artifact_module, "export_solution", export)

    @agent
    def cancelled_agent() -> Agent:
        async def execute(state: AgentState) -> AgentState:
            del state
            raise asyncio.CancelledError

        return execute

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            bounded_generation(cancelled_agent())(
                _setup_state(),
                cast(Generate, None),
            )
        )

    assert exported is False


def test_bounded_generation_rejects_a_budget_it_did_not_apply() -> None:
    for unsupported in ("message", "working", "cost", "operator", ""):
        with pytest.raises(ValueError, match="unsupported generation limit"):
            validated_generation_limit(unsupported)
    assert validated_generation_limit(None) is None


def test_task_records_pinned_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_loaders(monkeypatch)
    monkeypatch.setattr(task_module, "codex_cli", lambda **kwargs: _fake_codex_agent())

    task = task_module.securityeval_static_safety_codeguard()

    assert task.metadata == {
        "benchmark": "SecurityEval",
        "suite": "static_safety",
        "condition": "codeguard",
        "agent": "codex-cli",
        "codex_version": CODEX_VERSION,
        "inspect_swe_version": task_module.INSPECT_SWE_VERSION,
        "python_version": task_module.PYTHON_VERSION,
        "skill_available": True,
        "codeguard": {
            "version": "1.4.0",
            "content_sha256": codeguard_content_sha256(_codeguard_snapshot()),
        },
        "sandbox": "docker-compose",
        "dataset": {
            "repository": SECURITYEVAL_REPO_ID,
            "filename": SECURITYEVAL_FILENAME,
            "revision": SECURITYEVAL_REVISION,
            "sha256": SECURITYEVAL_SOURCE_SHA256,
            "selection": "all-cases",
            "selected_cases": 1,
        },
    }
