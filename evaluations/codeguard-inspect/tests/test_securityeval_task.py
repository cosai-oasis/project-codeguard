from __future__ import annotations

import asyncio
import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from inspect_ai import Task
from inspect_ai import eval as inspect_eval
from inspect_ai.agent import Agent, AgentState, agent
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.event import SampleLimitEvent
from inspect_ai.model import get_model
from inspect_ai.solver import Generate, TaskState
from inspect_ai.util import LimitExceededError

import codeguard_evals.output_artifact as artifact_module
from codeguard_evals.codeguard import codeguard_content_sha256
from codeguard_evals.output_artifact import (
    SAVED_OUTPUT_KEY,
    SEMGREP_EVIDENCE_KEY,
    SavedOutput,
    SemgrepEvidence,
    load_semgrep_evidence,
)
from codeguard_evals.sandbox_client import (
    BenchmarkInfrastructureError,
    ExportedSolution,
)
from codeguard_evals.sandbox_protocol import (
    CODEX_HOME_DIR,
    CODEX_SKILLS_DIR,
    SANDBOX_NAME,
    SANDBOX_ROOT_USER,
    SANDBOX_USER,
    SANDBOX_WORKDIR,
    SOURCE_FILENAME,
)
from codeguard_evals.scorers import static_safety_scorer
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
    CODEGUARD_DIRECTORY_MODE,
    CODEGUARD_FILE_MODE,
    CODEGUARD_RULES_DIR,
    CODEGUARD_SKILL_DIR,
    CODEX_VERSION,
    MAX_GENERATION_TOKENS,
    SAMPLE_TIME_LIMIT,
    bounded_generation,
)
from codeguard_evals.semgrep_artifacts import SemgrepFinding
from tests.conftest import ORIGINAL_SOURCE, SAFE_SOURCE, FakeSandbox, task_state

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

    def fake_codex_cli(**kwargs: object) -> Agent:
        observed.update(kwargs)
        return _fake_codex_agent()

    monkeypatch.setattr(task_module, "codex_cli", fake_codex_cli)

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


def test_bounded_generation_captures_success_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_calls = 0
    scanned: list[str] = []

    async def export() -> ExportedSolution:
        nonlocal export_calls
        export_calls += 1
        return ExportedSolution(ORIGINAL_SOURCE.encode(), None)

    async def scan(source: str) -> tuple[SemgrepFinding, ...]:
        scanned.append(source)
        return ()

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)
    state = _setup_state()

    result = asyncio.run(
        bounded_generation(_fake_codex_agent())(
            state,
            cast(Generate, None),
        )
    )

    assert result is state
    assert export_calls == 1
    assert scanned == [ORIGINAL_SOURCE]
    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        ORIGINAL_SOURCE
    )
    assert load_semgrep_evidence(state).findings == ()


def test_bounded_generation_scans_a_parse_valid_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def export() -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    finding = SemgrepFinding(
        rule_id="python.security.rule",
        severity="ERROR",
        line=2,
        subcategory="vuln",
        confidence="HIGH",
    )
    scanned: list[str] = []

    async def scan(source: str) -> tuple[SemgrepFinding, ...]:
        scanned.append(source)
        return (finding,)

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)
    state = _setup_state()

    asyncio.run(
        bounded_generation(_fake_codex_agent())(
            state,
            cast(Generate, None),
        )
    )

    assert scanned == [SAFE_SOURCE]
    assert load_semgrep_evidence(state).findings == (finding,)


def test_bounded_generation_skips_an_invalid_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_source = "def generated(command):\n    return (\n"

    async def export() -> ExportedSolution:
        return ExportedSolution(invalid_source.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise AssertionError("invalid Python must not reach Semgrep")

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)
    state = _setup_state()

    asyncio.run(
        bounded_generation(_fake_codex_agent())(
            state,
            cast(Generate, None),
        )
    )

    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        invalid_source
    )
    assert load_semgrep_evidence(state).findings is None


def test_bounded_generation_keeps_source_when_scanning_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def export() -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise RuntimeError("Semgrep exited with status 2")

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)
    state = _setup_state()

    with pytest.raises(RuntimeError, match="status 2"):
        asyncio.run(
            bounded_generation(_fake_codex_agent())(
                state,
                cast(Generate, None),
            )
        )

    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        SAFE_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_direct_generation_limit_preserves_context_when_scanning_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied_limit = task_module.turn_limit(1)

    async def export() -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise RuntimeError("Semgrep exited with status 2")

    @agent
    def limited_agent() -> Agent:
        async def execute(state: AgentState) -> AgentState:
            del state
            raise LimitExceededError(
                "turn",
                value=2,
                limit=1,
                source=applied_limit,
            )

        return execute

    monkeypatch.setattr(task_module, "turn_limit", lambda _limit: applied_limit)
    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)
    state = _setup_state()

    with pytest.raises(RuntimeError, match="status 2") as error:
        asyncio.run(
            bounded_generation(limited_agent())(
                state,
                cast(Generate, None),
            )
        )

    assert isinstance(error.value.__context__, LimitExceededError)
    assert error.value.__context__.source is applied_limit
    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        SAFE_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


@pytest.mark.parametrize(
    ("budget", "budget_value", "expected"),
    [
        ("TURN_LIMIT", 2, "turn"),
        ("OUTPUT_TOKEN_LIMIT", 40, "token"),
        ("AGENT_TIME_LIMIT", 0.01, "time"),
    ],
)
def test_bounded_generation_captures_and_uses_inspect_native_limit(
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

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return ()

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)

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
    assert SemgrepEvidence.model_validate(
        sample.store[SEMGREP_EVIDENCE_KEY]
    ).findings == ()
    assert sample.limit is not None
    assert sample.limit.type == expected
    assert sample.limit.limit == budget_value

    assert sample.scores is not None
    score = sample.scores["static_safety_scorer"]
    assert score.answer == ORIGINAL_SOURCE
    score_values = cast(dict[str, object], score.value)
    assert score_values["valid_output"] == 1
    assert score_values["finding_count"] == 0

    assert log.results is not None
    results = {result.name: result for result in log.results.scores}
    assert results["valid_output"].scored_samples == 1
    assert results["finding_count"].scored_samples == 1


def test_bridge_limit_event_survives_fail_closed_scanner_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    monkeypatch.setattr(task_module, "TURN_LIMIT", 2)

    async def export() -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise RuntimeError("Semgrep exited with status 2")

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(task_module, "scan_source", scan)

    @agent
    def overruns_turn_limit() -> Agent:
        async def execute(state: AgentState) -> AgentState:
            for _ in range(8):
                state.output = await get_model().generate(state.messages)
                state.messages.append(state.output.message)
            return state

        return execute

    case_id = "CWE-078_scan_failure_1.py"
    task = Task(
        name="static_safety_limit_then_scanner_failure",
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
        solver=bounded_generation(overruns_turn_limit()),
        scorer=static_safety_scorer(),
        time_limit=SAMPLE_TIME_LIMIT,
        score_on_error=False,
    )

    log = inspect_eval(
        task,
        model="mockllm/model",
        display="none",
        log_dir=str(tmp_path),
        log_realtime=False,
        ctl_server=False,
    )[0]

    assert log.status == "error"
    assert log.samples is not None and len(log.samples) == 1
    sample = log.samples[0]
    assert sample.error is not None
    assert "Semgrep exited with status 2" in sample.error.message
    # The scanner error deliberately becomes the terminal sample error. Inspect
    # therefore omits its derived ``sample.limit``, but the original framework
    # event still records why generation stopped.
    assert sample.limit is None
    assert any(
        isinstance(event, SampleLimitEvent)
        and event.type == "turn"
        and event.limit == 2
        for event in sample.events
    )
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == (
        SAFE_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in sample.store
    assert not sample.scores


def test_bounded_generation_captures_then_propagates_unrelated_cancellation(
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

    state = _setup_state()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(
            bounded_generation(cancelled_agent())(
                state,
                cast(Generate, None),
            )
        )

    assert exported is True
    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        ORIGINAL_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_bounded_generation_captures_then_propagates_unrelated_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def export() -> ExportedSolution:
        return ExportedSolution(ORIGINAL_SOURCE.encode(), None)

    monkeypatch.setattr(artifact_module, "export_solution", export)

    @agent
    def failing_agent() -> Agent:
        async def execute(state: AgentState) -> AgentState:
            del state
            raise ValueError("agent failed")

        return execute

    state = _setup_state()
    with pytest.raises(ValueError, match="agent failed"):
        asyncio.run(
            bounded_generation(failing_agent())(
                state,
                cast(Generate, None),
            )
        )

    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        ORIGINAL_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


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
        "semgrep": task_module.semgrep_provenance(),
        "dataset": {
            "repository": SECURITYEVAL_REPO_ID,
            "filename": SECURITYEVAL_FILENAME,
            "revision": SECURITYEVAL_REVISION,
            "sha256": SECURITYEVAL_SOURCE_SHA256,
            "selection": "all-cases",
            "selected_cases": 1,
        },
    }
