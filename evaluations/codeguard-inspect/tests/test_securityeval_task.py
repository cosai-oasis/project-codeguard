from __future__ import annotations

import asyncio
import hashlib
import importlib
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest


from inspect_ai import Task
from inspect_ai.agent import Agent, AgentState, agent
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.log import read_eval_log
from inspect_ai.model import ModelOutput, ModelUsage, get_model
from inspect_ai.solver import Generate, TaskState, generate
from inspect_ai.util import LimitExceededError
from inspect_ai.viewer import TaskSamplesColumn

import codeguard_evals.graders.semgrep as semgrep_grading
from codeguard_evals.securityeval import scorers
import codeguard_evals.harness as harness
import codeguard_evals.output_artifact as artifact_module
from codeguard_evals.skill_files import skill_content_sha256
from codeguard_evals.graders.semgrep import (
    SEMGREP_EVIDENCE_KEY,
)
from codeguard_evals.harness import (
    AGENT_TIME_LIMIT,
    CODEX_VERSION,
    MAX_GENERATION_TOKENS,
    SAMPLE_TIME_LIMIT,
    SKILL_DIRECTORY_MODE,
    SKILL_FILE_MODE,
    TURN_LIMIT,
)
from codeguard_evals.metrics import SKILL_SNAPSHOT_KEY
from codeguard_evals.output_artifact import SAVED_OUTPUT_KEY, SavedOutput
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
from codeguard_evals.securityeval.dataset import (
    SECURITYEVAL_FILENAME,
    SECURITYEVAL_REPO_ID,
    SECURITYEVAL_REVISION,
    SECURITYEVAL_SOURCE_SHA256,
    SecurityEvalCase,
)
from codeguard_evals.securityeval.protocol import (
    AGENT_ENVIRONMENT_INSTRUCTIONS,
    EVALUATION_VERSION,
    Condition,
    condition_has_skill,
    securityeval_prompt,
)
from codeguard_evals.graders.semgrep_artifacts import SemgrepFinding
from codeguard_evals.skill_catalog import CODEGUARD_VARIANT, SkillProvenance
from tests.conftest import (
    CODEGUARD_SKILL_DIR,
    ORIGINAL_SOURCE,
    SAFE_SOURCE,
    FakeSandbox,
    eval_mock_task,
    task_state,
)

task_module = importlib.import_module("codeguard_evals.securityeval.securityeval")


@agent
def _fake_codex_agent() -> Agent:
    async def execute(state: AgentState) -> AgentState:
        return state

    return execute


def _codeguard_snapshot(guidance_dir: str = "rules") -> dict[str, bytes]:
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
            b"Read the relevant guidance file.\n"
        ),
        f"{guidance_dir}/codeguard-0-python.md": b"# Python\nAvoid shell=True.\n",
    }


def _codeguard_variant(variant: str) -> tuple[dict[str, bytes], SkillProvenance]:
    assert variant == CODEGUARD_VARIANT
    snapshot = _codeguard_snapshot()
    return snapshot, SkillProvenance(
        id=variant, label="CodeGuard 1.4.0", name="codeguard",
        content_sha256=skill_content_sha256(snapshot), version="1.4.0",
    )


def bounded_generation(agent, **kwargs):
    return harness.bounded_generation(
        agent,
        capture_output=harness.capture_source(lambda state: "solution.py"),
        **kwargs,
    )


def _stub_loaders(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        scorers, "load_default_locked_rules_directory", lambda: Path("verified")
    )
    monkeypatch.setattr(harness, "load_skill_variant", _codeguard_variant)
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
        ("securityeval_static_safety_codeguard", "skill"),
    ],
)
@pytest.mark.parametrize("agent_turn_limit", [None, 7], ids=["default", "custom"])
def test_tasks_use_one_static_safety_path_and_explicit_codex_home(
    factory: str,
    condition: Condition,
    agent_turn_limit: int | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_loaders(monkeypatch)
    observed: dict[str, object] = {}

    def fake_codex_cli(**kwargs: object) -> Agent:
        observed.update(kwargs)
        return _fake_codex_agent()

    monkeypatch.setattr(harness, "codex_cli", fake_codex_cli)

    arguments = (
        {} if agent_turn_limit is None else {"agent_turn_limit": agent_turn_limit}
    )
    task = getattr(task_module, factory)(**arguments)

    uses_skill = condition_has_skill(condition)
    # Task names are eval-set resume identities, so pin them literally.
    assert task.name == {
        "baseline": "securityeval_static_safety_baseline",
        "secure_prompt": "securityeval_static_safety_secure_prompt",
        "skill": "securityeval_static_safety_skill_codeguard-1.5",
    }[condition]
    assert (
        task.display_name
        == {
            "baseline": "SecurityEval — Baseline",
            "secure_prompt": "SecurityEval — Secure prompt",
            "skill": "SecurityEval — Skill — CodeGuard 1.4.0",
        }[condition]
    )
    assert task.tags == [
        "securityeval",
        "static-safety",
        condition.replace("_", "-"),
    ]
    assert task.setup is not None
    assert len(task.setup) == (2 if uses_skill else 1)
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
    assert task.scorer is None
    assert task.viewer is not None
    assert task.viewer.trust_content is False
    assert task.viewer.sample_score_view is not None
    assert task.viewer.sample_score_view.default == "grid"
    sample_view = task.viewer.task_samples_view
    assert sample_view is not None and not isinstance(sample_view, list)
    assert sample_view.multiline is False
    assert sample_view.compact_scores is True
    assert sample_view.color_scales_enabled is True
    assert sample_view.sort is not None
    assert [sort.column for sort in sample_view.sort] == [
        TaskSamplesColumn.score("static_safety_scorer", "semgrep_flagged_output").id,
        TaskSamplesColumn.score("static_safety_scorer", "finding_count").id,
        TaskSamplesColumn.score("static_safety_scorer", "changed_output").id,
        "sampleId",
        "epoch",
    ]
    assert [sort.dir for sort in sample_view.sort] == [
        "desc",
        "desc",
        "asc",
        "asc",
        "asc",
    ]
    assert sample_view.columns is not None
    visible_scores = [
        "changed_output",
        "valid_output",
        "semgrep_flagged_output",
        "finding_count",
        "severity_error",
        "severity_warning",
        "severity_info",
        "loc",
    ]
    hidden_scores = [
        "subcategory_vuln",
        "subcategory_secure_default",
        "subcategory_audit",
        "confidence_high",
        "confidence_medium",
        "confidence_low",
    ]
    skill_column = TaskSamplesColumn.score("static_safety_scorer", "skill_loaded").id
    expected_score_ids = [
        TaskSamplesColumn.score("static_safety_scorer", name).id
        for name in (*visible_scores, *hidden_scores)
    ]
    if uses_skill:
        expected_score_ids.append(skill_column)
    assert [column.id for column in sample_view.columns] == [
        "sampleStatus",
        "sampleId",
        "epoch",
        "limit",
        *expected_score_ids,
        "duration",
        "tokens",
    ]
    columns = {column.id: column.visible for column in sample_view.columns}
    assert all(
        columns[TaskSamplesColumn.score("static_safety_scorer", name).id]
        for name in visible_scores
    )
    assert all(
        not columns[TaskSamplesColumn.score("static_safety_scorer", name).id]
        for name in hidden_scores
    )
    assert (skill_column in columns) is (uses_skill)
    assert sample_view.score_labels is not None
    assert sample_view.score_labels["semgrep_flagged_output"] == "Semgrep flagged"
    assert sample_view.score_labels["confidence_medium"] == "Medium confidence"
    assert sample_view.score_color_scales is not None
    finding_scale = sample_view.score_color_scales["finding_count"]
    assert not isinstance(finding_scale, str)
    assert finding_scale.palette == "neutral"
    assert finding_scale.min == 0
    assert finding_scale.max is None
    changed_scale = sample_view.score_color_scales["changed_output"]
    assert not isinstance(changed_scale, str)
    assert changed_scale.palette == "good-high"
    assert changed_scale.min == 0
    assert changed_scale.max == 1
    assert len(task.dataset) == 1
    sample = task.dataset[0]
    assert sample.files is None
    assert sample.input == securityeval_prompt(condition)

    assert observed["version"] == CODEX_VERSION
    assert observed["system_prompt"] == AGENT_ENVIRONMENT_INSTRUCTIONS
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
    assert task.metadata["skill_available"] is uses_skill
    assert ("skill" in task.metadata) == uses_skill
    assert task.metadata["python_version"] == harness.PYTHON_VERSION
    assert task.metadata["generation_limits"] == {
        "output_tokens": harness.OUTPUT_TOKEN_LIMIT,
        "turns": TURN_LIMIT if agent_turn_limit is None else agent_turn_limit,
        "agent_seconds": AGENT_TIME_LIMIT,
    }


@pytest.mark.parametrize("agent_turn_limit", [True, 0, -1, 1.5, "16"])
def test_tasks_reject_invalid_agent_turn_limits(
    agent_turn_limit: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_dataset_load() -> list[SecurityEvalCase]:
        pytest.fail("Invalid limits must fail before loading the dataset")

    monkeypatch.setattr(task_module, "load_securityeval_cases", unexpected_dataset_load)
    with pytest.raises(ValueError, match="positive integer"):
        task_module.securityeval_static_safety_baseline(
            agent_turn_limit=agent_turn_limit,  # type: ignore[arg-type]
        )


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


@pytest.mark.parametrize("guidance_dir", ["rules", "references"])
def test_codeguard_setup_installs_the_exact_repository_bytes(
    guidance_dir: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    success = SimpleNamespace(success=True)
    snapshot = _codeguard_snapshot(guidance_dir)
    environment = FakeSandbox(success, success, success, success, success)
    monkeypatch.setattr(harness, "sandbox", lambda _name: environment)
    state = _setup_state()

    result = asyncio.run(
        harness.install_skill(snapshot)(state, cast(Generate, None))
    )

    assert result is state
    assert state.store.get(SKILL_SNAPSHOT_KEY) == {
        "schema_version": 2,
        "skill_name": "codeguard",
        "content_sha256": skill_content_sha256(snapshot),
        "document_sha256": hashlib.sha256(snapshot["SKILL.md"]).hexdigest(),
        "document": snapshot["SKILL.md"].decode(),
    }
    assert environment.calls[0] == (
        ["/usr/bin/mkdir", "-p", CODEGUARD_SKILL_DIR, f"{CODEGUARD_SKILL_DIR}/{guidance_dir}"],
        {
            "input": None,
            "cwd": None,
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
            SKILL_FILE_MODE,
            *(f"{CODEGUARD_SKILL_DIR}/{path}" for path in sorted(snapshot)),
        ],
        {
            "input": None,
            "cwd": None,
            "user": SANDBOX_ROOT_USER,
            "timeout": 10,
            "timeout_retry": False,
        },
    )
    assert environment.calls[-1] == (
        [
            "/usr/bin/chmod",
            SKILL_DIRECTORY_MODE,
            CODEX_SKILLS_DIR,
            CODEGUARD_SKILL_DIR,
            f"{CODEGUARD_SKILL_DIR}/{guidance_dir}",
        ],
        {
            "input": None,
            "cwd": None,
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
    monkeypatch.setattr(harness, "sandbox", lambda _name: environment)
    state = _setup_state()

    with pytest.raises(BenchmarkInfrastructureError, match="Could not install"):
        asyncio.run(
            harness.install_skill(_codeguard_snapshot())(
                state,
                cast(Generate, None),
            )
        )
    assert SKILL_SNAPSHOT_KEY not in state.store


def test_bounded_generation_captures_success_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export_calls = 0
    scanned: list[str] = []

    async def export(_filename: str = "solution.py") -> ExportedSolution:
        nonlocal export_calls
        export_calls += 1
        return ExportedSolution(ORIGINAL_SOURCE.encode(), None)

    async def scan(source: str) -> tuple[SemgrepFinding, ...]:
        scanned.append(source)
        return ()

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)
    state = _setup_state()

    result = asyncio.run(
        bounded_generation(_fake_codex_agent())(
            state,
            cast(Generate, None),
        )
    )

    assert result is state
    assert export_calls == 1
    assert scanned == []
    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        ORIGINAL_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_bounded_generation_captures_parse_valid_output_without_scanning(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def export(_filename: str = "solution.py") -> ExportedSolution:
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
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)
    state = _setup_state()

    asyncio.run(
        bounded_generation(_fake_codex_agent())(
            state,
            cast(Generate, None),
        )
    )

    assert scanned == []
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_bounded_generation_skips_an_invalid_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_source = "def generated(command):\n    return (\n"

    async def export(_filename: str = "solution.py") -> ExportedSolution:
        return ExportedSolution(invalid_source.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        raise AssertionError("invalid Python must not reach Semgrep")

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)
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
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_generation_does_not_depend_on_scanner_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def export(_filename: str = "solution.py") -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return ["parse_error"]

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)
    state = _setup_state()

    asyncio.run(
        bounded_generation(_fake_codex_agent())(state, cast(Generate, None))
    )

    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        SAFE_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_direct_generation_limit_is_preserved_without_scanner_interference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied_limit = harness.turn_limit(1)

    async def export(_filename: str = "solution.py") -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return ["parse_error"]

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

    monkeypatch.setattr(harness, "turn_limit", lambda _limit: applied_limit)
    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)
    state = _setup_state()

    with pytest.raises(LimitExceededError) as error:
        asyncio.run(
            bounded_generation(limited_agent())(
                state,
                cast(Generate, None),
            )
        )

    assert error.value.source is applied_limit
    assert SavedOutput.model_validate(state.store.get(SAVED_OUTPUT_KEY)).source == (
        SAFE_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in state.store


def test_mock_task_preserves_custom_responses_and_usage(tmp_path):
    response = ModelOutput.from_content("mockllm/model", "Custom fixture response")
    response.usage = ModelUsage(input_tokens=2, output_tokens=7, total_tokens=9)
    log = eval_mock_task(
        Task(dataset=[Sample(input="Fixture request")], solver=generate()),
        tmp_path,
        model_args={"custom_outputs": [response]},
    )
    assert log.status == "success", log.error
    assert log.samples[0].output.completion == "Custom fixture response"
    assert log.stats.model_usage["mockllm/model"] == response.usage


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
    offline_batch,
    budget: str,
    budget_value: int | float,
    expected: str,
) -> None:
    """A truncated sample must count as a weak generation, not disappear.

    Applied as task limits these would abort the chain before capture, so the
    scorer would find no evidence and the sample would leave every denominator.
    """
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))
    if budget != "TURN_LIMIT":
        monkeypatch.setattr(harness, budget, budget_value)

    async def export(_filename: str = "solution.py") -> ExportedSolution:
        # Truncated before the agent changed anything the setup wrote.
        return ExportedSolution(ORIGINAL_SOURCE.encode(), None)

    async def scan(sources):
        return [() for _ in sources]

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)

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
        solver=bounded_generation(
            overruns_its_budget(),
            agent_turn_limit=(
                cast(int, budget_value) if budget == "TURN_LIMIT" else TURN_LIMIT
            ),
        ),
        version=EVALUATION_VERSION,
        metadata={"benchmark": "SecurityEval", "phase": "generation", "condition": "baseline"},
        time_limit=SAMPLE_TIME_LIMIT,
    )

    log = eval_mock_task(task, tmp_path, model_args={})

    assert log.status == "success", log.error
    assert log.samples is not None and len(log.samples) == 1
    sample = log.samples[0]
    assert sample.error is None
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == (
        ORIGINAL_SOURCE
    )
    assert SEMGREP_EVIDENCE_KEY not in sample.store
    assert not sample.scores
    assert sample.limit is not None
    assert sample.limit.type == expected
    assert sample.limit.limit == budget_value

    log = offline_batch(log, tmp_path / "scored")
    sample = log.samples[0]
    assert sample.scores is not None
    score = sample.scores["static_safety_scorer"]
    assert score.answer == ORIGINAL_SOURCE
    score_values = cast(dict[str, object], score.value)
    assert score_values["valid_output"] == 1
    assert score_values["changed_output"] == 0
    assert score_values["finding_count"] == 0

    assert log.results is not None
    results = {result.name: result for result in log.results.scores}
    assert results["valid_output"].scored_samples == 1
    assert results["changed_output"].metrics["total"].value == 0
    assert results["finding_count"].scored_samples == 1


def test_bridge_limit_event_survives_fail_closed_scanner_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    offline_batch,
) -> None:
    monkeypatch.setenv("INSPECT_TRACE_FILE", str(tmp_path / "trace.log"))

    async def export(_filename: str = "solution.py") -> ExportedSolution:
        return ExportedSolution(SAFE_SOURCE.encode(), None)

    async def scan(_source: str) -> tuple[SemgrepFinding, ...]:
        return ["parse_error"]

    monkeypatch.setattr(artifact_module, "export_solution", export)
    monkeypatch.setattr(semgrep_grading, "scan_sources", scan)

    @agent
    def overruns_turn_limit() -> Agent:
        async def execute(state: AgentState) -> AgentState:
            for _ in range(8):
                state.output = await get_model().generate(state.messages)
                state.messages.append(state.output.message)
            return state

        return execute

    case_id = "CWE-078_scan-failure_1.py"
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
        solver=bounded_generation(overruns_turn_limit(), agent_turn_limit=2),
        version=EVALUATION_VERSION,
        metadata={"benchmark": "SecurityEval", "phase": "generation", "condition": "baseline"},
        time_limit=SAMPLE_TIME_LIMIT,
        score_on_error=False,
    )

    log = eval_mock_task(task, tmp_path)

    assert log.status == "success"
    sample = log.samples[0]
    assert sample.error is None and sample.limit.type == "turn"
    original = Path(log.location).read_bytes()
    with pytest.raises(BenchmarkInfrastructureError, match="source scans could not be completed"):
        offline_batch(log, tmp_path / "scored")
    scored = read_eval_log(tmp_path / "scored" / Path(log.location).name)
    assert scored.status == "success"
    assert scored.samples[0].limit == sample.limit
    assert scored.samples[0].error and not scored.samples[0].scores
    assert Path(log.location).read_bytes() == original
    assert SavedOutput.model_validate(sample.store[SAVED_OUTPUT_KEY]).source == SAFE_SOURCE
    assert SEMGREP_EVIDENCE_KEY not in sample.store
    assert not sample.scores


def test_bounded_generation_captures_then_propagates_unrelated_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exported = False

    async def export(_filename: str = "solution.py") -> ExportedSolution:
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
    async def export(_filename: str = "solution.py") -> ExportedSolution:
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
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: _fake_codex_agent())

    task = task_module.securityeval_static_safety_codeguard()

    assert task.metadata == {
        "benchmark": "SecurityEval",
        "suite": "static_safety",
        "phase": "generation",
        "condition": "skill",
        "agent": "codex-cli",
        "codex_version": CODEX_VERSION,
        "inspect_swe_version": harness.INSPECT_SWE_VERSION,
        "python_version": harness.PYTHON_VERSION,
        "generation_limits": {
            "output_tokens": harness.OUTPUT_TOKEN_LIMIT,
            "turns": TURN_LIMIT,
            "agent_seconds": AGENT_TIME_LIMIT,
        },
        "skill_available": True,
        "skill": _codeguard_variant(CODEGUARD_VARIANT)[1].model_dump(),
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


def test_new_attempts_select_codeguard_from_the_catalog(monkeypatch):
    _stub_loaders(monkeypatch)
    monkeypatch.setattr(harness, "codex_cli", lambda **kwargs: _fake_codex_agent())
    with pytest.raises(ValueError, match="catalog entry"):
        task_module.build_task("codeguard", agent_turn_limit=TURN_LIMIT)


def test_standalone_skill_installation_preserves_bytes_and_protects_directory(catalog_skill, monkeypatch):
    from codeguard_evals.skill_catalog import load_skill_variant
    from codeguard_evals.metrics import skill_was_read
    _, expected = catalog_skill("selected")
    snapshot, identity = load_skill_variant("selected")
    success = SimpleNamespace(success=True)
    environment = FakeSandbox(success, success, success, success)
    monkeypatch.setattr(harness, "sandbox", lambda _: environment)
    state = _setup_state()
    asyncio.run(harness.install_skill(snapshot)(state, cast(Generate, None)))
    directory = f"{CODEX_SKILLS_DIR}/{identity.name}"
    assert environment.calls[0][0] == ["/usr/bin/mkdir", "-p", directory]
    command, arguments = environment.calls[1]
    assert command == ["/usr/bin/dd", "of=SKILL.md", "status=none", "conv=excl"]
    assert arguments["input"] == expected["SKILL.md"] and arguments["cwd"] == directory
    assert all(args["user"] == SANDBOX_ROOT_USER for _, args in environment.calls)
    assert environment.calls[-1][0] == ["/usr/bin/chmod", "0555", CODEX_SKILLS_DIR, directory]
    assert state.store.get(SKILL_SNAPSHOT_KEY)["skill_name"] == identity.name
    assert skill_was_read(state) == 0
