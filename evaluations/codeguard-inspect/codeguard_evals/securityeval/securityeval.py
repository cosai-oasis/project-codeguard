"""Docker-isolated SecurityEval tasks backed by the native Codex CLI."""

from __future__ import annotations

import platform
from collections.abc import Mapping
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Final, Literal, NamedTuple

import anyio
from inspect_ai import Task, task
from inspect_ai.agent import Agent, as_solver
from inspect_ai.dataset import MemoryDataset
from inspect_ai.event import SampleLimitEvent
from inspect_ai.log import transcript
from inspect_ai.model import GenerateConfig
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import (
    Limit,
    LimitExceededError,
    sandbox,
    time_limit,
    token_limit,
    turn_limit,
)
from inspect_ai.viewer import (
    SampleScoreView,
    ScoreColorScale,
    TaskSamplesColumn,
    TaskSamplesSort,
    TaskSamplesView,
    ViewerConfig,
)
from inspect_swe import codex_cli

from codeguard_evals.codeguard import (
    codeguard_content_sha256,
    codeguard_version,
    load_codeguard,
)
from codeguard_evals.output_artifact import (
    capture_generated_output,
    load_saved_output,
    save_semgrep_evidence,
)
from codeguard_evals.python_output import (
    validate_python_solution,
    validated_original_bytes,
)
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import (
    CODEX_HOME_DIR,
    CODEX_SKILLS_DIR,
    SANDBOX_NAME,
    SANDBOX_ROOT_USER,
    SANDBOX_USER,
    SANDBOX_WORKDIR,
    SOURCE_FILENAME,
)
from codeguard_evals.scorers import (
    CHANGED_OUTPUT_METRIC,
    CONFIDENCE_HIGH_METRIC,
    CONFIDENCE_LOW_METRIC,
    CONFIDENCE_MEDIUM_METRIC,
    FINDING_COUNT_METRIC,
    LOC_METRIC,
    SEMGREP_FLAGGED_OUTPUT_METRIC,
    SEVERITY_ERROR_METRIC,
    SEVERITY_INFO_METRIC,
    SEVERITY_WARNING_METRIC,
    SKILL_LOADED_METRIC,
    SUBCATEGORY_AUDIT_METRIC,
    SUBCATEGORY_SECURE_DEFAULT_METRIC,
    SUBCATEGORY_VULN_METRIC,
    VALID_OUTPUT_METRIC,
    static_safety_scorer,
)
from codeguard_evals.securityeval.dataset import (
    SECURITYEVAL_FILENAME,
    SECURITYEVAL_REPO_ID,
    SECURITYEVAL_REVISION,
    SECURITYEVAL_SOURCE_SHA256,
    load_securityeval_cases,
    securityeval_samples,
)
from codeguard_evals.securityeval.protocol import (
    CODEGUARD_SKILL_DIR,
    EVALUATION_VERSION,
    STATIC_SAFETY_SUITE,
    Condition,
    condition_skill_name,
    securityeval_task_name,
)
from codeguard_evals.semgrep_artifacts import semgrep_provenance
from codeguard_evals.semgrep_runner import scan_source

MAX_GENERATION_TOKENS: Final = 4_096
OUTPUT_TOKEN_LIMIT: Final = 32_768
TURN_LIMIT: Final = 8
AGENT_TIME_LIMIT: Final = 300
CODEX_VERSION: Final = "0.146.0"
# Backstop for a wedged sandbox only. Generation has its own scoped budget, and
# the bounded setup, export, and scan steps fit well inside the remainder.
SAMPLE_TIME_LIMIT: Final = 900
CODEGUARD_RULES_DIR: Final = f"{CODEGUARD_SKILL_DIR}/rules"
CODEGUARD_FILE_MODE: Final = "0444"
CODEGUARD_DIRECTORY_MODE: Final = "0555"
SANDBOX_CONFIG: Final = Path(__file__).parents[2] / "sandbox" / "compose.yaml"
INSPECT_SWE_VERSION: Final = distribution_version("inspect-swe")
PYTHON_VERSION: Final = platform.python_version()
SOLUTION_WRITE_COMMAND: Final = (
    "/usr/bin/dd",
    f"of={SOURCE_FILENAME}",
    "status=none",
    "conv=excl",
)
_SCORER_NAME: Final = "static_safety_scorer"
_CONDITION_DISPLAY_NAMES: Final[Mapping[Condition, str]] = {
    "baseline": "SecurityEval — Baseline",
    "secure_prompt": "SecurityEval — Secure prompt",
    "codeguard": "SecurityEval — CodeGuard",
}


class _ScoreViewSpec(NamedTuple):
    name: str
    label: str
    visible: bool = True
    palette: Literal["good-high", "neutral"] = "neutral"
    skill_only: bool = False


_SCORE_VIEW_SPECS: Final = (
    _ScoreViewSpec(CHANGED_OUTPUT_METRIC, "Changed", palette="good-high"),
    _ScoreViewSpec(VALID_OUTPUT_METRIC, "Valid Python", palette="good-high"),
    _ScoreViewSpec(SEMGREP_FLAGGED_OUTPUT_METRIC, "Semgrep flagged"),
    _ScoreViewSpec(FINDING_COUNT_METRIC, "Findings"),
    _ScoreViewSpec(SEVERITY_ERROR_METRIC, "Error"),
    _ScoreViewSpec(SEVERITY_WARNING_METRIC, "Warning"),
    _ScoreViewSpec(SEVERITY_INFO_METRIC, "Info"),
    _ScoreViewSpec(LOC_METRIC, "LOC"),
    _ScoreViewSpec(SUBCATEGORY_VULN_METRIC, "Vuln", visible=False),
    _ScoreViewSpec(
        SUBCATEGORY_SECURE_DEFAULT_METRIC,
        "Secure default",
        visible=False,
    ),
    _ScoreViewSpec(SUBCATEGORY_AUDIT_METRIC, "Audit", visible=False),
    _ScoreViewSpec(CONFIDENCE_HIGH_METRIC, "High confidence", visible=False),
    _ScoreViewSpec(
        CONFIDENCE_MEDIUM_METRIC,
        "Medium confidence",
        visible=False,
    ),
    _ScoreViewSpec(CONFIDENCE_LOW_METRIC, "Low confidence", visible=False),
    _ScoreViewSpec(
        SKILL_LOADED_METRIC,
        "Skill loaded",
        palette="good-high",
        skill_only=True,
    ),
)


def _securityeval_viewer(*, include_skill: bool) -> ViewerConfig:
    specs = [
        spec for spec in _SCORE_VIEW_SPECS if include_skill or not spec.skill_only
    ]
    score_columns = [
        TaskSamplesColumn.score(
            _SCORER_NAME,
            spec.name,
            visible=spec.visible,
        )
        for spec in specs
    ]

    binary_scale = ScoreColorScale(palette="good-high", min=0, max=1)
    neutral_scale = ScoreColorScale(palette="neutral", min=0)
    color_scales: dict[str, str | ScoreColorScale] = {
        spec.name: binary_scale if spec.palette == "good-high" else neutral_scale
        for spec in specs
    }

    return ViewerConfig(
        sample_score_view=SampleScoreView(default="grid"),
        task_samples_view=TaskSamplesView(
            name="SecurityEval static safety",
            columns=[
                TaskSamplesColumn(id="sampleStatus"),
                TaskSamplesColumn(id="sampleId"),
                TaskSamplesColumn(id="epoch"),
                TaskSamplesColumn(id="limit"),
                *score_columns,
                TaskSamplesColumn(id="duration"),
                TaskSamplesColumn(id="tokens"),
            ],
            sort=[
                TaskSamplesSort.score(
                    _SCORER_NAME,
                    SEMGREP_FLAGGED_OUTPUT_METRIC,
                    dir="desc",
                ),
                TaskSamplesSort.score(
                    _SCORER_NAME,
                    FINDING_COUNT_METRIC,
                    dir="desc",
                ),
                TaskSamplesSort.score(
                    _SCORER_NAME,
                    CHANGED_OUTPUT_METRIC,
                    dir="asc",
                ),
                TaskSamplesSort(column="sampleId"),
                TaskSamplesSort(column="epoch"),
            ],
            multiline=False,
            compact_scores=True,
            score_labels={spec.name: spec.label for spec in specs},
            score_color_scales=color_scales,
            color_scales_enabled=True,
        ),
    )


@solver
def prepare_solution_file() -> Solver:
    """Create the verified benchmark scaffold as the agent user."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
        environment = sandbox(SANDBOX_NAME)
        result = await environment.exec(
            list(SOLUTION_WRITE_COMMAND),
            input=validated_original_bytes(state.target.text),
            cwd=SANDBOX_WORKDIR,
            user=SANDBOX_USER,
            timeout=10,
            timeout_retry=False,
        )
        if not result.success:
            raise BenchmarkInfrastructureError(
                "Could not prepare the benchmark solution for the agent"
            )
        return state

    return solve


@solver
def install_codeguard_skill(snapshot: Mapping[str, bytes]) -> Solver:
    """Install the validated repository skill without parsing or rewriting it."""
    frozen = dict(snapshot)
    codeguard_version(frozen)
    files = tuple(sorted(frozen.items()))

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
        environment = sandbox(SANDBOX_NAME)
        directory_result = await environment.exec(
            ["/usr/bin/mkdir", "-p", CODEGUARD_RULES_DIR],
            user=SANDBOX_ROOT_USER,
            timeout=10,
            timeout_retry=False,
        )
        if not directory_result.success:
            raise BenchmarkInfrastructureError(
                "Could not install the repository CodeGuard skill for the agent"
            )
        for path, content in files:
            write_result = await environment.exec(
                [
                    "/usr/bin/dd",
                    f"of={path}",
                    "status=none",
                    "conv=excl",
                ],
                input=content,
                cwd=CODEGUARD_SKILL_DIR,
                user=SANDBOX_ROOT_USER,
                timeout=10,
                timeout_retry=False,
            )
            if not write_result.success:
                raise BenchmarkInfrastructureError(
                    "Could not install the repository CodeGuard skill for the agent"
                )
        file_result = await environment.exec(
            [
                "/usr/bin/chmod",
                CODEGUARD_FILE_MODE,
                *(f"{CODEGUARD_SKILL_DIR}/{path}" for path, _content in files),
            ],
            user=SANDBOX_ROOT_USER,
            timeout=10,
            timeout_retry=False,
        )
        if not file_result.success:
            raise BenchmarkInfrastructureError(
                "Could not install the repository CodeGuard skill for the agent"
            )
        directory_permissions_result = await environment.exec(
            [
                "/usr/bin/chmod",
                CODEGUARD_DIRECTORY_MODE,
                CODEX_SKILLS_DIR,
                CODEGUARD_SKILL_DIR,
                CODEGUARD_RULES_DIR,
            ],
            user=SANDBOX_ROOT_USER,
            timeout=10,
            timeout_retry=False,
        )
        if not directory_permissions_result.success:
            raise BenchmarkInfrastructureError(
                "Could not install the repository CodeGuard skill for the agent"
            )
        return state

    return solve


@solver
def bounded_generation(agent: Agent) -> Solver:
    """Budget generation and always capture its saved artifact.

    Applying these as task limits would abort the whole solver chain, so a
    truncated sample would reach scoring with nothing captured and be dropped
    from every metric instead of counting as the weak generation it is.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        limits: dict[str, Limit] = {
            "token": token_limit(OUTPUT_TOKEN_LIMIT, type="output"),
            "turn": turn_limit(TURN_LIMIT),
            "time": time_limit(AGENT_TIME_LIMIT),
        }
        collect_evidence = False
        agent_solver = as_solver(agent, limits=list(limits.values()))
        try:
            state = await agent_solver(state, generate)
            collect_evidence = True
            return state
        except LimitExceededError as error:
            collect_evidence = _is_applied_generation_limit(limits, error)
            raise
        except anyio.get_cancelled_exc_class():
            collect_evidence = _has_applied_generation_limit_event(limits)
            raise
        finally:
            with anyio.CancelScope(shield=True):
                await capture_generated_output(state)
                if collect_evidence:
                    await _capture_semgrep_evidence(state)

    return solve


async def _capture_semgrep_evidence(state: TaskState) -> None:
    saved = load_saved_output(state)
    findings = None
    if saved.source is not None:
        try:
            validation = validate_python_solution(saved.source)
        except ValueError:
            raise BenchmarkInfrastructureError(
                "Saved output could not be prepared for scanning"
            ) from None
        if validation.valid:
            findings = await scan_source(saved.source)
    save_semgrep_evidence(state, findings)


def _is_applied_generation_limit(
    limits: dict[str, Limit],
    error: LimitExceededError,
) -> bool:
    limit = limits.get(error.type)
    return limit is not None and error.source is limit


def _has_applied_generation_limit_event(limits: dict[str, Limit]) -> bool:
    for event in reversed(transcript().history.recent_events(20)):
        if isinstance(event, SampleLimitEvent):
            limit = limits.get(event.type)
            return limit is not None and event.limit == limit.limit
    return False


@task
def securityeval_static_safety_baseline() -> Task:
    """Measure the Codex static-safety baseline without a security skill."""
    return _securityeval_task("baseline")


@task
def securityeval_static_safety_secure_prompt() -> Task:
    """Measure a plain security-focused prompt without a skill."""
    return _securityeval_task("secure_prompt")


@task
def securityeval_static_safety_codeguard() -> Task:
    """Measure repository CodeGuard under automatic skill routing."""
    return _securityeval_task("codeguard")


def _securityeval_task(condition: Condition) -> Task:
    skill_name = condition_skill_name(condition)
    task_name = securityeval_task_name(condition)
    cases = load_securityeval_cases()
    samples = securityeval_samples(cases, condition=condition)
    setup_solvers = [prepare_solution_file()]
    codeguard_metadata: dict[str, str] | None = None
    if skill_name is not None:
        snapshot = load_codeguard()
        version = codeguard_version(snapshot)
        setup_solvers.append(install_codeguard_skill(snapshot))
        codeguard_metadata = {
            "version": version,
            "content_sha256": codeguard_content_sha256(snapshot),
        }
    agent_solver = bounded_generation(
        codex_cli(
            version=CODEX_VERSION,
            skills=None,
            cwd=SANDBOX_WORKDIR,
            home_dir=CODEX_HOME_DIR,
            user=SANDBOX_USER,
            sandbox=SANDBOX_NAME,
            web_search="disabled",
            goals=False,
            auto_review=False,
            attempts=1,
            retry_refusals=0,
        )
    )

    return Task(
        dataset=MemoryDataset(samples, name=task_name),
        setup=setup_solvers,
        solver=agent_solver,
        scorer=static_safety_scorer(),
        sandbox=("docker", str(SANDBOX_CONFIG)),
        checkpoint=False,
        config=GenerateConfig(
            max_tokens=MAX_GENERATION_TOKENS,
            max_connections=1,
        ),
        time_limit=SAMPLE_TIME_LIMIT,
        fail_on_error=True,
        continue_on_fail=True,
        score_on_error=False,
        display_name=_CONDITION_DISPLAY_NAMES[condition],
        name=task_name,
        version=EVALUATION_VERSION,
        tags=["securityeval", "static-safety", condition.replace("_", "-")],
        viewer=_securityeval_viewer(include_skill=skill_name is not None),
        metadata={
            "benchmark": "SecurityEval",
            "suite": STATIC_SAFETY_SUITE,
            "condition": condition,
            "agent": "codex-cli",
            "codex_version": CODEX_VERSION,
            "inspect_swe_version": INSPECT_SWE_VERSION,
            "python_version": PYTHON_VERSION,
            "skill_available": skill_name is not None,
            "codeguard": codeguard_metadata,
            "sandbox": "docker-compose",
            "semgrep": semgrep_provenance(),
            "dataset": {
                "repository": SECURITYEVAL_REPO_ID,
                "filename": SECURITYEVAL_FILENAME,
                "revision": SECURITYEVAL_REVISION,
                "sha256": SECURITYEVAL_SOURCE_SHA256,
                "selection": "all-cases",
                "selected_cases": len(cases),
            },
        },
    )
