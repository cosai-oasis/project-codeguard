"""SecurityEval dataset and grading adapter for the shared static harness."""

from __future__ import annotations

from pathlib import Path
from typing import Final

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox
from inspect_ai.viewer import (
    TaskSamplesColumn,
    TaskSamplesSort,
    TaskSamplesView,
    ViewerConfig,
)

from codeguard_evals.harness import (
    TURN_LIMIT,
    StaticBenchmark,
    build_static_task,
    validate_agent_turn_limit,
)
from codeguard_evals.protocol import CONDITION_LABELS, Condition, condition_has_skill
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import (
    SANDBOX_NAME,
    SANDBOX_USER,
    SANDBOX_WORKDIR,
    SOURCE_FILENAME,
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
    CHANGED_OUTPUT_METRIC,
    CONFIDENCE_HIGH_METRIC,
    CONFIDENCE_LOW_METRIC,
    CONFIDENCE_MEDIUM_METRIC,
    FINDING_COUNT_METRIC,
    LOC_METRIC,
    SCORER_NAME,
    SEMGREP_FLAGGED_OUTPUT_METRIC,
    SEVERITY_ERROR_METRIC,
    SEVERITY_INFO_METRIC,
    SEVERITY_WARNING_METRIC,
    SKILL_LOADED_METRIC,
    STATIC_SAFETY_SUITE,
    SUBCATEGORY_AUDIT_METRIC,
    SUBCATEGORY_SECURE_DEFAULT_METRIC,
    SUBCATEGORY_VULN_METRIC,
    VALID_OUTPUT_METRIC,
    securityeval_task_name,
)
from codeguard_evals.securityeval.python_output import validated_original_bytes
from codeguard_evals.skill_catalog import CODEGUARD_VARIANT
from codeguard_evals.viewer import ScoreView, static_safety_viewer

SANDBOX_CONFIG: Final = Path(__file__).parents[2] / "sandbox/generate.yaml"

SOLUTION_WRITE_COMMAND: Final = (
    "/usr/bin/dd",
    f"of={SOURCE_FILENAME}",
    "status=none",
    "conv=excl",
)
_SCORE_VIEW_SPECS: Final = (
    ScoreView(CHANGED_OUTPUT_METRIC, "Changed", palette="good-high"),
    ScoreView(VALID_OUTPUT_METRIC, "Valid Python", palette="good-high"),
    ScoreView(SEMGREP_FLAGGED_OUTPUT_METRIC, "Semgrep flagged"),
    ScoreView(FINDING_COUNT_METRIC, "Findings"),
    ScoreView(SEVERITY_ERROR_METRIC, "Error"),
    ScoreView(SEVERITY_WARNING_METRIC, "Warning"),
    ScoreView(SEVERITY_INFO_METRIC, "Info"),
    ScoreView(LOC_METRIC, "LOC"),
    ScoreView(SUBCATEGORY_VULN_METRIC, "Vuln", visible=False),
    ScoreView(SUBCATEGORY_SECURE_DEFAULT_METRIC, "Secure default", visible=False),
    ScoreView(SUBCATEGORY_AUDIT_METRIC, "Audit", visible=False),
    ScoreView(CONFIDENCE_HIGH_METRIC, "High confidence", visible=False),
    ScoreView(CONFIDENCE_MEDIUM_METRIC, "Medium confidence", visible=False),
    ScoreView(CONFIDENCE_LOW_METRIC, "Low confidence", visible=False),
    ScoreView(SKILL_LOADED_METRIC, "Skill loaded", palette="good-high", skill_only=True),
)


@task
def securityeval_static_safety_baseline(
    agent_turn_limit: int = TURN_LIMIT,
) -> Task:
    """Measure the Codex static-safety baseline without a security skill."""
    return build_task("baseline", agent_turn_limit=agent_turn_limit)


@task
def securityeval_static_safety_secure_prompt(
    agent_turn_limit: int = TURN_LIMIT,
) -> Task:
    """Measure a plain security-focused prompt without a skill."""
    return build_task("secure_prompt", agent_turn_limit=agent_turn_limit)


@task
def securityeval_static_safety_codeguard(
    agent_turn_limit: int = TURN_LIMIT,
) -> Task:
    """Measure the pinned CodeGuard catalog entry under automatic skill routing."""
    return build_task("skill", agent_turn_limit=agent_turn_limit, skill_variant=CODEGUARD_VARIANT)


def build_task(
    condition: Condition, *, agent_turn_limit: int, skill_variant: str | None = None,
) -> Task:
    agent_turn_limit = validate_agent_turn_limit(agent_turn_limit)
    uses_skill = condition_has_skill(condition)
    name = securityeval_task_name(condition)
    cases = load_securityeval_cases()
    benchmark = StaticBenchmark(
        name=name,
        display_name=f"SecurityEval — {CONDITION_LABELS[condition]}",
        dataset=MemoryDataset(
            securityeval_samples(cases, condition=condition), name=name
        ),
        filename=lambda state: SOURCE_FILENAME,
        sandbox_config=SANDBOX_CONFIG,
        setup=(prepare_solution_file(),),
        tags=("securityeval", "static-safety", condition.replace("_", "-")),
        viewer=_viewer(include_skill=uses_skill),
        metadata={
            "benchmark": "SecurityEval",
            "suite": STATIC_SAFETY_SUITE,
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
    return build_static_task(benchmark, condition, agent_turn_limit=agent_turn_limit,
                             skill_variant=skill_variant)


def _viewer(*, include_skill: bool) -> ViewerConfig:
    return static_safety_viewer(
        SCORER_NAME,
        _SCORE_VIEW_SPECS,
        include_skill=include_skill,
        sample_view=TaskSamplesView(
            name="SecurityEval static safety",
            columns=[TaskSamplesColumn(id="duration")],
            sort=[
                TaskSamplesSort.score(SCORER_NAME, SEMGREP_FLAGGED_OUTPUT_METRIC, dir="desc"),
                TaskSamplesSort.score(SCORER_NAME, FINDING_COUNT_METRIC, dir="desc"),
                TaskSamplesSort.score(SCORER_NAME, CHANGED_OUTPUT_METRIC, dir="asc"),
                TaskSamplesSort(column="sampleId"),
                TaskSamplesSort(column="epoch"),
            ],
            multiline=False,
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
