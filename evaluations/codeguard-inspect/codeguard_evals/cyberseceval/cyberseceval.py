"""CyberSecEval instruct-v2 adapter using our grader and Meta's pinned ICD rules."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Final

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset
from inspect_ai.viewer import TaskSamplesView, ViewerConfig

from codeguard_evals.cyberseceval.dataset import (
    DATASET_FILE,
    DATASET_SHA256,
    REPOSITORY,
    REVISION,
    load_cases,
    make_samples,
    select_cases,
)
from codeguard_evals.harness import (
    TURN_LIMIT,
    StaticBenchmark,
    build_static_task,
    validate_agent_turn_limit,
)
from codeguard_evals.protocol import CONDITION_LABELS, Condition, condition_has_skill
from codeguard_evals.sandbox_protocol import LANGUAGE_FILENAMES
from codeguard_evals.skill_catalog import CODEGUARD_VARIANT
from codeguard_evals.viewer import ScoreView, static_safety_viewer

SANDBOX_CONFIG: Final = Path(__file__).parents[2] / "sandbox/generate.yaml"

_SCORE_VIEW_SPECS: Final = (
    ScoreView("output_present", "Output present"),
    ScoreView("output_nonempty", "Nonempty output"),
    ScoreView("scan_complete", "Scan complete"),
    ScoreView("icd_flagged_output", "ICD flagged"),
    ScoreView("icd_finding_count", "Findings"),
    ScoreView("loc", "LOC"),
    ScoreView("skill_loaded", "Skill loaded", skill_only=True),
)


@task
def cyberseceval_static_safety_baseline(
    languages: str | list[str] = "",
    agent_turn_limit: int = TURN_LIMIT,
) -> Task:
    """Measure the Codex static-safety baseline without a security skill."""
    return build_task("baseline", languages=languages, agent_turn_limit=agent_turn_limit)


@task
def cyberseceval_static_safety_secure_prompt(
    languages: str | list[str] = "",
    agent_turn_limit: int = TURN_LIMIT,
) -> Task:
    """Measure a plain security-focused prompt without a skill."""
    return build_task("secure_prompt", languages=languages, agent_turn_limit=agent_turn_limit)


@task
def cyberseceval_static_safety_codeguard(
    languages: str | list[str] = "",
    agent_turn_limit: int = TURN_LIMIT,
) -> Task:
    """Measure the pinned CodeGuard catalog entry under automatic skill routing."""
    return build_task("skill", languages=languages, agent_turn_limit=agent_turn_limit, skill_variant=CODEGUARD_VARIANT)


def build_task(
    condition: Condition,
    *,
    languages: str | list[str],
    agent_turn_limit: int,
    skill_variant: str | None = None,
) -> Task:
    agent_turn_limit = validate_agent_turn_limit(agent_turn_limit)
    uses_skill = condition_has_skill(condition)
    cases = select_cases(load_cases(), languages)
    name = f"cyberseceval_static_safety_{condition}"
    benchmark = StaticBenchmark(
        name=name,
        display_name=f"CyberSecEval — {CONDITION_LABELS[condition]}",
        dataset=MemoryDataset(make_samples(cases, condition), name=name),
        filename=lambda state: LANGUAGE_FILENAMES[state.metadata["language"]],
        sandbox_config=SANDBOX_CONFIG,
        tags=("cyberseceval", "instruct-v2", "icd", "static-safety", condition),
        viewer=_viewer(include_skill=uses_skill),
        metadata={
            "benchmark": "CyberSecEval",
            "suite": "instruct-v2-static-safety",
            "dataset": {
                "repository": REPOSITORY,
                "revision": REVISION,
                "filename": DATASET_FILE,
                "sha256": DATASET_SHA256,
                "selected_cases": len(cases),
                "language_counts": dict(Counter(case.language for case in cases)),
            },
        },
    )
    return build_static_task(benchmark, condition, agent_turn_limit=agent_turn_limit,
                             skill_variant=skill_variant)


def _viewer(*, include_skill: bool) -> ViewerConfig:
    return static_safety_viewer(
        "cyberseceval_scorer",
        _SCORE_VIEW_SPECS,
        include_skill=include_skill,
        sample_view=TaskSamplesView(
            name="CyberSecEval static safety",
            score_labels={score.name: score.label for score in _SCORE_VIEW_SPECS},
        ),
    )
