"""Shared Inspect presentation for static-code benchmarks."""

from collections.abc import Sequence
from typing import Literal, NamedTuple

from inspect_ai.viewer import (
    SampleScoreView,
    ScoreColorScale,
    TaskSamplesColumn,
    TaskSamplesView,
    ViewerConfig,
)


class ScoreView(NamedTuple):
    """One score column; use good-high only for binary checks."""

    name: str
    label: str
    visible: bool = True
    palette: Literal["good-high", "neutral"] = "neutral"
    skill_only: bool = False


def static_safety_viewer(
    scorer_name: str,
    scores: Sequence[ScoreView],
    *,
    include_skill: bool,
    sample_view: TaskSamplesView,
) -> ViewerConfig:
    """Add common columns and score styling to a benchmark's Inspect view."""
    scores = [score for score in scores if include_skill or not score.skill_only]
    view = sample_view.model_copy(update={
        "columns": [
            TaskSamplesColumn(id="sampleStatus"),
            TaskSamplesColumn(id="sampleId"),
            TaskSamplesColumn(id="epoch"),
            TaskSamplesColumn(id="limit"),
            *[
                TaskSamplesColumn.score(scorer_name, score.name, visible=score.visible)
                for score in scores
            ],
            *(sample_view.columns or []),
            TaskSamplesColumn(id="tokens"),
        ],
        "compact_scores": True,
        "score_labels": sample_view.score_labels or {score.name: score.label for score in scores},
        "score_color_scales": {
            score.name: ScoreColorScale(
                palette=score.palette,
                min=0,
                max=1 if score.palette == "good-high" else None,
            )
            for score in scores
        },
    })
    return ViewerConfig(
        sample_score_view=SampleScoreView(default="grid"),
        task_samples_view=view,
    )
