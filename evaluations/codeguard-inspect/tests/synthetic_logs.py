"""Synthetic Inspect logs shared by the results exporter and report tests.

Every private field carries CANARY, so a test can prove that it never reaches
an export.
"""

from __future__ import annotations

import csv
import math
import socket
import subprocess
from pathlib import Path

import pytest

from inspect_ai.log import (
    write_eval_log,
    EvalConfig,
    EvalDataset,
    EvalLog,
    EvalMetric,
    EvalResults,
    EvalRevision,
    EvalSample,
    EvalScore,
    EvalSpec,
    EvalStats,
)
from inspect_ai.model import ChatMessageUser, GenerateConfig, ModelUsage
from inspect_ai.scorer import Score

from codeguard_evals.export_results import METRICS, SCORER

CANARY = "DO_NOT_EXPORT_SYNTHETIC_PRIVATE_VALUE"
START = "2026-01-01T12:00:00+00:00"
END = "2026-01-01T12:00:30+00:00"
SKILL_SHA256 = "a" * 64


def values(findings: int = 0, changed: int = 1, valid: int = 1) -> dict[str, float]:
    result: dict[str, float] = dict.fromkeys(METRICS, 0)
    result.update(
        changed_output=changed,
        valid_output=valid,
        loc=12,
        skill_loaded=1,
        finding_count=findings,
        semgrep_flagged_output=int(findings > 0),
        severity_warning=findings,
        subcategory_audit=findings,
        confidence_low=findings,
    )
    return result


def sample(
    index: int, scores=None, *, condition: str = "codeguard", **kwargs
) -> EvalSample:
    score = Score(
        value=scores if scores is not None else values(),
        answer=CANARY,
        explanation=CANARY,
        metadata={"private": CANARY},
    )
    usage = ModelUsage(
        input_tokens=70,
        output_tokens=10,
        input_tokens_cache_read=20,
        reasoning_tokens=5,
        total_tokens=100,
        total_cost=0.1,
    )
    return EvalSample(
        id=f"static_safety/{condition}/CWE-020_author_{index}.py",
        epoch=1,
        input=CANARY,
        target=CANARY,
        scores={SCORER: score},
        metadata={"private": CANARY},
        messages=[ChatMessageUser(content=CANARY)],
        store={"source": CANARY},
        attachments={"private": CANARY},
        started_at=START,
        completed_at=END,
        total_time=30,
        model_usage={CANARY: usage},
        **kwargs,
    )


def log_for(
    samples: list[EvalSample],
    *,
    condition: str = "codeguard",
    version: str = "1.5.0",
    skill_sha256: str = SKILL_SHA256,
    task_id: str = "synthetic-task",
) -> EvalLog:
    usage = {}
    for item in samples:
        for model, amount in (item.model_usage or {}).items():
            usage[model] = usage.get(model, ModelUsage()) + amount
    aggregate_scores = []
    for name in METRICS:
        present = [
            item.scores[SCORER].value[name]
            for item in samples
            if item.scores
            and name in item.scores[SCORER].value
            and not math.isnan(item.scores[SCORER].value[name])
        ]
        total = sum(present) if present else math.nan
        mean = total / len(present) if present else math.nan
        metrics = {
            "total": EvalMetric(name="total", value=total),
            "mean": EvalMetric(name="mean", value=mean),
            "stderr": EvalMetric(name="stderr", value=0.125),
        }
        aggregate_scores.append(EvalScore(name=name, scorer=SCORER, metrics=metrics))
    skill = (
        {"version": version, "content_sha256": skill_sha256}
        if condition == "codeguard"
        else None
    )
    metadata = {
        "benchmark": "SecurityEval",
        "condition": condition,
        "private": CANARY,
        "codeguard": skill,
        "codex_version": "0.146.0",
        "inspect_swe_version": "0.2.67",
        "python_version": "3.13.14",
        "dataset": {"revision": "b" * 40, "sha256": "c" * 64},
        "semgrep": {
            "version": "1.173.0",
            "rules_tree_sha256": "d" * 64,
            "image_digest": "sha256:" + "f" * 64,
        },
        "generation_limits": {
            "turns": 16,
            "agent_seconds": 600,
            "output_tokens": 32768,
        },
    }
    return EvalLog(
        status="success",
        eval=EvalSpec(
            created=START,
            task="synthetic",
            task_id=task_id,
            model=CANARY,
            dataset=EvalDataset(samples=len(samples), location=CANARY),
            config=EvalConfig(
                epochs=1,
                sample_shuffle=42,
                time_limit=1200,
                max_samples=2,
                max_sandboxes=2,
            ),
            model_generate_config=GenerateConfig(
                reasoning_effort="medium", max_connections=2, max_retries=0
            ),
            model_args={"private": CANARY},
            model_base_url=f"https://{CANARY}.invalid",
            task_file=f"/Users/{CANARY}/task.py",
            tags=[CANARY],
            revision=EvalRevision(
                type="git", origin=CANARY, commit="abcdef1234", dirty=False
            ),
            packages={"inspect_ai": "0.3.255", CANARY: CANARY},
            metadata=metadata,
        ),
        results=EvalResults(
            total_samples=len(samples),
            completed_samples=len(samples),
            scores=aggregate_scores,
        ),
        samples=samples,
        stats=EvalStats(
            started_at=START,
            completed_at=END,
            model_usage=usage,
        ),
    )


@pytest.fixture
def save(tmp_path: Path):
    def write(log: EvalLog | None = None, name: str = "run.eval") -> Path:
        path = tmp_path / name
        write_eval_log(log if log is not None else log_for([sample(1)]), path)
        return path

    return write


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("the exporter must stay offline")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)


def rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as source:
        return list(csv.DictReader(source))


def repeated_log(condition="codeguard", epochs=2):
    cases = []
    for epoch in range(1, epochs + 1):
        for case_id in (1, 2):
            item = sample(case_id, values(findings=epoch), condition=condition)
            item.epoch = epoch
            item.model_usage = {
                CANARY: ModelUsage(total_tokens=100 * epoch, total_cost=0.25 * epoch)
            }
            cases.append(item)
    log = log_for(cases, condition=condition, task_id=condition)
    log.eval.config.epochs = epochs
    # Whole-run totals must not be copied into each epoch.
    log.stats.model_usage = {CANARY: ModelUsage(total_tokens=9999, total_cost=99)}
    return log
