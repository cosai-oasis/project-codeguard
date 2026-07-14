"""Tool-free Inspect SecurityEval task for CodeGuard."""

from __future__ import annotations

from typing import Final

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset
from inspect_ai.solver import generate

from codeguard_evals.bandit import bandit_cwe
from codeguard_evals.codeguard import load_codeguard
from codeguard_evals.securityeval.dataset import (
    BANDIT_CASE_IDS,
    SECURITYEVAL_FILENAME,
    SECURITYEVAL_REPO_ID,
    SECURITYEVAL_REVISION,
    SECURITYEVAL_SOURCE_SHA256,
    bandit_securityeval_cases,
    load_securityeval_cases,
    securityeval_samples,
)

MAX_GENERATION_TOKENS: Final = 4_096
TIME_LIMIT: Final = 300


@task
def securityeval() -> Task:
    """Evaluate one model over all SecurityEval conditions."""
    frozen_codeguard = load_codeguard()
    cases = bandit_securityeval_cases(load_securityeval_cases())
    return Task(
        dataset=MemoryDataset(
            securityeval_samples(cases, codeguard=frozen_codeguard),
            name="securityeval",
        ),
        solver=generate(tool_calls="none", max_tokens=MAX_GENERATION_TOKENS),
        scorer=bandit_cwe(),
        time_limit=TIME_LIMIT,
        fail_on_error=False,
        score_on_error=True,
        name="securityeval",
        version="2",
        metadata={
            "benchmark": "SecurityEval",
            "dataset": {
                "repository": SECURITYEVAL_REPO_ID,
                "filename": SECURITYEVAL_FILENAME,
                "revision": SECURITYEVAL_REVISION,
                "sha256": SECURITYEVAL_SOURCE_SHA256,
                "selection": "bandit-oracle-detectable",
                "selected_cases": len(BANDIT_CASE_IDS),
            },
        },
    )
