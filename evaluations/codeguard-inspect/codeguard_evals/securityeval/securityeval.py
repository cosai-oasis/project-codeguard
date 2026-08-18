"""Docker-isolated SecurityEval tasks backed by the native Codex CLI."""

from __future__ import annotations

import platform
from collections.abc import Mapping
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Final

import anyio
from inspect_ai import Task, task
from inspect_ai.agent import Agent, as_solver
from inspect_ai.dataset import MemoryDataset
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
from inspect_swe import codex_cli

from codeguard_evals.codeguard import (
    codeguard_content_sha256,
    codeguard_version,
    load_codeguard,
)
from codeguard_evals.output_artifact import (
    GENERATION_LIMIT_KEY,
    GenerationLimit,
    capture_generated_output,
)
from codeguard_evals.python_output import validated_original_bytes
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
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

    capture = capture_generated_output()

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        limits: dict[GenerationLimit, Limit] = {
            "token": token_limit(OUTPUT_TOKEN_LIMIT, type="output"),
            "turn": turn_limit(TURN_LIMIT),
            "time": time_limit(AGENT_TIME_LIMIT),
        }
        agent_solver = as_solver(agent, limits=list(limits.values()))
        try:
            state = await agent_solver(state, generate)
        except (LimitExceededError, anyio.get_cancelled_exc_class()):
            generation_limit = _crossed_generation_limit(limits)
            if generation_limit is None:
                raise

            # The sandbox bridge promotes a model limit to sample cancellation.
            # Shield only bounded finalization, then preserve Inspect's exception.
            with anyio.CancelScope(shield=True):
                state.store.set(GENERATION_LIMIT_KEY, generation_limit)
                await capture(state, generate)
            raise
        return await capture(state, generate)

    return solve


def _crossed_generation_limit(
    limits: Mapping[GenerationLimit, Limit],
) -> GenerationLimit | None:
    for name, limit in limits.items():
        ceiling = limit.limit
        if ceiling is None:
            continue
        if name == "time":
            crossed = limit.usage >= ceiling
        else:
            crossed = limit.usage > ceiling
        if crossed:
            return name
    return None


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
        name=task_name,
        version=EVALUATION_VERSION,
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
