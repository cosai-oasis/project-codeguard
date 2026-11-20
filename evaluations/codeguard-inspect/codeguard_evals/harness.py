"""Shared lifecycle for bounded, single-file static code-generation benchmarks."""

from __future__ import annotations

import platform
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Final

import anyio
from inspect_ai import Task
from inspect_ai.agent import Agent, as_solver
from inspect_ai.dataset import Dataset
from inspect_ai.model import GenerateConfig
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import (
    sandbox,
    sample_limits,
    time_limit,
    token_limit,
    turn_limit,
)
from inspect_ai.viewer import ViewerConfig
from inspect_swe import codex_cli

from codeguard_evals.skill_files import skill_front_matter
from codeguard_evals.metrics import save_skill_snapshot
from codeguard_evals.skill_catalog import load_skill_variant
from codeguard_evals.output_artifact import capture_generated_output
from codeguard_evals.protocol import (
    AGENT_ENVIRONMENT_INSTRUCTIONS,
    EVALUATION_VERSION,
    Condition,
    condition_has_skill,
)
from codeguard_evals.sandbox_client import BenchmarkInfrastructureError
from codeguard_evals.sandbox_protocol import (
    CODEX_HOME_DIR,
    CODEX_SKILLS_DIR,
    SANDBOX_NAME,
    SANDBOX_ROOT_USER,
    SANDBOX_USER,
    SANDBOX_WORKDIR,
)

MAX_GENERATION_TOKENS: Final = 4_096
OUTPUT_TOKEN_LIMIT: Final = 32_768
TURN_LIMIT: Final = 16
AGENT_TIME_LIMIT: Final = 600
CODEX_VERSION: Final = "0.146.0"
# Backstop for a wedged sandbox, with headroom for bounded setup and source capture.
SAMPLE_TIME_LIMIT: Final = 1_200
SKILL_FILE_MODE: Final = "0444"
SKILL_DIRECTORY_MODE: Final = "0555"
INSPECT_SWE_VERSION: Final = distribution_version("inspect-swe")
PYTHON_VERSION: Final = platform.python_version()


@solver
def install_skill(snapshot: Mapping[str, bytes]) -> Solver:
    """Install a validated skill snapshot without rewriting its bytes."""
    frozen = dict(snapshot)
    name = skill_front_matter(frozen)["name"]
    skill_dir = f"{CODEX_SKILLS_DIR}/{name}"
    files = tuple(sorted(frozen.items()))
    guidance_dirs = tuple(
        sorted(
            {
                f"{skill_dir}/{path.split('/', 1)[0]}"
                for path in frozen
                if "/" in path
            }
        )
    )

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        del generate
        environment = sandbox(SANDBOX_NAME)

        async def run_install(
            command: list[str], *, content: bytes | None = None, cwd: str | None = None
        ) -> None:
            result = await environment.exec(
                command,
                input=content,
                cwd=cwd,
                user=SANDBOX_ROOT_USER,
                timeout=10,
                timeout_retry=False,
            )
            if not result.success:
                raise BenchmarkInfrastructureError(
                    "Could not install the selected skill for the agent"
                )

        await run_install(["/usr/bin/mkdir", "-p", skill_dir, *guidance_dirs])
        for path, content in files:
            await run_install(
                ["/usr/bin/dd", f"of={path}", "status=none", "conv=excl"],
                content=content,
                cwd=skill_dir,
            )
        await run_install(
            [
                "/usr/bin/chmod",
                SKILL_FILE_MODE,
                *(f"{skill_dir}/{path}" for path, _content in files),
            ],
        )
        await run_install(
            [
                "/usr/bin/chmod",
                SKILL_DIRECTORY_MODE,
                CODEX_SKILLS_DIR,
                skill_dir,
                *guidance_dirs,
            ],
        )
        save_skill_snapshot(state, frozen)
        return state

    return solve


def _fail_on_sample_backstop(step: Solver) -> Solver:
    """Make outer sample timeouts retryable without changing the solver's identity."""

    @wraps(step)
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        try:
            return await step(state, generate)
        except anyio.get_cancelled_exc_class():
            try:
                remaining = sample_limits().time.remaining
            except RuntimeError:
                # Direct solver calls may have no enclosing sample-limit context.
                remaining = None
            if remaining is not None and remaining <= 0:
                raise BenchmarkInfrastructureError(
                    "Execution exceeded the sample time backstop"
                ) from None
            raise

    return solve


@solver
def bounded_generation(
    agent: Agent,
    *,
    agent_turn_limit: int = TURN_LIMIT,
    capture_output: Callable[[TaskState], Awaitable[None]],
) -> Solver:
    """Budget generation and capture its source before every sandbox teardown."""
    effective_turn_limit = validate_agent_turn_limit(agent_turn_limit)

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        agent_solver = as_solver(
            agent,
            limits=[
                token_limit(OUTPUT_TOKEN_LIMIT, type="output"),
                turn_limit(effective_turn_limit),
                time_limit(AGENT_TIME_LIMIT),
            ],
        )
        try:
            state = await agent_solver(state, generate)
            return state
        finally:
            with anyio.CancelScope(shield=True):
                await capture_output(state)

    return _fail_on_sample_backstop(solve)


def validate_agent_turn_limit(value: int) -> int:
    if type(value) is not int or value < 1:
        raise ValueError("agent_turn_limit must be a positive integer")
    return value


@dataclass(frozen=True)
class StaticBenchmark:
    """Benchmark-owned generation inputs, presentation, and provenance."""

    name: str
    display_name: str
    dataset: Dataset
    filename: Callable[[TaskState], str]
    sandbox_config: Path
    metadata: Mapping[str, object]
    tags: tuple[str, ...]
    viewer: ViewerConfig | None = None
    setup: tuple[Solver, ...] = ()


def capture_source(
    filename: Callable[[TaskState], str],
) -> Callable[[TaskState], Awaitable[None]]:
    async def capture(state: TaskState) -> None:
        await capture_generated_output(state, filename(state))

    return capture


def build_static_task(
    benchmark: StaticBenchmark,
    condition: Condition,
    *,
    agent_turn_limit: int = TURN_LIMIT,
    skill_variant: str | None = None,
) -> Task:
    """One generation/capture lifecycle for explicitly supplied static adapters."""
    agent_turn_limit = validate_agent_turn_limit(agent_turn_limit)
    if condition == "codeguard":
        raise ValueError("New CodeGuard attempts select its catalog entry with the skill condition")
    if condition_has_skill(condition) != (skill_variant is not None):
        raise ValueError("Select a catalog variant only for the skill condition")
    setup = list(benchmark.setup)
    variant = None
    if skill_variant is not None:
        snapshot, variant = load_skill_variant(skill_variant)
        setup.append(install_skill(snapshot))
    agent = codex_cli(
        version=CODEX_VERSION,
        system_prompt=AGENT_ENVIRONMENT_INSTRUCTIONS,
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
    viewer = benchmark.viewer.model_copy() if benchmark.viewer else ViewerConfig()
    viewer.trust_content = False
    return Task(
        dataset=benchmark.dataset,
        setup=[_fail_on_sample_backstop(step) for step in setup],
        solver=bounded_generation(
            agent,
            agent_turn_limit=agent_turn_limit,
            capture_output=capture_source(benchmark.filename),
        ),
        scorer=None,
        sandbox=("docker", str(benchmark.sandbox_config)),
        checkpoint=False,
        config=GenerateConfig(max_tokens=MAX_GENERATION_TOKENS, max_connections=1),
        time_limit=SAMPLE_TIME_LIMIT,
        fail_on_error=True,
        continue_on_fail=True,
        score_on_error=False,
        name=f"{benchmark.name}_{variant.id}" if variant else benchmark.name,
        display_name=f"{benchmark.display_name} — {variant.label}" if variant else benchmark.display_name,
        version=EVALUATION_VERSION,
        tags=list(benchmark.tags),
        viewer=viewer,
        metadata={
            **benchmark.metadata,
            "phase": "generation",
            "condition": condition,
            "agent": "codex-cli",
            "codex_version": CODEX_VERSION,
            "inspect_swe_version": INSPECT_SWE_VERSION,
            "python_version": PYTHON_VERSION,
            "generation_limits": {
                "output_tokens": OUTPUT_TOKEN_LIMIT,
                "turns": agent_turn_limit,
                "agent_seconds": AGENT_TIME_LIMIT,
            },
            "skill_available": variant is not None,
            **({"skill": variant.model_dump()} if variant else {}),
            "sandbox": "docker-compose",
        },
    )
