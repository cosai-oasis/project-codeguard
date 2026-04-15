"""
Benchmark orchestrator.

Manages Docker container lifecycle for benchmark runs.
Uses asyncio + docker SDK with a semaphore for parallelism control.
"""

from __future__ import annotations

import asyncio
import io
import shutil
import tarfile
import time
from pathlib import Path

import docker
from docker.errors import ImageNotFound

from benchmarks.config import (
    BenchmarkConfig,
    Credentials,
    DOCKER_DIR,
    SKILLS_DIR,
)
from benchmarks.models import ContainerResult, RunMode, Scenario, TokenUsage


DOCKER_IMAGE_TAG = "codeguard-bench:latest"


async def build_image() -> None:
    """Build the benchmark Docker image.

    Prepares a temporary build context that includes:
    - Dockerfile and entrypoint.sh from benchmarks/docker/
    - skills/secure-coding/ (SKILL.md + rules)
    """
    build_context = DOCKER_DIR / "_build_ctx"
    build_context.mkdir(exist_ok=True)

    try:
        # Copy Dockerfile and entrypoint
        shutil.copy2(DOCKER_DIR / "Dockerfile", build_context / "Dockerfile")
        shutil.copy2(DOCKER_DIR / "entrypoint.sh", build_context / "entrypoint.sh")

        # Copy skills into context
        skills_dst = build_context / "skills" / "secure-coding"
        if skills_dst.exists():
            shutil.rmtree(skills_dst)
        shutil.copytree(SKILLS_DIR, skills_dst)

        client = docker.from_env()
        await asyncio.to_thread(
            client.images.build,
            path=str(build_context),
            tag=DOCKER_IMAGE_TAG,
            rm=True,
        )
    finally:
        shutil.rmtree(build_context, ignore_errors=True)


def _extract_file_from_archive(archive_stream, filename: str) -> str:
    """Extract a single file's contents from a Docker archive tar stream."""
    buf = io.BytesIO()
    for chunk in archive_stream:
        buf.write(chunk)
    buf.seek(0)

    try:
        with tarfile.open(fileobj=buf) as tar:
            for member in tar.getmembers():
                if member.name.endswith(filename):
                    f = tar.extractfile(member)
                    if f:
                        return f.read().decode("utf-8", errors="replace")
    except Exception:
        pass
    return ""


async def run_container(
    client: docker.DockerClient,
    scenario: Scenario,
    run_mode: RunMode,
    run_index: int,
    config: BenchmarkConfig,
    creds: Credentials,
    debug: bool = False,
) -> ContainerResult:
    """Run a single benchmark container and collect results."""
    container_name = f"bench-{scenario.id}-{run_mode.value}-{run_index}"
    timeout = scenario.timeout_seconds or config.timeout_seconds

    environment = {
        "REPO_URL": scenario.repo_url,
        "REPO_REF": scenario.repo_ref,
        "RUN_MODE": run_mode.value,
        "AGENT_PROMPT": scenario.prompt,
        "AGENT_MODEL": config.agent_model,
        "OPENAI_API_KEY": creds.openai_api_key,
        "OPENAI_BASE_URL": creds.openai_base_url,
        "OPENROUTER_API_KEY": creds.openai_api_key,
        "BENCH_DEBUG": "1" if debug else "0",
    }

    container = None
    start = time.monotonic()
    timed_out = False

    try:
        container = await asyncio.to_thread(
            client.containers.run,
            DOCKER_IMAGE_TAG,
            detach=True,
            name=container_name,
            environment=environment,
            mem_limit="4g",
            auto_remove=False,
        )

        try:
            result = await asyncio.to_thread(
                container.wait, timeout=timeout,
            )
            exit_code = result.get("StatusCode", -1)
        except Exception:
            timed_out = True
            exit_code = -1
            await asyncio.to_thread(container.kill)

        duration = time.monotonic() - start

        # Extract diff, log, usage, and trace
        import json as _json

        diff = ""
        agent_log = ""
        agent_usage = TokenUsage()
        agent_trace: list = []

        files_to_extract = [
            ("diff.patch", "diff"),
            ("agent.log", "agent_log"),
            ("usage.json", "_usage_raw"),
            ("trace.json", "_trace_raw"),
        ]
        for filename, attr in files_to_extract:
            try:
                stream, _ = await asyncio.to_thread(
                    container.get_archive, f"/workspace/output/{filename}",
                )
                content = _extract_file_from_archive(stream, filename)
                if attr == "_usage_raw":
                    usage_data = _json.loads(content)
                    agent_usage = TokenUsage(**usage_data)
                elif attr == "_trace_raw":
                    agent_trace = _json.loads(content)
                elif attr == "diff":
                    diff = content
                else:
                    agent_log = content
            except Exception:
                pass

        return ContainerResult(
            scenario_id=scenario.id,
            run_mode=run_mode,
            run_index=run_index,
            diff=diff,
            agent_log=agent_log,
            agent_trace=agent_trace,
            exit_code=exit_code,
            timed_out=timed_out,
            duration_seconds=round(duration, 1),
            agent_usage=agent_usage,
            container_id=container.id[:12] if container else "",
        )

    except Exception as exc:
        duration = time.monotonic() - start
        return ContainerResult(
            scenario_id=scenario.id,
            run_mode=run_mode,
            run_index=run_index,
            timed_out=timed_out,
            duration_seconds=round(duration, 1),
            error=str(exc),
        )
    finally:
        if container:
            try:
                await asyncio.to_thread(container.remove, force=True)
            except Exception:
                pass


async def _run_with_semaphore(
    semaphore: asyncio.Semaphore,
    client: docker.DockerClient,
    scenario: Scenario,
    run_mode: RunMode,
    run_index: int,
    config: BenchmarkConfig,
    creds: Credentials,
    debug: bool = False,
) -> ContainerResult:
    async with semaphore:
        return await run_container(
            client, scenario, run_mode, run_index, config, creds, debug,
        )


async def run_scenario(
    client: docker.DockerClient,
    scenario: Scenario,
    config: BenchmarkConfig,
    creds: Credentials,
    semaphore: asyncio.Semaphore,
    debug: bool = False,
) -> list[ContainerResult]:
    """Run all executions for one scenario (both modes, all run indices)."""
    tasks = []
    for run_index in range(config.runs_per_scenario):
        for mode in RunMode:
            tasks.append(
                _run_with_semaphore(
                    semaphore, client, scenario, mode, run_index, config, creds, debug,
                )
            )
    return list(await asyncio.gather(*tasks))


async def run_all(
    scenarios: list[Scenario],
    config: BenchmarkConfig,
    creds: Credentials,
    debug: bool = False,
) -> list[ContainerResult]:
    """Run all scenarios with parallelism control.

    Returns a flat list of all ContainerResult objects.
    """
    # Verify image exists
    client = docker.from_env()
    try:
        client.images.get(DOCKER_IMAGE_TAG)
    except ImageNotFound:
        print(f"Image {DOCKER_IMAGE_TAG} not found. Building...")
        await build_image()

    semaphore = asyncio.Semaphore(config.max_parallel)
    all_tasks = [
        run_scenario(client, s, config, creds, semaphore, debug) for s in scenarios
    ]
    nested = await asyncio.gather(*all_tasks)
    return [r for sub in nested for r in sub]
