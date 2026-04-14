"""
CLI entry point for the CodeGuard benchmarking system.

Usage:
    python -m benchmarks.run                              # Run all scenarios
    python -m benchmarks.run --scenario jvl-feat-001      # Run one scenario
    python -m benchmarks.run --runs 5                     # 5 runs per scenario
    python -m benchmarks.run --parallel 30                # 30 containers at once
    python -m benchmarks.run --build                      # Rebuild Docker image
    python -m benchmarks.run --dry-run                    # Print plan only
    python -m benchmarks.run --judge-only                 # Re-judge from debug/
"""

from __future__ import annotations

import asyncio
import json
import sys
from argparse import ArgumentParser
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from benchmarks.config import (
    RESULTS_DIR,
    SCENARIOS_DIR,
    fetch_model_pricing,
    load_benchmark,
    load_credentials,
)
from benchmarks.judge import judge_all
from benchmarks.models import ContainerResult, RunMode, TokenUsage
from benchmarks.orchestrator import build_image, run_all
from benchmarks.report import build_summary, print_summary, save_results

console = Console()


def _load_results_from_debug(
    debug_dir: Path,
    scenarios: dict,
    config,
) -> list[ContainerResult]:
    """Rebuild ContainerResult list from saved debug artifacts."""
    results = []
    for scenario_id in scenarios:
        for mode in RunMode:
            for run_idx in range(config.runs_per_scenario):
                tag = f"{scenario_id}_{mode.value}_{run_idx}"
                diff = ""
                agent_log = ""
                agent_trace = []
                agent_usage = TokenUsage()

                diff_path = debug_dir / f"{tag}.diff"
                log_path = debug_dir / f"{tag}_agent.log"
                trace_path = debug_dir / f"{tag}_trace.json"
                usage_path = debug_dir / f"{tag}_usage.json"

                if diff_path.exists():
                    diff = diff_path.read_text(encoding="utf-8", errors="replace")
                if log_path.exists():
                    agent_log = log_path.read_text(encoding="utf-8", errors="replace")
                if trace_path.exists():
                    try:
                        agent_trace = json.loads(trace_path.read_text(encoding="utf-8"))
                    except Exception:
                        pass
                if usage_path.exists():
                    try:
                        agent_usage = TokenUsage(**json.loads(usage_path.read_text(encoding="utf-8")))
                    except Exception:
                        pass

                # Estimate usage from trace if usage.json missing
                if agent_usage.total_tokens == 0 and agent_trace:
                    inp = out = 0
                    for e in agent_trace:
                        if e.get("type") == "step_finish":
                            t = e.get("part", {}).get("tokens", {})
                            inp += t.get("input", 0)
                            out += t.get("output", 0)
                    agent_usage = TokenUsage(
                        prompt_tokens=inp,
                        completion_tokens=out,
                        total_tokens=inp + out,
                    )

                results.append(ContainerResult(
                    scenario_id=scenario_id,
                    run_mode=mode,
                    run_index=run_idx,
                    diff=diff,
                    agent_log=agent_log,
                    agent_trace=agent_trace,
                    agent_usage=agent_usage,
                ))
    return results


def main() -> None:
    parser = ArgumentParser(description="CodeGuard Benchmark Runner")
    parser.add_argument(
        "--scenarios-file", type=Path,
        default=SCENARIOS_DIR / "javavulnerablelab.yaml",
        help="Path to YAML file with config + scenarios",
    )
    parser.add_argument("--scenario", "-s", nargs="*", help="Run only these scenario IDs")
    parser.add_argument("--runs", "-n", type=int, help="Override runs_per_scenario")
    parser.add_argument("--parallel", "-p", type=int, help="Override max_parallel")
    parser.add_argument("--timeout", "-t", type=int, help="Override timeout_seconds")
    parser.add_argument("--model", help="Override agent_model")
    parser.add_argument("--judge-model", help="Override judge_model")
    parser.add_argument("--build", action="store_true", help="Rebuild Docker image before running")
    parser.add_argument("--dry-run", action="store_true", help="Print scenario plan without executing")
    parser.add_argument("--debug", action="store_true", help="Save full agent traces to results/debug/")
    parser.add_argument(
        "--judge-only", action="store_true",
        help="Skip containers — re-judge from saved debug/ artifacts",
    )
    args = parser.parse_args()

    overrides: dict = {}
    if args.runs is not None:
        overrides["runs_per_scenario"] = args.runs
    if args.parallel is not None:
        overrides["max_parallel"] = args.parallel
    if args.timeout is not None:
        overrides["timeout_seconds"] = args.timeout
    if args.model:
        overrides["agent_model"] = args.model
    if args.judge_model:
        overrides["judge_model"] = args.judge_model

    config, scenarios = load_benchmark(args.scenarios_file, overrides or None)

    if args.scenario:
        scenarios = {k: v for k, v in scenarios.items() if k in args.scenario}

    if not scenarios:
        console.print("[red]No scenarios matched. Exiting.[/red]")
        sys.exit(1)

    total_containers = len(scenarios) * 2 * config.runs_per_scenario

    console.rule("[bold]CodeGuard Benchmark[/bold]")
    console.print(f"  Agent: [cyan]{config.agent_model}[/cyan]  Judge: [cyan]{config.judge_model}[/cyan]")
    console.print(f"  Scenarios: [bold]{len(scenarios)}[/bold]  Runs: [bold]{config.runs_per_scenario}[/bold]  Containers: [bold]{total_containers}[/bold]  Parallel: [bold]{config.max_parallel}[/bold]")

    if args.dry_run:
        console.print()
        for s in scenarios.values():
            console.print(f"  [bold]{s.id}[/bold]: {s.name} [dim][{s.security_category.value}][/dim]")
            console.print(f"    Repo: {s.repo_url} @ {s.repo_ref}")
        sys.exit(0)

    creds = load_credentials()

    console.print("\n  Fetching model pricing...")
    agent_pricing = fetch_model_pricing(config.agent_model, creds)
    judge_pricing = fetch_model_pricing(config.judge_model, creds)
    if agent_pricing.prompt:
        console.print(f"  Agent: [green]${agent_pricing.prompt*1e6:.2f}[/green] / [green]${agent_pricing.completion*1e6:.2f}[/green] per 1M tokens")
    if judge_pricing.prompt:
        console.print(f"  Judge: [green]${judge_pricing.prompt*1e6:.2f}[/green] / [green]${judge_pricing.completion*1e6:.2f}[/green] per 1M tokens")

    async def _run() -> None:
        if args.build:
            with console.status("[bold]Building Docker image..."):
                await build_image()
            console.print("  [green]Image built.[/green]")

        # --- Container phase ---
        if args.judge_only:
            debug_dir = RESULTS_DIR / "debug"
            console.print(f"\n  [yellow]--judge-only[/yellow]: loading results from {debug_dir}")
            results = _load_results_from_debug(debug_dir, scenarios, config)
            loaded = sum(1 for r in results if r.diff or r.agent_trace)
            console.print(f"  Loaded [bold]{loaded}[/bold] / {len(results)} results with data")
        else:
            console.print()
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Containers", total=total_containers)

                # Monkey-patch orchestrator to update progress on each container finish
                from benchmarks import orchestrator as _orch
                _orig_run_container = _orch.run_container

                async def _tracked_run_container(*a, **kw):
                    result = await _orig_run_container(*a, **kw)
                    progress.advance(task)
                    return result

                _orch.run_container = _tracked_run_container
                try:
                    results = await run_all(
                        list(scenarios.values()), config, creds, debug=args.debug,
                    )
                finally:
                    _orch.run_container = _orig_run_container

            succeeded = sum(1 for r in results if not r.error)
            failed = sum(1 for r in results if r.error)
            timed_out = sum(1 for r in results if r.timed_out)
            console.print(f"  [green]{succeeded} ok[/green]  [red]{failed} errors[/red]  [yellow]{timed_out} timeouts[/yellow]")

            # Save debug artifacts
            if args.debug or args.judge_only is False:
                debug_dir = RESULTS_DIR / "debug"
                debug_dir.mkdir(parents=True, exist_ok=True)
                for r in results:
                    tag = f"{r.scenario_id}_{r.run_mode.value}_{r.run_index}"
                    if r.agent_trace:
                        (debug_dir / f"{tag}_trace.json").write_text(
                            json.dumps(r.agent_trace, indent=2), encoding="utf-8",
                        )
                    if r.agent_log:
                        (debug_dir / f"{tag}_agent.log").write_text(
                            r.agent_log, encoding="utf-8",
                        )
                    if r.diff:
                        (debug_dir / f"{tag}.diff").write_text(
                            r.diff, encoding="utf-8",
                        )

        # --- Judge phase ---
        console.print()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Judging", total=len(results))

            from benchmarks import judge as _judge_mod
            _orig_judge_result = _judge_mod.judge_result

            async def _tracked_judge(*a, **kw):
                result = await _orig_judge_result(*a, **kw)
                progress.advance(task)
                return result

            _judge_mod.judge_result = _tracked_judge
            try:
                verdicts = await judge_all(scenarios, results, config, creds)
            finally:
                _judge_mod.judge_result = _orig_judge_result

        summary = build_summary(
            scenarios, verdicts, config, results, agent_pricing, judge_pricing,
        )
        filepath = save_results(summary, RESULTS_DIR)
        console.print(f"\n  Results: [link file://{filepath}]{filepath}[/link]")
        print_summary(summary)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
