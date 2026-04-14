"""
CLI entry point for the CodeGuard benchmarking system.

Usage:
    python -m benchmarks.run                              # Run all scenarios
    python -m benchmarks.run --scenario jvl-sql-001       # Run one scenario
    python -m benchmarks.run --runs 5                     # 5 runs per scenario
    python -m benchmarks.run --parallel 5                 # Max 5 containers
    python -m benchmarks.run --build                      # Rebuild Docker image
    python -m benchmarks.run --dry-run                    # Print plan only
"""

from __future__ import annotations

import asyncio
import sys
from argparse import ArgumentParser
from pathlib import Path

from benchmarks.config import (
    RESULTS_DIR,
    SCENARIOS_DIR,
    load_benchmark,
    load_credentials,
)
from benchmarks.judge import judge_all
from benchmarks.orchestrator import build_image, run_all
from benchmarks.report import build_summary, print_summary, save_results


def main() -> None:
    parser = ArgumentParser(description="CodeGuard Benchmark Runner")
    parser.add_argument(
        "--scenarios-file", type=Path,
        default=SCENARIOS_DIR / "javavulnerablelab.yaml",
        help="Path to YAML file with config + scenarios",
    )
    parser.add_argument(
        "--scenario", "-s", nargs="*",
        help="Run only these scenario IDs",
    )
    parser.add_argument("--runs", "-n", type=int, help="Override runs_per_scenario")
    parser.add_argument("--parallel", "-p", type=int, help="Override max_parallel")
    parser.add_argument("--timeout", "-t", type=int, help="Override timeout_seconds")
    parser.add_argument("--model", help="Override agent_model")
    parser.add_argument("--judge-model", help="Override judge_model")
    parser.add_argument(
        "--build", action="store_true",
        help="Rebuild Docker image before running",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print scenario plan without executing",
    )
    args = parser.parse_args()

    # Build CLI overrides dict (only set keys)
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

    # Load config + scenarios from YAML
    config, scenarios = load_benchmark(args.scenarios_file, overrides or None)

    # Filter scenarios if requested
    if args.scenario:
        scenarios = {k: v for k, v in scenarios.items() if k in args.scenario}

    if not scenarios:
        print("No scenarios matched. Exiting.")
        sys.exit(1)

    total_containers = len(scenarios) * 2 * config.runs_per_scenario
    print(f"Loaded {len(scenarios)} scenarios from {args.scenarios_file.name}")
    print(f"Agent: {config.agent_model}  |  Judge: {config.judge_model}")
    print(f"Runs per scenario: {config.runs_per_scenario}")
    print(f"Total container runs: {total_containers} ({total_containers // 2} with + {total_containers // 2} without)")
    print(f"Max parallel: {config.max_parallel}")

    if args.dry_run:
        print(f"\n{'Scenario plan':}")
        for s in scenarios.values():
            print(f"  {s.id}: {s.name} [{s.security_category.value}]")
            print(f"    Repo: {s.repo_url} @ {s.repo_ref}")
            print(f"    Files: {', '.join(s.context_files)}")
        sys.exit(0)

    # Load credentials from .env
    creds = load_credentials()

    async def _run() -> None:
        if args.build:
            print("\nBuilding Docker image...")
            await build_image()
            print("Image built successfully.")

        print(f"\nStarting benchmark ({total_containers} containers)...")
        results = await run_all(list(scenarios.values()), config, creds)

        succeeded = sum(1 for r in results if not r.error)
        failed = sum(1 for r in results if r.error)
        timed_out = sum(1 for r in results if r.timed_out)
        print(f"Containers finished: {succeeded} ok, {failed} errors, {timed_out} timeouts")

        print(f"\nJudging {len(results)} results...")
        verdicts = await judge_all(scenarios, results, config, creds)

        summary = build_summary(scenarios, verdicts, config, results)
        filepath = save_results(summary, RESULTS_DIR)
        print(f"Results saved to: {filepath}")
        print_summary(summary)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
