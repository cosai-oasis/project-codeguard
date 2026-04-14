"""
Results aggregation and reporting.

Collects JudgeVerdicts, groups by scenario and mode,
computes statistics, and produces BenchmarkSummary.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from benchmarks.models import (
    BenchmarkConfig,
    BenchmarkSummary,
    ContainerResult,
    JudgeVerdict,
    RunMode,
    Scenario,
    ScenarioReport,
    UsageSummary,
)


def aggregate_scenario(
    scenario: Scenario,
    verdicts: list[JudgeVerdict],
) -> ScenarioReport:
    with_skills = [v for v in verdicts if v.run_mode == RunMode.WITH_SKILLS]
    without_skills = [v for v in verdicts if v.run_mode == RunMode.WITHOUT_SKILLS]

    def _avg_score(vs: list[JudgeVerdict]) -> float:
        return (sum(v.security_score for v in vs) / len(vs)) if vs else 0.0

    def _secure_rate(vs: list[JudgeVerdict]) -> float:
        return (sum(1 for v in vs if v.secure_implementation) / len(vs)) if vs else 0.0

    avg_w = _avg_score(with_skills)
    avg_wo = _avg_score(without_skills)

    return ScenarioReport(
        scenario_id=scenario.id,
        scenario_name=scenario.name,
        security_category=scenario.security_category.value,
        with_skills=with_skills,
        without_skills=without_skills,
        avg_score_with=round(avg_w, 2),
        avg_score_without=round(avg_wo, 2),
        delta=round(avg_w - avg_wo, 2),
        secure_rate_with=round(_secure_rate(with_skills), 3),
        secure_rate_without=round(_secure_rate(without_skills), 3),
    )


def _aggregate_usage(
    container_results: list[ContainerResult],
    verdicts: list[JudgeVerdict],
) -> UsageSummary:
    agent_prompt = sum(r.agent_usage.prompt_tokens for r in container_results)
    agent_completion = sum(r.agent_usage.completion_tokens for r in container_results)
    judge_prompt = sum(v.judge_usage.prompt_tokens for v in verdicts)
    judge_completion = sum(v.judge_usage.completion_tokens for v in verdicts)
    return UsageSummary(
        agent_prompt_tokens=agent_prompt,
        agent_completion_tokens=agent_completion,
        agent_total_tokens=agent_prompt + agent_completion,
        judge_prompt_tokens=judge_prompt,
        judge_completion_tokens=judge_completion,
        judge_total_tokens=judge_prompt + judge_completion,
        total_tokens=agent_prompt + agent_completion + judge_prompt + judge_completion,
    )


def build_summary(
    scenarios: dict[str, Scenario],
    verdicts: list[JudgeVerdict],
    config: BenchmarkConfig,
    container_results: list[ContainerResult] | None = None,
) -> BenchmarkSummary:
    by_scenario: dict[str, list[JudgeVerdict]] = defaultdict(list)
    for v in verdicts:
        by_scenario[v.scenario_id].append(v)

    reports = []
    for sid, vlist in sorted(by_scenario.items()):
        if sid in scenarios:
            reports.append(aggregate_scenario(scenarios[sid], vlist))

    all_with = [v for v in verdicts if v.run_mode == RunMode.WITH_SKILLS]
    all_without = [v for v in verdicts if v.run_mode == RunMode.WITHOUT_SKILLS]

    overall_avg_with = (
        sum(v.security_score for v in all_with) / len(all_with)
    ) if all_with else 0.0
    overall_avg_without = (
        sum(v.security_score for v in all_without) / len(all_without)
    ) if all_without else 0.0

    # By category
    by_category: dict[str, dict[str, float]] = {}
    cat_groups: dict[str, list[ScenarioReport]] = defaultdict(list)
    for r in reports:
        cat_groups[r.security_category].append(r)
    for cat, cat_reports in sorted(cat_groups.items()):
        avg_w = sum(r.avg_score_with for r in cat_reports) / len(cat_reports)
        avg_wo = sum(r.avg_score_without for r in cat_reports) / len(cat_reports)
        by_category[cat] = {
            "avg_with": round(avg_w, 2),
            "avg_without": round(avg_wo, 2),
            "delta": round(avg_w - avg_wo, 2),
        }

    return BenchmarkSummary(
        timestamp=datetime.now(timezone.utc),
        model=config.agent_model,
        judge_model=config.judge_model,
        total_scenarios=len(reports),
        runs_per_scenario=config.runs_per_scenario,
        scenario_reports=reports,
        overall_avg_with=round(overall_avg_with, 2),
        overall_avg_without=round(overall_avg_without, 2),
        overall_delta=round(overall_avg_with - overall_avg_without, 2),
        overall_secure_rate_with=round(
            (sum(1 for v in all_with if v.secure_implementation) / len(all_with)), 3
        ) if all_with else 0.0,
        overall_secure_rate_without=round(
            (sum(1 for v in all_without if v.secure_implementation) / len(all_without)), 3
        ) if all_without else 0.0,
        by_category=by_category,
        usage=_aggregate_usage(container_results or [], verdicts),
    )


def save_results(summary: BenchmarkSummary, results_dir: Path) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    ts = summary.timestamp.strftime("%Y%m%d_%H%M%S")
    filepath = results_dir / f"benchmark_{ts}.json"
    filepath.write_text(
        summary.model_dump_json(indent=2),
        encoding="utf-8",
    )
    return filepath


def print_summary(summary: BenchmarkSummary) -> None:
    print(f"\n{'=' * 76}")
    print(f"  CodeGuard Benchmark Results  (CVSS: 0=ideal, 10=critical)")
    print(f"  Model: {summary.model}  |  Judge: {summary.judge_model}")
    print(f"  Scenarios: {summary.total_scenarios}  |  Runs each: {summary.runs_per_scenario}")
    print(f"{'=' * 76}\n")

    header = f"  {'Scenario':<40} {'With':>6} {'W/o':>6} {'Delta':>7} {'Sec%':>6}"
    print(header)
    print(f"  {'-' * 40} {'-' * 6} {'-' * 6} {'-' * 7} {'-' * 6}")

    for r in summary.scenario_reports:
        name = r.scenario_name[:38]
        sec_pct = f"{r.secure_rate_with * 100:.0f}%"
        print(
            f"  {name:<40} {r.avg_score_with:>6.1f} "
            f"{r.avg_score_without:>6.1f} {r.delta:>+7.1f} {sec_pct:>6}"
        )

    print(
        f"\n  {'OVERALL':<40} {summary.overall_avg_with:>6.1f} "
        f"{summary.overall_avg_without:>6.1f} {summary.overall_delta:>+7.1f}"
    )

    if summary.by_category:
        print(f"\n  By Category:")
        for cat, stats in sorted(summary.by_category.items()):
            print(
                f"    {cat:<36} {stats['avg_with']:>6.1f} "
                f"{stats['avg_without']:>6.1f} {stats['delta']:>+7.1f}"
            )

    u = summary.usage
    if u.total_tokens > 0:
        print(f"\n  Token Usage:")
        print(f"    Agent:  {u.agent_prompt_tokens:>10,} prompt + {u.agent_completion_tokens:>10,} completion = {u.agent_total_tokens:>10,}")
        print(f"    Judge:  {u.judge_prompt_tokens:>10,} prompt + {u.judge_completion_tokens:>10,} completion = {u.judge_total_tokens:>10,}")
        print(f"    Total:  {u.total_tokens:>10,} tokens")
    print()
