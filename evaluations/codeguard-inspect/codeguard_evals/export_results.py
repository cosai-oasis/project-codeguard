"""Export completed SecurityEval logs as a results page, charts, and CSV files.

Logs are read through Inspect's read-only API and must come from trusted local
runs. Only allowlisted public results are exported: never transcripts,
source, endpoints, error text, or file paths. Nothing is rescored, and the
output must be a new directory, so existing files are never replaced.
"""

from __future__ import annotations

import argparse
import math
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final, get_args

from inspect_ai.log import EvalSampleLimit, read_eval_log, read_eval_log_sample_summaries
from codeguard_evals.safe_io import load_strict_json, read_bounded
from codeguard_evals import results_report as report
from codeguard_evals.results_report import (
    DEFAULT_TITLE, MODEL_LABEL, TITLE, VERSION, ReportError as ExportError, number, text,
)

from codeguard_evals.scorers import (
    CHANGED_OUTPUT_METRIC,
    CONFIDENCE_HIGH_METRIC,
    CONFIDENCE_MEDIUM_METRIC,
    CONFIDENCE_LOW_METRIC,
    FINDING_COUNT_METRIC,
    SUBCATEGORY_VULN_METRIC,
    VALID_OUTPUT_METRIC,
)
from codeguard_evals.securityeval.protocol import (
    STATIC_SAFETY_SUITE,
    Condition,
    securityeval_case_cwe,
)

SCORER: Final = "static_safety_scorer"
METRICS: Final = (
    CHANGED_OUTPUT_METRIC,
    VALID_OUTPUT_METRIC,
    FINDING_COUNT_METRIC,
    SUBCATEGORY_VULN_METRIC,
    CONFIDENCE_HIGH_METRIC,
    CONFIDENCE_MEDIUM_METRIC,
    CONFIDENCE_LOW_METRIC,
)
CONDITIONS: Final = frozenset(get_args(Condition))
LIMITS: Final = frozenset(
    get_args(EvalSampleLimit.model_fields["type"].annotation)
)
SHA256: Final = r"[0-9a-f]{64}"

DEFAULT_COST_NOTE = (
    "USD estimates use supplied prices and recorded token usage. "
    "For old OpenAI logs without cache-write counts, non-cached input uses the higher "
    "input or cache-write rate. Actual charges may differ."
)
PRICE_FIELDS = ("input", "output", "input_cache_read", "input_cache_write")

Row = dict[str, object]


# Settings that should match before runs are compared, with plain names.
SETTINGS: Final = (
    ("dataset", ("dataset_revision", "dataset_sha256")),
    ("scanner", ("semgrep_version", "rules_sha256", "semgrep_image_digest")),
    ("Codex version", ("codex_version",)),
    ("Inspect version", ("inspect_version",)),
    ("Inspect SWE version", ("inspect_swe_version",)),
    ("Python version", ("python_version",)),
    ("sample order", ("sample_shuffle",)),
    ("sample concurrency", ("max_samples",)),
    ("sandbox concurrency", ("max_sandboxes",)),
    ("connection limit", ("max_connections",)),
    ("retry limit", ("max_retries",)),
    ("turn limit", ("agent_turn_limit",)),
    ("agent time limit", ("agent_seconds",)),
    ("output token limit", ("agent_output_tokens",)),
    ("case time limit", ("sample_seconds_limit",)),
    ("reasoning effort", ("reasoning_effort",)),
    ("harness version", ("harness_commit", "harness_dirty")),
)


def read_run(model_label: str, path: Path) -> tuple[str | None, Row, list[Row]]:
    """Validate one final log; return its task ID, run summary, and case rows."""
    model_label = text(model_label, MODEL_LABEL)
    if path.suffix != ".eval" or not path.is_file():
        raise ExportError("Each input must be an existing local .eval file.")
    # Resolving a local file before Inspect reads it rules out remote storage URLs.
    path = path.resolve()
    log = read_eval_log(path, header_only=True)
    if log.status != "success" or log.invalidated or log.results is None:
        raise ExportError("Select a completed, non-invalidated final log.")
    if any(score.scorer != SCORER for score in log.results.scores):
        raise ExportError(f"Unsupported scorer; expected {SCORER}.")
    if log.config_updates:
        raise ExportError(
            "Runs with mid-run configuration changes need separate review."
        )

    meta = log.eval.metadata or {}
    condition = meta.get("condition")
    if meta.get("benchmark") != "SecurityEval" or condition not in CONDITIONS:
        raise ExportError("The log is not a supported SecurityEval condition.")
    skill, dataset, scanner, limits = (
        meta.get(key) or {}
        for key in ("codeguard", "dataset", "semgrep", "generation_limits")
    )
    if not all(isinstance(item, dict) for item in (skill, dataset, scanner, limits)):
        raise ExportError("The recorded provenance has an unsupported format.")
    version = _skill_version(condition, skill)
    words = f"{model_label} {condition} {version}".lower()
    run = re.sub(r"[^a-z0-9.]+", "-", words).strip("-")
    summaries = read_eval_log_sample_summaries(path)
    rows = _sample_rows(run, condition, summaries, log)
    config, generate = log.eval.config, log.eval.model_generate_config
    inspect_version = _setting(log.eval.packages.get("inspect_ai"))
    revision = log.eval.revision
    shuffle = config.sample_shuffle
    summary: Row = {
        "run": run,
        "model_label": model_label,
        "condition": condition,
        "codeguard_version": version,
        "epochs": config.epochs or 1,
        "harness_commit": _setting(revision.commit) if revision else "",
        "harness_dirty": ""
        if revision is None or revision.dirty is None
        else int(revision.dirty),
        "inspect_version": inspect_version,
        "codex_version": _setting(meta.get("codex_version")),
        "inspect_swe_version": _setting(meta.get("inspect_swe_version")),
        "python_version": _setting(meta.get("python_version")),
        "dataset_revision": _setting(dataset.get("revision")),
        "dataset_sha256": _setting(dataset.get("sha256")),
        "semgrep_version": _setting(scanner.get("version")),
        "rules_sha256": _setting(scanner.get("rules_tree_sha256")),
        "semgrep_image_digest": _setting(scanner.get("image_digest")),
        "sample_shuffle": "" if shuffle is None else str(shuffle).lower(),
        "max_samples": _setting(config.max_samples),
        "max_sandboxes": _setting(config.max_sandboxes),
        "max_connections": _setting(generate.max_connections),
        "max_retries": _setting(generate.max_retries),
        "agent_turn_limit": number(limits.get("turns")),
        "agent_seconds": number(limits.get("agent_seconds")),
        "agent_output_tokens": number(limits.get("output_tokens")),
        "sample_seconds_limit": number(config.time_limit),
        "reasoning_effort": _setting(generate.reasoning_effort),
        "samples": len(rows),
        "recorded_tokens": number(_tokens(log.stats.model_usage)),
        "recorded_cost_usd": _complete_run_cost(log.stats.model_usage, summaries, inspect_version),
        "_usage": log.stats.model_usage,
    }
    return log.eval.task_id, summary, rows


def read_runs(runs: Sequence[tuple[str, str | Path]], *, epoch: int | None = None) -> tuple[list[Row], list[Row]]:
    """Validate the selected final logs before computing public aggregates."""
    results, samples, tasks = [], [], set()
    case_sets = {}
    for model_label, source in runs:
        task_id, result, rows = read_run(model_label, Path(source))
        if any(result["run"] == other["run"] for other in results):
            raise ExportError(
                "Select one final log per model, condition, and CodeGuard version. "
                "Run IDs ignore case and most punctuation, so different labels or versions can collide."
            )
        if task_id and task_id in tasks:
            raise ExportError("Select only one final log per task, not its retry logs.")
        tasks.add(task_id)
        results.append(result)
        samples.extend(rows)
        case_sets[result["run"]] = {row["case_id"] for row in rows}
    if not results:
        raise ExportError("Select at least one run.")
    for group in by_model(results).values():
        if len({row["epochs"] for row in group}) != 1:
            raise ExportError("Runs for the same model must have matching epoch counts.")
        if any(case_sets[row["run"]] != case_sets[group[0]["run"]] for row in group[1:]):
            raise ExportError("Runs for the same model must attempt the same cases.")
    if epoch is not None and (type(epoch) is not int or epoch < 1 or any(epoch > row["epochs"] for row in results)):
        raise ExportError("The selected epoch must exist in every run.")
    return results, samples


def export_results(runs: Sequence[tuple[str, str | Path]], output: Path, *, title: str = DEFAULT_TITLE,
                   epoch: int | None = None, prices: Path | None = None, cost_note: str = DEFAULT_COST_NOTE) -> None:
    if output.exists() or output.is_symlink():
        raise ExportError("The output directory already exists. Choose a new directory.")
    title = text(title, TITLE)
    results, samples = read_runs(runs, epoch=epoch)
    selected = [sample for sample in samples if epoch is None or sample["epoch"] == epoch]
    public = public_results(results, samples, epoch=epoch)
    if prices is not None:
        _apply_prices(results, selected, public, prices)
    estimated = any(row["estimated_cost_usd"] != "" for row in public)
    report.write_report(output, public, _public_samples(selected),
                        title=title, comparison_note=comparison_note(results), cost_note=cost_note if estimated else "",
                        multiple_epochs=any(row["epochs"] > 1 for row in results))


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", nargs=2, action="append", required=True, metavar=("MODEL", "LOG"),
                        help="Public model label and final local .eval log; repeat per run in display order.")
    parser.add_argument("--title", default=DEFAULT_TITLE, help="Title of the results page.")
    parser.add_argument("--epoch", type=int, metavar="N", help="Export only epoch N; otherwise show every epoch separately.")
    parser.add_argument("-o", "--output-dir", type=Path, required=True, help="New output directory.")
    parser.add_argument("--prices", type=Path,
                        help="Price every run using JSON rates per million tokens, keyed by public model label.")
    parser.add_argument("--cost-note", default=DEFAULT_COST_NOTE, help="Public explanation of estimated costs.")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = argument_parser()
    args = parser.parse_args(argv)
    try:
        export_results(args.run, args.output_dir, title=args.title, epoch=args.epoch, prices=args.prices, cost_note=args.cost_note)
    except ExportError as error:
        parser.exit(2, f"Export refused: {error}\n")
    except Exception:
        # Unexpected tracebacks can expose private log values. Cancellation still propagates.
        parser.exit(2, "Export failed: check the logs, prices, and that the output directory is new. "
                      "Details are omitted because they can contain private values.\n")
    print("Wrote index.md, charts, and CSVs. Review every file before committing. Link the report from docs/results/index.md.")


def _setting(value: object) -> object:
    """Compare private settings as scalars without imposing a published format."""
    if value is None:
        return ""
    if type(value) not in (str, int, float, bool):
        raise ExportError("A comparison setting has an unsupported type.")
    return value


def _apply_prices(runs: Sequence[Row], samples: Sequence[Row], public: Sequence[Row], path: Path) -> None:
    """Apply one supplied pricing basis to every run, keeping recorded costs separate."""
    data = load_strict_json(read_bounded(path, 64 * 1024, label="Model prices"))
    if not isinstance(data, dict) or not data:
        raise ExportError("Prices require public model labels and rates.")
    for rates in data.values():
        if not isinstance(rates, dict) or set(rates) != set(PRICE_FIELDS):
            raise ExportError("Each model needs input, output, input_cache_read, and input_cache_write prices.")
        if any(number(rate) == "" for rate in rates.values()):
            raise ExportError("Prices must be finite, non-negative numbers.")
    for run in runs:
        if run["model_label"] not in data:
            raise ExportError("A public model label has no configured prices.")
        usage = run["_usage"]
        if not usage or len(usage) != 1:
            raise ExportError("Estimates require complete usage for one model per run.")
        model = next(iter(usage))
        rates = data[run["model_label"]]
        for row in public:
            if row["run"] != run["run"]:
                continue
            usages = [usage] if run["epochs"] == 1 else [
                sample["_usage"] for sample in samples if (sample["run"], sample["epoch"]) == (row["run"], row["epoch"])
            ]
            row["estimated_cost_usd"] = number(sum(
                _price_usage(item, model, rates, run["inspect_version"]) for item in usages
            ))
    report.update_cost_columns(public)


def _price_usage(usage: Mapping[str, Any] | None, model: str, rates: Mapping[str, float], inspect_version: object) -> float:
    if not usage or set(usage) != {model}:
        raise ExportError("Estimates require complete usage for one model per run.")
    item = usage[model]
    counts = (item.input_tokens, item.output_tokens, item.input_tokens_cache_read or 0, item.input_tokens_cache_write or 0)
    if any(type(n) is not int or n < 0 for n in counts) or sum(counts) != item.total_tokens:
        raise ExportError("Token counts do not add up to the recorded total.")
    normal, output, cache_read, cache_write = counts
    input_price = rates["input"]
    if _missing_cache_writes(usage, inspect_version):
        input_price = max(input_price, rates["input_cache_write"])
    return (normal * input_price + output * rates["output"]
            + cache_read * rates["input_cache_read"]
            + cache_write * rates["input_cache_write"]) / 1_000_000


def _skill_version(condition: str, skill: Mapping[str, Any]) -> str:
    """Require recorded skill provenance, but publish only its version."""
    if condition != "codeguard":
        return ""
    digest = text(skill.get("content_sha256"), SHA256)
    if not digest:
        raise ExportError("CodeGuard provenance is missing its content hash.")
    version = skill.get("version")
    if version in (None, "unspecified"):
        raise ExportError(f"The CodeGuard skill {digest[:12]} records no version.")
    return text(version, VERSION)


def _sample_rows(
    run: str, condition: str, samples: Sequence[Any], log: Any
) -> list[Row]:
    if not samples or len(samples) != log.results.total_samples:
        raise ExportError("The final log does not contain its full sample inventory.")
    prefix = f"{STATIC_SAFETY_SUITE}/{condition}/"
    rows: list[Row] = []
    epochs = log.eval.config.epochs or 1
    seen: set[tuple[str, int]] = set()
    for sample in sorted(samples, key=lambda item: (item.epoch, str(item.id))):
        case_id = str(sample.id).removeprefix(prefix)
        try:
            if case_id == str(sample.id) or not 1 <= sample.epoch <= epochs:
                raise ValueError
            securityeval_case_cwe(case_id)
        except ValueError:
            raise ExportError("A sample has an unsupported case ID or epoch.") from None
        identity = (case_id, sample.epoch)
        if identity in seen:
            raise ExportError("The selected log contains duplicate case/epoch pairs.")
        seen.add(identity)
        if sample.limit is not None and sample.limit not in LIMITS:
            raise ExportError("A sample has an unsupported limit type.")
        scores = sample.scores or {}
        if scores and set(scores) != {SCORER}:
            raise ExportError(f"Unsupported sample scorer; expected {SCORER}.")
        score = scores.get(SCORER)
        if score is None and sample.error is None:
            raise ExportError("A sample is missing its expected scorer.")
        values = score.value if score is not None else {}
        if not isinstance(values, dict):
            raise ExportError("The sample score must contain named metrics.")
        rows.append(
            {
                "run": run,
                "case_id": case_id,
                "epoch": sample.epoch,
                "error": int(sample.error is not None),
                "limit": sample.limit or "",
                "recorded_tokens": number(_tokens(sample.model_usage)),
                "recorded_cost_usd": _recorded_cost(sample.model_usage, log.eval.packages.get("inspect_ai")),
                "_usage": sample.model_usage,
                **{name: number(values.get(name)) for name in METRICS},
            }
        )
    if len(seen) != len({case for case, _ in seen}) * epochs:
        raise ExportError("Every selected case must have a recorded attempt in every epoch.")
    return rows


def _tokens(usage: Mapping[str, Any] | None) -> int | None:
    return sum(item.total_tokens for item in usage.values()) if usage else None


def _missing_cache_writes(usage: Mapping[str, Any] | None, inspect_version: object) -> bool:
    """Old OpenAI summaries may count cache writes as ordinary input."""
    version = str(inspect_version).split(".")
    fixed = (
        len(version) >= 3 and all(p.isdigit() for p in version[:3])
        and tuple(map(int, version[:3])) >= (0, 3, 260)
    )
    return not fixed and any(
        model.startswith("openai/") and item.input_tokens_cache_write is None
        for model, item in (usage or {}).items()
    )


def _recorded_cost(usage: Mapping[str, Any] | None, inspect_version: object) -> int | float | str:
    if _missing_cache_writes(usage, inspect_version):
        return ""
    costs = [number(item.total_cost) for item in (usage or {}).values()]
    return sum(costs) if costs and "" not in costs else ""


def _complete_run_cost(
    usage: Mapping[str, Any] | None, samples: Sequence[Any], inspect_version: object
) -> int | float | str:
    """Do not treat a priced retry as pricing its earlier unpriced usage."""
    total = _recorded_cost(usage, inspect_version)
    if total == "" or any(_recorded_cost(sample.model_usage, inspect_version) == "" for sample in samples):
        return ""
    for model, whole in usage.items():
        saved = [sample.model_usage[model] for sample in samples if model in sample.model_usage]
        known_tokens = sum(item.total_tokens for item in saved)
        known_cost = sum(item.total_cost for item in saved)
        # Extra run-level usage may mix priced and unpriced attempts. Without
        # a matching priced sample ledger, a complete cost cannot be established.
        if whole.total_tokens != known_tokens or not math.isclose(
            whole.total_cost, known_cost, rel_tol=1e-12, abs_tol=1e-12
        ):
            return ""
    return total


def by_model(results: Sequence[Row]) -> dict[str, list[Row]]:
    groups: dict[str, list[Row]] = {}
    for row in results:
        groups.setdefault(row["model_label"], []).append(row)
    return groups


def outcome(sample: Row) -> str:
    """Place each attempt in exactly one outcome, so the bars add up to all cases."""
    if sample["limit"] == "turn":
        return "Turn limit"
    if sample["limit"] == "time":
        return "Time limit"
    if sample["limit"]:
        return "Other limit"
    return "Error" if sample["error"] else "Completed"


def shared_cases(runs: Sequence[Row], samples: Sequence[Row]) -> set[str]:
    """Return the cases where every run produced changed, valid, scanned code."""
    scanned: dict[object, set[str]] = {row["run"]: set() for row in runs}
    for sample in samples:
        if (
            sample["run"] in scanned
            and sample["changed_output"] == 1
            and sample["valid_output"] == 1
            and sample["finding_count"] != ""
        ):
            scanned[sample["run"]].add(sample["case_id"])
    return set.intersection(*scanned.values()) if scanned else set()


def setting_notes(results: Sequence[Row]) -> tuple[list[str], list[str]]:
    """Name the settings that differ between runs, and those some runs lack."""
    differ = [
        label
        for label, keys in SETTINGS
        if len({tuple(row[key] for key in keys) for row in results}) > 1
    ]
    missing = [
        label
        for label, keys in SETTINGS
        if label not in differ
        and any(row[key] == "" for row in results for key in keys)
    ]
    return differ, missing


def _total(samples: Sequence[Row], key: str) -> object:
    values = [sample[key] for sample in samples]
    return "" if "" in values else sum(values)


def comparison_note(results: Sequence[Row]) -> str:
    differ, missing = setting_notes(results)
    if differ == ["harness version"] and not missing:
        return "Recorded comparison settings match; harness snapshots differ."
    notes = []
    if differ:
        notes.append(f"settings differ for {report.listed(differ)}")
    if missing:
        notes.append(f"not recorded: {report.listed(missing)}")
    return "> **Check before comparing:** " + "; ".join(notes) + "." if notes else ""


def public_results(results: Sequence[Row], samples: Sequence[Row], *, epoch: int | None = None) -> list[Row]:
    """Compute each shared cohort once and return only public summary columns."""
    exported = []
    epochs = [epoch] if epoch is not None else sorted({sample["epoch"] for sample in samples})
    for selected_epoch in epochs:
        selected = [sample for sample in samples if sample["epoch"] == selected_epoch]
        for runs in by_model([row for row in results if row["epochs"] >= selected_epoch]).values():
            shared = shared_cases(runs, selected)
            for row in runs:
                own = [sample for sample in selected if sample["run"] == row["run"]]
                scanned = [sample for sample in own if sample["case_id"] in shared]
                tokens = row["recorded_tokens"] if row["epochs"] == 1 else _total(own, "recorded_tokens")
                cost = row["recorded_cost_usd"] if row["epochs"] == 1 else _total(own, "recorded_cost_usd")
                count = row["samples"] if row["epochs"] == 1 else len(own)
                exported.append({
                    "run": row["run"], "epoch": selected_epoch, "model": row["model_label"],
                    "condition": row["condition"], "codeguard_version": row["codeguard_version"],
                    **{key: row[key] for key in report.LIMIT_FIELDS},
                    "cases": count, "shared_cases": len(shared),
                    "findings": _total(scanned, "finding_count") if shared else "",
                    "likely_vulnerabilities": _total(scanned, "subcategory_vuln") if shared else "",
                    "tokens_per_case": tokens / count if tokens != "" and count else "",
                    "unfinished": sum(outcome(sample) != "Completed" for sample in own),
                    "recorded_cost_usd": cost, "estimated_cost_usd": "",
                    "cost_per_case_usd": "", "cost_change_pct": "",
                    **{key: _total(scanned, key) if shared else "" for key in (
                        "confidence_high", "confidence_medium", "confidence_low")},
                })
    report.update_cost_columns(exported)
    return exported


def _public_samples(samples: Sequence[Row]) -> list[Row]:
    """Keep public case results; exclude timing, retries, usage, and diagnostics."""
    return [
        {
            "run": row["run"],
            "case_id": row["case_id"],
            "epoch": row["epoch"],
            "outcome": outcome(row),
            "changed_output": row["changed_output"],
            "valid_output": row["valid_output"],
            "findings": row["finding_count"],
            "likely_vulnerabilities": row["subcategory_vuln"],
        }
        for row in samples
    ]


if __name__ == "__main__":
    main()
