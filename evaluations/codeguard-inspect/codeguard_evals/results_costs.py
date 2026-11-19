"""Recorded usage, explicit pricing and cost comparisons shared by benchmarks."""

import math
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codeguard_evals.results_common import ReportError as ExportError, Row, number
from codeguard_evals.safe_io import load_strict_json, read_bounded

DEFAULT_COST_NOTE = (
    "USD estimates use supplied prices and recorded token usage. "
    "For old OpenAI logs without cache-write counts, non-cached input uses the higher "
    "input or cache-write rate. Actual charges may differ."
)
PRICE_FIELDS = ("input", "output", "input_cache_read", "input_cache_write")


def tokens(usage: Mapping[str, Any] | None) -> int | None:
    return sum(item.total_tokens for item in usage.values()) if usage else None


def usage_records(
    run: Row, samples: Sequence[Row], epoch: int,
) -> tuple[list[Row], bool]:
    """Return the usage records to total for one run and epoch, and whether it is the run total."""
    # The run total spans every epoch and language in the log, so use it only when nothing was filtered out.
    if run["epochs"] == 1 and not run.get("_language_subset", False):
        return [run], True
    attempts = [sample for sample in samples if (sample["run"], sample["epoch"]) == (run["run"], epoch)]
    # Every report counts missing records separately; estimates use known usage only.
    return [sample for sample in attempts if sample["_usage"]], False


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


def recorded_cost(usage: Mapping[str, Any] | None, inspect_version: object) -> int | float | str:
    if _missing_cache_writes(usage, inspect_version):
        return ""
    costs = [number(item.total_cost) for item in (usage or {}).values()]
    return sum(costs) if costs and "" not in costs else ""


def complete_run_cost(
    usage: Mapping[str, Any] | None, samples: Sequence[Any], inspect_version: object
) -> int | float | str:
    """Do not treat a priced retry as pricing its earlier unpriced usage."""
    total = recorded_cost(usage, inspect_version)
    if total == "" or any(recorded_cost(sample.model_usage, inspect_version) == "" for sample in samples):
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


def apply_prices(
    runs: Sequence[Row], samples: Sequence[Row], public: Sequence[Row], path: Path,
) -> None:
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
            records, _ = usage_records(run, samples, row["epoch"])
            if not records:
                raise ExportError("The selected examples have no recorded model usage to price.")
            row["estimated_cost_usd"] = number(sum(
                _price_usage(record["_usage"], model, rates, run["inspect_version"]) for record in records
            ))
    update_cost_columns(public)


def total_cost(row: Row):
    """Use supplied-price estimates when present; otherwise use recorded costs."""
    return row["estimated_cost_usd"] if row["estimated_cost_usd"] != "" else row["recorded_cost_usd"]


def update_cost_columns(results: Sequence[Row]) -> None:
    """Derive costs against the same-model, same-epoch baseline."""
    baselines = {
        (row["model"], row["epoch"]): total_cost(row)
        for row in results if row["condition"] == "baseline"
    }
    for row in results:
        cost = total_cost(row)
        baseline = baselines.get((row["model"], row["epoch"]), "")
        row["cost_per_case_usd"] = cost / row["cases"] if cost != "" and row["cases"] else ""
        row["cost_change_pct"] = 100 * (cost / baseline - 1) if cost != "" and baseline not in ("", 0) else ""
