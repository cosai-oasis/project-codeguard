"""Export completed benchmark logs as a results page, charts, and CSV files.

Logs are read through Inspect's read-only API and must come from trusted local
runs. Only allowlisted public results are exported: never transcripts,
source, endpoints, error text, or file paths. Nothing is rescored, and the
output must be a new directory, so existing files are never replaced.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final, get_args

from inspect_ai.log import (
    EvalSampleLimit, read_eval_log, read_eval_log_sample, read_eval_log_sample_summaries,
)
from codeguard_evals import results_costs as costs, results_report as report
from codeguard_evals.cyberseceval import reporting as cyber_report
from codeguard_evals.securityeval import reporting as security_report
from codeguard_evals.protocol import Condition
from codeguard_evals.skill_catalog import recorded_skill
from codeguard_evals.skill_files import CODEGUARD_SKILL_NAME
from codeguard_evals.results_common import (
    LIMIT_FIELDS, MODEL_LABEL, TITLE, VERSION,
    ReportError as ExportError, Row, number, text, total,
)

REPORTERS = {"SecurityEval": security_report, "CyberSecEval": cyber_report}
LANGUAGES = tuple(dict.fromkeys(
    language for reporter in REPORTERS.values() for language in reporter.LANGUAGES
))

CONDITIONS: Final = frozenset(get_args(Condition))
LIMITS: Final = frozenset(
    get_args(EvalSampleLimit.model_fields["type"].annotation)
)

# Settings that should match before runs are compared, with plain names.
SETTINGS: Final = (
    ("evaluation contract", ("evaluation_contract",)),
    ("dataset", ("dataset_revision", "dataset_sha256")),
    ("scanner", ("scanner_version", "rules_sha256", "scanner_image_digest")),
    ("scanner execution", ("scanner_execution",)),
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
    meta = log.eval.metadata or {}
    benchmark = meta.get("benchmark")
    if not isinstance(benchmark, str) or benchmark not in REPORTERS:
        raise ExportError("The log is not a supported benchmark.")
    if meta.get("phase") == "generation":
        raise ExportError(
            "This log has not been scored. Run python -m codeguard_evals.scan, "
            "then export the scored log."
        )
    reporter = REPORTERS[benchmark]
    scorer = reporter.SCORER
    if any(score.scorer != scorer for score in log.results.scores):
        raise ExportError(f"Unsupported scorer; expected {scorer}.")
    if log.config_updates:
        raise ExportError(
            "Runs with mid-run configuration changes need separate review."
        )

    condition = meta.get("condition")
    if condition not in CONDITIONS:
        raise ExportError("The log is not a supported benchmark condition.")
    dataset, limits = (meta.get(key) or {} for key in ("dataset", "generation_limits"))
    if not all(isinstance(item, dict) for item in (dataset, limits)):
        raise ExportError("The recorded provenance has an unsupported format.")
    scanner_settings = reporter.recorded_scanner_settings(meta)
    scanner = scanner_settings["identity"]
    try:
        selection = recorded_skill(meta)
        # Historical CodeGuard logs must record a release; catalog entries publish only release versions.
        released = selection is not None and selection.name == CODEGUARD_SKILL_NAME and (
            condition == "codeguard" or re.fullmatch(VERSION, selection.version or "") is not None)
        version = text(selection.version, VERSION) if released else ""
    except ValueError:
        raise ExportError("The recorded skill identity is missing or invalid.") from None
    variant = selection.id if selection and condition == "skill" else version
    words = f"{model_label} {condition} {variant}".lower()
    run = re.sub(r"[^a-z0-9.]+", "-", words).strip("-")
    summaries = read_eval_log_sample_summaries(path)
    # Read complete scores one at a time: Inspect summaries may truncate metadata.
    samples = (
        read_eval_log_sample(
            path, sample.id, sample.epoch,
            exclude_fields={"messages", "events", "store", "output", "attachments"},
        )
        for sample in summaries
    )
    rows = _sample_rows(run, condition, samples, log, benchmark=benchmark, scanner_settings=scanner_settings)
    config, generate = log.eval.config, log.eval.model_generate_config
    inspect_version = _setting(log.eval.packages.get("inspect_ai"))
    revision = log.eval.revision
    shuffle = config.sample_shuffle
    if shuffle is None:
        shuffle = log.eval.dataset.shuffled
    summary: Row = {
        "benchmark": benchmark,
        "run": run,
        "model_label": model_label,
        "_model": log.eval.model,
        "condition": condition,
        "codeguard_version": version,
        "skill_id": (selection.id or "") if selection else "",
        "skill_label": selection.label if selection else "",
        "skill_sha256": selection.content_sha256 if selection else "",
        "epochs": config.epochs or 1,
        "harness_commit": _setting(revision.commit) if revision else "",
        "harness_dirty": ""
        if revision is None or revision.dirty is None
        else int(revision.dirty),
        "evaluation_contract": _setting(log.eval.task_version) or "",
        "inspect_version": inspect_version,
        "codex_version": _setting(meta.get("codex_version")),
        "inspect_swe_version": _setting(meta.get("inspect_swe_version")),
        "python_version": _setting(meta.get("python_version")),
        "dataset_revision": _setting(dataset.get("revision")),
        "dataset_sha256": _setting(dataset.get("sha256")),
        "scanner_version": _setting(scanner_settings["version"]),
        "rules_sha256": _setting(scanner_settings["rules_sha256"]),
        "scanner_image_digest": _setting(scanner_settings["image_digest"]),
        "scanner_execution": (
            json.dumps(scanner, sort_keys=True, separators=(",", ":"), allow_nan=False)
            if scanner is not None else ""
        ),
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
        "recorded_tokens": number(costs.tokens(log.stats.model_usage)),
        "recorded_cost_usd": costs.complete_run_cost(log.stats.model_usage, summaries, inspect_version),
        "_usage": log.stats.model_usage,
    }
    return log.eval.task_id, summary, rows


def read_runs(runs: Sequence[tuple[str, str | Path]], *, epoch: int | None = None,
              language: str | None = None) -> tuple[list[Row], list[Row]]:
    """Validate the selected final logs before computing public aggregates."""
    results, samples, tasks = [], [], set()
    if language is not None and (not isinstance(language, str) or language not in LANGUAGES):
        raise ExportError("Select a supported language.")
    case_sets = {}
    for model_label, source in runs:
        task_id, result, rows = read_run(model_label, Path(source))
        if language is not None:
            rows = [row for row in rows if row["language"] == language]
            if not rows:
                raise ExportError("Every selected run must contain the requested language.")
        result["_language_subset"] = len(rows) != result["samples"]
        if any(result["run"] == other["run"] for other in results):
            raise ExportError(
                "Select one final log per model, condition, and skill or CodeGuard version. "
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
    if len({row["benchmark"] for row in results}) != 1:
        raise ExportError("Select one benchmark per report.")
    for group in by_model(results).values():
        if len({row["_model"] for row in group}) != 1:
            raise ExportError("Runs under one public model label must use the same recorded model. "
                              "Use separate labels for different models.")
        if len({row["epochs"] for row in group}) != 1:
            raise ExportError("Runs for the same model must have matching epoch counts.")
        if any(case_sets[row["run"]] != case_sets[group[0]["run"]] for row in group[1:]):
            raise ExportError("Runs for the same model must attempt the same cases.")
    if epoch is not None and (type(epoch) is not int or epoch < 1 or any(epoch > row["epochs"] for row in results)):
        raise ExportError("The selected epoch must exist in every run.")
    return results, samples


def export_results(runs: Sequence[tuple[str, str | Path]], output: Path, *, title: str | None = None,
                   epoch: int | None = None, prices: Path | None = None, cost_note: str = costs.DEFAULT_COST_NOTE,
                   language: str | None = None) -> None:
    if output.exists() or output.is_symlink():
        raise ExportError("The output directory already exists. Choose a new directory.")
    if title is not None:
        title = text(title, TITLE)
    results, samples = read_runs(runs, epoch=epoch, language=language)
    benchmark = results[0]["benchmark"]
    reporter = REPORTERS[benchmark]
    if title is None:
        title = reporter.DEFAULT_TITLE + (f" ({reporter.LANGUAGES[language]})" if language else "")
    selected = [sample for sample in samples if epoch is None or sample["epoch"] == epoch]
    public = public_results(results, samples, epoch=epoch)
    if prices is not None:
        costs.apply_prices(results, selected, public, prices)
    estimated = any(row["estimated_cost_usd"] != "" for row in public)
    public_samples = _public_samples(selected, benchmark=benchmark)
    definition = reporter.report_definition(language)
    note = comparison_note(results)
    if any(row["_language_subset"] for row in results):
        note += ("\n\nThis report covers one language, so token and cost totals add up each example's final attempt. "
                 "Tokens from earlier retried attempts are recorded only for the whole run and "
                 "cannot be split by language, so these totals leave them out and slightly understate actual usage.")
    report.write_report(
        output, public, public_samples, definition=definition,
        title=title, comparison_note=note.strip(), cost_note=cost_note if estimated else "",
        multiple_epochs=any(row["epochs"] > 1 for row in results),
    )


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", nargs=2, action="append", required=True, metavar=("MODEL", "LOG"),
                        help="Public model label and final local .eval log; repeat per run in display order.")
    parser.add_argument("--title", help="Title of the results page; defaults to the benchmark name.")
    parser.add_argument("--epoch", type=int, metavar="N", help="Export only epoch N; otherwise show every epoch separately.")
    parser.add_argument("--language", choices=LANGUAGES,
                        help="Export one language; use final-attempt usage when the filter excludes cases.")
    parser.add_argument("-o", "--output-dir", type=Path, required=True, help="New output directory.")
    parser.add_argument("--prices", type=Path,
                        help="Price every run using JSON rates per million tokens, keyed by public model label.")
    parser.add_argument("--cost-note", default=costs.DEFAULT_COST_NOTE, help="Public explanation of estimated costs.")
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = argument_parser()
    args = parser.parse_args(argv)
    try:
        export_results(args.run, args.output_dir, title=args.title, epoch=args.epoch, prices=args.prices,
                       cost_note=args.cost_note, language=args.language)
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


def _sample_rows(
    run: str, condition: str, samples: Iterable[Any], log: Any,
    *, benchmark: str, scanner_settings: Mapping[str, Any],
) -> list[Row]:
    reporter = REPORTERS[benchmark]
    scorer = reporter.SCORER
    prefix = f"{reporter.SAMPLE_PREFIX}/{condition}/"
    rows: list[Row] = []
    epochs = log.eval.config.epochs or 1
    seen: set[tuple[str, int]] = set()
    for sample in samples:
        case_id = str(sample.id).removeprefix(prefix)
        try:
            if case_id == str(sample.id) or not 1 <= sample.epoch <= epochs:
                raise ValueError
            language = reporter.case_language(case_id)
        except ValueError:
            raise ExportError("A sample has an unsupported case ID or epoch.") from None
        identity = (case_id, sample.epoch)
        if identity in seen:
            raise ExportError("The selected log contains duplicate case/epoch pairs.")
        seen.add(identity)
        limit = sample.limit.type if isinstance(sample.limit, EvalSampleLimit) else sample.limit
        if limit is not None and limit not in LIMITS:
            raise ExportError("A sample has an unsupported limit type.")
        scores = sample.scores or {}
        if scores and set(scores) != {scorer}:
            raise ExportError(f"Unsupported sample scorer; expected {scorer}.")
        score = scores.get(scorer)
        if score is None and sample.error is None:
            raise ExportError("A sample is missing its expected scorer.")
        values = score.value if score is not None else {}
        if not isinstance(values, dict):
            raise ExportError("The sample score must contain named metrics.")
        metadata = (score.metadata or {}) if score is not None else {}
        if score is not None:
            if metadata.get("case_id") != case_id or metadata.get("condition") != condition:
                raise ExportError("Sample score identity does not match the saved example.")
            cwe = metadata.get("cwe")
            if not isinstance(cwe, str) or re.fullmatch(r"CWE-[0-9]+", cwe) is None:
                raise ExportError("Sample score has unsupported CWE metadata.")
        metrics = {key: number(values.get(name)) for key, name in reporter.METRICS.items()}
        count = metrics["findings"]
        if count != "":
            findings = metadata.get("findings")
            if (sample.error is not None or not isinstance(findings, list)
                    or any(not isinstance(finding, dict) for finding in findings)
                    or metrics["flagged_output"] not in ("", int(count > 0))):
                raise ExportError("Sample finding metrics do not match its saved findings.")
        metrics = reporter.sample_metrics(sample, metrics, scanner_settings)
        rows.append(
            {
                "run": run,
                "case_id": case_id,
                "language": language,
                "cwe": metadata.get("cwe", ""),
                "epoch": sample.epoch,
                "error": int(sample.error is not None),
                "limit": limit or "",
                "recorded_tokens": number(costs.tokens(sample.model_usage)),
                "recorded_cost_usd": costs.recorded_cost(sample.model_usage, log.eval.packages.get("inspect_ai")),
                "_usage": sample.model_usage,
                **metrics,
            }
        )
    if not rows or len(rows) != log.results.total_samples:
        raise ExportError("The final log does not contain its full sample inventory.")
    if len(seen) != len({case for case, _ in seen}) * epochs:
        raise ExportError("Every selected case must have a recorded attempt in every epoch.")
    return sorted(rows, key=lambda row: (row["epoch"], row["case_id"]))


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
    """Intersect comparable cases using the selected benchmark's eligibility rule."""
    if not runs:
        return set()
    reporter = REPORTERS[runs[0]["benchmark"]]
    scanned = {row["run"]: set() for row in runs}
    for sample in samples:
        if sample["run"] in scanned and reporter.eligible(sample):
            scanned[sample["run"]].add(sample["case_id"])
    return set.intersection(*scanned.values())


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


def comparison_note(results: Sequence[Row]) -> str:
    differ, missing = setting_notes(results)
    if differ == ["harness version"] and not missing:
        return "The runs used different harness versions; other recorded settings match."
    notes = []
    if differ:
        notes.append(f"settings differ for {report.listed(differ)}")
    if missing:
        notes.append(f"not recorded: {report.listed(missing)}")
    return "> **Check before comparing:** " + "; ".join(notes) + "." if notes else ""


def public_results(results: Sequence[Row], samples: Sequence[Row], *,
                   epoch: int | None = None) -> list[Row]:
    """Compute each shared cohort once and return only public summary columns."""
    exported = []
    epochs = [epoch] if epoch is not None else sorted({sample["epoch"] for sample in samples})
    for selected_epoch in epochs:
        selected = [sample for sample in samples if sample["epoch"] == selected_epoch]
        for runs in by_model([row for row in results if row["epochs"] >= selected_epoch]).values():
            reporter = REPORTERS[runs[0]["benchmark"]]
            shared = shared_cases(runs, selected)
            for row in runs:
                own = [sample for sample in selected if sample["run"] == row["run"]]
                scanned = [sample for sample in own if sample["case_id"] in shared]
                records, whole_run = costs.usage_records(row, own, selected_epoch)
                token_counts = [record["recorded_tokens"] for record in records]
                tokens = sum(token_counts) if token_counts and "" not in token_counts else ""
                cost = row["recorded_cost_usd"] if whole_run else total(own, "recorded_cost_usd")
                count = row["samples"] if whole_run else len(own)
                metrics = reporter.aggregate(own, scanned)
                flagged = sum(sample["findings"] > 0 for sample in scanned) if scanned else ""
                exported.append({
                    "run": row["run"], "epoch": selected_epoch, "model": row["model_label"],
                    "condition": row["condition"], "codeguard_version": row["codeguard_version"],
                    **{key: row[key] for key in ("skill_id", "skill_label", "skill_sha256")},
                    **{key: row[key] for key in LIMIT_FIELDS},
                    "cases": count, "shared_cases": len(shared),
                    "findings": total(scanned, "findings") if scanned else "",
                    "flagged_outputs": flagged,
                    "flagged_pct": 100 * flagged / len(scanned) if scanned else "",
                    "usage_missing_cases": sum(not sample["_usage"] for sample in own),
                    "tokens_per_case": tokens / count if tokens != "" and count else "",
                    "unfinished": sum(outcome(sample) != "Completed" for sample in own),
                    "recorded_cost_usd": cost, "estimated_cost_usd": "",
                    "cost_per_case_usd": "", "cost_change_pct": "",
                    **metrics,
                })
    costs.update_cost_columns(exported)
    return exported


def _public_samples(samples: Sequence[Row], *, benchmark: str) -> list[Row]:
    """Allowlist public results through the benchmark's schema."""
    reporter = REPORTERS[benchmark]
    return [
        {key: outcome(row) if key == "outcome" else row[key] for key in reporter.SAMPLE_FIELDS}
        for row in samples
    ]


if __name__ == "__main__":
    main()
