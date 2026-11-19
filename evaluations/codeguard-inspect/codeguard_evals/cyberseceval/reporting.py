"""CyberSecEval reporting from saved scores, without scanners or candidate source."""

import re
from collections import Counter
from collections.abc import Mapping, Sequence

from inspect_ai.log import EvalSample

from codeguard_evals import results_report as report
from codeguard_evals.cyberseceval.dataset import LANGUAGE_NAMES
from codeguard_evals.protocol import condition_has_skill
from codeguard_evals.results_common import (
    LIMIT_FIELDS, RUN_FIELDS, USAGE_FIELDS, ReportError, Row, total,
)
from codeguard_evals.sandbox_protocol import LANGUAGE_FILENAMES

SCORER = "cyberseceval_scorer"
SAMPLE_PREFIX = "cyberseceval"
LANGUAGES = LANGUAGE_NAMES
DEFAULT_TITLE = "CyberSecEval results"
METRICS = {
    "output_present": "output_present", "output_nonempty": "output_nonempty",
    "scan_complete": "scan_complete", "flagged_output": "icd_flagged_output",
    "findings": "icd_finding_count", "loc": "loc", "skill_loaded": "skill_loaded",
}
REASONS = {
    "missing_output": "Missing output", "empty_output": "Empty output",
    "parse_error": "Parse error", "rule_timeout": "Analysis timeout",
    "resource_limit": "Resource limit", "sample_error": "Sample error",
}
SEVERITY = (
    ("Error", "severity_error"),
    ("Warning", "severity_warning"),
    ("Info", "severity_info"),
    ("Advice", "severity_advice"),
)
SEVERITY_FIELDS = tuple(field for _, field in SEVERITY)
SEVERITY_NAMES = frozenset(label.lower() for label, _ in SEVERITY)
COVERAGE_FIELDS = tuple(f"scan_{reason}" for reason in REASONS)
RESULT_FIELDS = (
    *RUN_FIELDS, "language", *LIMIT_FIELDS,
    "cases", "scanned_cases", "shared_cases", "flagged_outputs", "flagged_pct",
    "findings", *SEVERITY_FIELDS, *COVERAGE_FIELDS, "skill_reads",
    *USAGE_FIELDS,
)
SAMPLE_FIELDS = (
    "run", "case_id", "epoch", "language", "cwe", "outcome", "limit", "error",
    "output_present", "output_nonempty", "scan_complete", "scan_reason",
    "flagged_output", "findings", *SEVERITY_FIELDS, "loc", "skill_loaded",
)


def recorded_scanner_settings(metadata: Mapping) -> dict:
    """Read saved scanner settings for comparison, without consulting current rules."""
    batch = metadata.get("batch_scan")
    if metadata.get("phase") != "scored" or not isinstance(batch, dict):
        raise ReportError("CyberSecEval requires a scored log with scanner provenance.")
    scanner = batch.get("grader")
    if not isinstance(scanner, dict):
        raise ReportError("The recorded scanner provenance has an unsupported format.")
    return {
        "version": scanner.get("semgrep_version"),
        "rules_sha256": scanner.get("rules_tree_sha256"),
        "image_digest": scanner.get("base_image_digest"),
        "identity": scanner,
    }


def case_language(case_id: str) -> str:
    match = re.fullmatch(r"instruct-v2/([a-z]+)/([0-9]+)", case_id)
    if match is None or match[1] not in LANGUAGE_FILENAMES:
        raise ValueError("Unsupported CyberSecEval case ID")
    return match[1]


def sample_metrics(sample: EvalSample, metrics: Row, scanner_settings: Mapping) -> Row:
    """Check CyberSecEval's scan states and count finding severities."""
    score = (sample.scores or {}).get(SCORER)
    if score is None:
        return {**metrics, **dict.fromkeys(SEVERITY_FIELDS, ""),
                "scan_complete": 0, "scan_reason": "sample_error"}
    # The shared loader has checked score identity, numeric values and finding structure.
    meta = score.metadata or {}
    if (meta.get("language") != case_language(meta["case_id"])
            or not scanner_settings["identity"] or meta.get("icd") != scanner_settings["identity"]):
        raise ReportError("CyberSecEval sample language or scanner settings do not match.")
    present, nonempty, complete = (metrics[k] for k in ("output_present", "output_nonempty", "scan_complete"))
    if (any(v not in (0, 1) for v in (present, nonempty, complete))
            or not complete <= nonempty <= present
            or (condition_has_skill(meta["condition"]) and metrics["skill_loaded"] not in (0, 1))):
        raise ReportError("CyberSecEval output and scan metrics are inconsistent.")
    reason = meta.get("scan_reason")
    findings = meta.get("findings")
    severities = dict.fromkeys(SEVERITY_FIELDS, "")
    if complete:
        if (reason is not None or metrics["findings"] == "" or metrics["flagged_output"] == ""
                or metrics["findings"] != len(findings)):
            raise ReportError("A complete CyberSecEval scan has inconsistent findings.")
        if any(finding.get("severity") not in SEVERITY_NAMES for finding in findings):
            raise ReportError("CyberSecEval findings require a recognized rule severity.")
        counts = Counter(finding["severity"] for finding in findings)
        severities = {field: counts[label.lower()] for label, field in SEVERITY}
    elif (reason not in REASONS or reason == "sample_error" or findings is not None
          or metrics["flagged_output"] != "" or metrics["findings"] != ""
          or (reason == "missing_output" and present != 0)
          or (reason == "empty_output" and (present != 1 or nonempty != 0))
          or (reason in ("parse_error", "rule_timeout", "resource_limit") and nonempty != 1)):
        raise ReportError("An incomplete CyberSecEval scan must remain unscored.")
    return {**metrics, **severities, "scan_reason": reason or ""}


def eligible(sample: Row) -> bool:
    return sample["scan_complete"] == 1 and not sample["error"]


def aggregate(own: Sequence[Row], scanned: Sequence[Row]) -> Row:
    """Summarise one run's scan coverage, skill reads and finding severities."""
    languages = {row["language"] for row in own}
    result = {
        "language": languages.pop() if len(languages) == 1 else "all",
        "scanned_cases": sum(row["scan_complete"] == 1 for row in own),
        "skill_reads": total(own, "skill_loaded"),
    }
    for reason in REASONS:
        result[f"scan_{reason}"] = sum(row["scan_reason"] == reason for row in own)
    for field in SEVERITY_FIELDS:
        result[field] = total(scanned, field) if scanned else ""
    return result


def _coverage_table(groups: report.Groups, heading: str) -> list[str]:
    lines = [f"{heading} Scan coverage", "",
             "All attempted examples are counted here. Files the scanner could not fully check have "
             "no finding score. Columns with no cases are omitted.", ""]
    for model, runs in groups.items():
        columns = [
            ("Condition", report.series_label),
            ("Complete scans", lambda row: report.share(row["scanned_cases"], row["cases"])),
            *[(label, lambda row, field=f"scan_{reason}": report.count(row[field]))
              for reason, label in REASONS.items() if any(row[f"scan_{reason}"] for row in runs)],
        ]
        if len(groups) > 1:
            lines += [f"{heading}# {model}", ""]
        lines += report.table(runs, columns)
    return lines


def _chart_text(name: str, multiple: bool, language: str | None = None) -> tuple[str, str]:
    usage_basis = "this epoch's recorded final attempts" if multiple else "recorded usage"
    title, note = {
        "findings": ("ICD findings against estimated total USD cost",
                     f"Findings use shared cases; costs use {usage_basis} and may be partial. Cost scales differ by model."),
        "outcomes": ("How each generation attempt ended",
                     "All attempted cases. Limit stops may still have saved code; scan coverage is reported separately."),
        "severity": ("Findings by rule severity",
                     "Shared cases only. Recorded severities are rule labels, not scanner failures or confirmed vulnerabilities."),
    }[name]
    label = LANGUAGES.get(language)
    return (f"{title} ({label})" if language else title), note


def report_definition(language: str | None = None) -> report.ReportDefinition:
    return report.ReportDefinition(
        result_fields=RESULT_FIELDS, sample_fields=SAMPLE_FIELDS,
        intro=(
            "Findings from Insecure Code Detector (ICD) rules are not confirmed vulnerabilities. "
            "[Evaluation Results](../index.md) explains how the evaluation works and its limits."
        ),
        chart_text=lambda name, multiple: _chart_text(name, multiple, language), detail_name="severity",
        finding_parts=SEVERITY,
        detail_table=_coverage_table,
        empty_note="No case was fully scanned in every selected run",
    )
