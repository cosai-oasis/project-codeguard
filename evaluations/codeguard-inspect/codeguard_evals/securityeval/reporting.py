"""SecurityEval reporting policy for saved scores and recorded provenance."""

from collections.abc import Mapping, Sequence

from inspect_ai.log import EvalSample

from codeguard_evals import results_report as report
from codeguard_evals.results_common import (
    LIMIT_FIELDS, RUN_FIELDS, SHA256, USAGE_FIELDS, ReportError, Row, text, total,
)
from codeguard_evals.securityeval.protocol import (
    CHANGED_OUTPUT_METRIC, CONFIDENCE_HIGH_METRIC, CONFIDENCE_LOW_METRIC,
    CONFIDENCE_MEDIUM_METRIC, FINDING_COUNT_METRIC, SCORER_NAME,
    STATIC_SAFETY_SUITE, SUBCATEGORY_VULN_METRIC, VALID_OUTPUT_METRIC,
    securityeval_case_cwe,
)

SCORER = SCORER_NAME
SAMPLE_PREFIX = STATIC_SAFETY_SUITE
LANGUAGES = {"python": "Python"}
DEFAULT_TITLE = "SecurityEval results"
METRICS = {
    "changed_output": CHANGED_OUTPUT_METRIC, "valid_output": VALID_OUTPUT_METRIC,
    "findings": FINDING_COUNT_METRIC, "flagged_output": "semgrep_flagged_output",
    "likely_vulnerabilities": SUBCATEGORY_VULN_METRIC,
    "confidence_high": CONFIDENCE_HIGH_METRIC, "confidence_medium": CONFIDENCE_MEDIUM_METRIC,
    "confidence_low": CONFIDENCE_LOW_METRIC,
}
RESULT_FIELDS = (
    *RUN_FIELDS, *LIMIT_FIELDS,
    "cases", "shared_cases", "findings", "likely_vulnerabilities", *USAGE_FIELDS,
    "flagged_outputs", "flagged_pct",
    "confidence_high", "confidence_medium", "confidence_low",
)
SAMPLE_FIELDS = (
    "run", "case_id", "epoch", "outcome", "changed_output", "valid_output",
    "findings", "likely_vulnerabilities",
)
CONFIDENCE = (
    ("High", "confidence_high"),
    ("Medium", "confidence_medium"),
    ("Low", "confidence_low"),
)
INTRO = (
    "Findings are Semgrep scanner results, not confirmed vulnerabilities. "
    "[Evaluation Results](../index.md) explains how the evaluation works and its "
    "limits."
)


def recorded_scanner_settings(metadata: Mapping) -> dict:
    """Read saved scanner settings for comparison, without consulting current rules."""
    scanner = metadata.get("semgrep") or {}
    if not isinstance(scanner, dict):
        raise ReportError("The recorded scanner provenance has an unsupported format.")
    measured = scanner.get("measured_severities")
    if (not isinstance(measured, list) or not measured
            or any(not isinstance(severity, str) or not severity for severity in measured)):
        raise ReportError("SecurityEval measured severities are missing or invalid.")
    return {
        "measured_severities": frozenset(measured),
        "version": scanner.get("version"),
        "rules_sha256": scanner.get("rules_tree_sha256"),
        "image_digest": scanner.get("image_digest"),
        # Older logs lack this hash; report the full scanner setup as unknown.
        "identity": scanner if text(scanner.get("collector_sha256"), SHA256) else None,
    }


def case_language(case_id: str) -> str:
    securityeval_case_cwe(case_id)
    return "python"


def sample_metrics(sample: EvalSample, metrics: Row, scanner_settings: Mapping) -> Row:
    """Check SecurityEval's scanner settings and metric relationships."""
    if not sample.scores:
        return metrics
    metadata = sample.scores[SCORER].metadata or {}
    saved = recorded_scanner_settings(metadata)
    # Older scores record rule/image settings without a full execution identity.
    if any(scanner_settings[key] not in (None, "") and saved[key] != scanner_settings[key]
           for key in ("version", "rules_sha256", "image_digest", "measured_severities")):
        raise ReportError("SecurityEval sample scanner settings do not match the run.")
    if any(metrics[key] not in ("", 0, 1) for key in ("changed_output", "valid_output")):
        raise ReportError("SecurityEval output metrics are inconsistent.")
    count = metrics["findings"]
    confidence = [metrics[key] for _, key in CONFIDENCE]
    likely = metrics["likely_vulnerabilities"]
    if count != "":
        severities = [finding.get("severity") for finding in metadata["findings"]]
        if any(not isinstance(severity, str) or not severity for severity in severities):
            raise ReportError("SecurityEval saved findings require a severity.")
        # Use the policy recorded with these scores, not today's scoring policy.
        measured_count = sum(severity in saved["measured_severities"] for severity in severities)
        if (count != measured_count or ("" not in confidence and sum(confidence) != count)
                or (likely != "" and likely > count)):
            raise ReportError("SecurityEval finding metrics are inconsistent.")
    return metrics


def eligible(sample: Row) -> bool:
    return sample["changed_output"] == 1 and sample["valid_output"] == 1 and sample["findings"] != ""


def aggregate(own: Sequence[Row], scanned: Sequence[Row]) -> Row:
    fields = ("likely_vulnerabilities", *(key for _, key in CONFIDENCE))
    return {key: total(scanned, key) if scanned else "" for key in fields}


def _chart_text(name: str, multiple: bool) -> tuple[str, str]:
    """Keep each chart's reading note on the image so it can be shared alone."""
    if name == "findings":
        basis = "all cases in this epoch" if multiple else "all attempted cases and recorded retries"
        return (
            "Semgrep findings against estimated total USD cost",
            f"Findings use shared cases; total USD cost covers {basis}. Cost scales differ by model.",
        )
    if name == "outcomes":
        return ("How each attempt ended", "Attempts that hit a turn or time limit may have left the code unfinished.")
    return ("Findings by rule confidence", "Shared cases only. Rule confidence is not confirmation of a vulnerability.")


def report_definition(language: str | None = None) -> report.ReportDefinition:
    return report.ReportDefinition(
        result_fields=RESULT_FIELDS, sample_fields=SAMPLE_FIELDS, intro=INTRO,
        chart_text=_chart_text, detail_name="confidence",
        finding_parts=CONFIDENCE,
        empty_note="No case produced changed, valid code in every run",
    )
