"""Shared report fields and validation for allowlisted public values."""

import math
import re
from collections.abc import Sequence

Row = dict[str, object]
SHA256 = r"[0-9a-f]{64}"
MODEL_LABEL = r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,59}"
TITLE = r"[A-Za-z0-9][A-Za-z0-9 .,:;()/+#-]{0,119}"
VERSION = r"[0-9]+(?:\.[0-9]+){1,3}[A-Za-z0-9.+-]*"
NOTE = r"[A-Za-z0-9][A-Za-z0-9 .,;:()/%+$-]{0,999}"
LIMIT_FIELDS = (
    "agent_turn_limit", "agent_seconds", "sample_seconds_limit", "agent_output_tokens",
)
RUN_FIELDS = ("run", "epoch", "model", "condition", "codeguard_version",
              "skill_id", "skill_label", "skill_sha256")
USAGE_FIELDS = (
    "usage_missing_cases", "tokens_per_case", "unfinished", "recorded_cost_usd", "estimated_cost_usd",
    "cost_per_case_usd", "cost_change_pct",
)


class ReportError(ValueError):
    """A validation error that is safe to display without private input values."""


def text(value: object, pattern: str) -> str:
    """Return an allowlisted text value; ``None`` becomes blank."""
    if value is None:
        return ""
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ReportError("An approved text field has an unsupported format.")
    return value


def number(value: object) -> int | float | str:
    """Return a finite, non-negative number; missing or NaN stays blank, not zero."""
    if value is None:
        return ""
    if type(value) not in (int, float):
        raise ReportError("An approved numeric field is not numeric.")
    if math.isnan(value):
        return ""
    if not math.isfinite(value) or value < 0:
        raise ReportError("An approved numeric field is out of range.")
    return value


def total(samples: Sequence[Row], key: str) -> object:
    """Keep an aggregate unknown if any contributing value is missing."""
    values = [sample[key] for sample in samples]
    return "" if "" in values else sum(values)
