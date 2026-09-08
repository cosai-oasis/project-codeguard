"""Pinned, offline SecurityEval loading and Inspect sample construction."""

from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from huggingface_hub import hf_hub_download
from huggingface_hub.errors import LocalEntryNotFoundError
from inspect_ai.dataset import Sample

from codeguard_evals.safe_io import load_strict_json, read_bounded
from codeguard_evals.securityeval.protocol import (
    Condition,
    securityeval_case_cwe,
    securityeval_prompt,
    securityeval_sample_id,
)

SECURITYEVAL_REPO_ID: Final = "s2e-lab/SecurityEval"
SECURITYEVAL_FILENAME: Final = "dataset.jsonl"
SECURITYEVAL_ENDPOINT: Final = "https://huggingface.co"
SECURITYEVAL_REVISION: Final = "d1b6f685bba97b6f14af5f256e2aebf44216261f"
SECURITYEVAL_SOURCE_SHA256: Final = (
    "e46918698e190e481399c51330c60049ed34a38ccc2546c9a81f0c84d446335f"
)
SECURITYEVAL_MAX_BYTES: Final = 1024 * 1024
_REQUIRED_FIELDS: Final = frozenset({"ID", "Prompt", "Insecure_code"})


@dataclass(frozen=True)
class SecurityEvalCase:
    case_id: str
    cwe: str
    prompt: str


def prefetch_securityeval() -> Path:
    """Download and verify the one supported SecurityEval source revision."""
    path = _download_dataset(local_files_only=False)
    load_securityeval_cases(rows=_rows_from_path(path))
    return path


def load_securityeval_cases(
    *,
    rows: Iterable[Mapping[str, object]] | None = None,
) -> list[SecurityEvalCase]:
    """Load the pinned cases, or validate caller-supplied rows in tests.

    Row and CWE counts are not asserted: the caller verifies the source content
    hash, which fixes them exactly.
    """
    source = (
        _rows_from_path(_download_dataset(local_files_only=True))
        if rows is None
        else rows
    )
    cases = [_case_from_row(row) for row in source]
    if not cases:
        raise ValueError("SecurityEval dataset is empty")
    if len({case.case_id for case in cases}) != len(cases):
        raise ValueError("SecurityEval dataset contains duplicate IDs")
    return cases


def securityeval_samples(
    cases: Sequence[SecurityEvalCase],
    *,
    condition: Condition,
) -> list[Sample]:
    """Build samples for one internally consistent experiment condition."""
    if not cases:
        raise ValueError("cases must not be empty")
    prompt = securityeval_prompt(condition)
    samples: list[Sample] = []
    for case in cases:
        samples.append(
            Sample(
                id=securityeval_sample_id(condition, case.case_id),
                input=prompt,
                target=case.prompt,
                metadata={
                    "case_id": case.case_id,
                    "cwe": case.cwe,
                    "condition": condition,
                },
            )
        )
    return samples


def _download_dataset(*, local_files_only: bool) -> Path:
    try:
        path = Path(
            hf_hub_download(
                repo_id=SECURITYEVAL_REPO_ID,
                filename=SECURITYEVAL_FILENAME,
                repo_type="dataset",
                revision=SECURITYEVAL_REVISION,
                local_files_only=local_files_only,
                endpoint=SECURITYEVAL_ENDPOINT,
                token=False,
            )
        )
    except LocalEntryNotFoundError as exc:
        if not local_files_only:
            raise
        raise FileNotFoundError(
            "The verified SecurityEval dataset is not cached. Run "
            "`uv run --locked python -m codeguard_evals.prefetch` before "
            "evaluation."
        ) from exc
    if not path.exists():
        raise FileNotFoundError(f"SecurityEval source file is missing: {path}")
    return path


def _rows_from_path(path: Path) -> list[Mapping[str, object]]:
    raw = _read_source(path)
    if hashlib.sha256(raw).hexdigest() != SECURITYEVAL_SOURCE_SHA256:
        raise ValueError("SecurityEval source SHA-256 does not match the pinned dataset")

    rows: list[Mapping[str, object]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), 1):
        if not raw_line:
            raise ValueError(f"Empty SecurityEval line at line {line_number}")
        try:
            row = load_strict_json(raw_line)
        except ValueError as exc:
            raise ValueError(f"Malformed SecurityEval JSON at line {line_number}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"SecurityEval row {line_number} must be an object")
        rows.append(row)
    return rows


def _read_source(path: Path) -> bytes:
    # The HuggingFace cache stores blobs behind symlinks, so the path must be
    # resolved first. That makes read_bounded's O_NOFOLLOW inert here and only
    # its size bound useful; integrity comes from the SHA-256 pin in the caller.
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"Cannot safely open SecurityEval source: {path}") from exc
    try:
        return read_bounded(
            resolved,
            SECURITYEVAL_MAX_BYTES,
            label="SecurityEval source",
        )
    except OSError as exc:
        raise ValueError(f"Cannot safely open SecurityEval source: {path}") from exc


def _case_from_row(row: Mapping[str, object]) -> SecurityEvalCase:
    if set(row) != _REQUIRED_FIELDS:
        raise ValueError("SecurityEval rows must contain exactly ID, Prompt, and Insecure_code")
    case_id = _required_string(row, "ID")
    cwe = securityeval_case_cwe(case_id)
    prompt = _required_string(row, "Prompt")
    # Insecure_code is required for row-shape validation but is never evaluated;
    # only the prompt is handed to the agent.
    _required_string(row, "Insecure_code")
    _validate_python(prompt, case_id=case_id, field="prompt")
    return SecurityEvalCase(
        case_id=case_id,
        cwe=cwe,
        prompt=prompt,
    )


def _validate_python(source: str, *, case_id: str, field: str) -> None:
    try:
        ast.parse(source)
    except SyntaxError as exc:
        raise ValueError(
            f"SecurityEval {field} is not valid Python: {case_id}"
        ) from exc
    except (MemoryError, RecursionError) as exc:
        raise ValueError(f"SecurityEval {field} is too complex: {case_id}") from exc


def _required_string(row: Mapping[str, object], key: str) -> str:
    value = row[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"SecurityEval field {key} must be a non-empty string")
    return value
