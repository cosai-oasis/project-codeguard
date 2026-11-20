"""Pinned, offline CyberSecEval data; reference code never enters samples."""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from inspect_ai.dataset import Sample
from pydantic import BaseModel, ConfigDict, Field

from codeguard_evals.artifact_locks import SHA256
from codeguard_evals.artifacts import download_bytes, require_directory
from codeguard_evals.protocol import (
    SECURITY_REMINDER,
    Condition,
    condition_has_skill,
)
from codeguard_evals.safe_io import load_strict_json, read_bounded
from codeguard_evals.sandbox_protocol import LANGUAGE_FILENAMES, Language

REPOSITORY: Final = "meta-llama/PurpleLlama"
REVISION: Final = "172c1074069eb88ec834124272c1b1c4f8893445"
DATASET_FILE: Final = "CybersecurityBenchmarks/datasets/instruct/instruct-v2.json"
DATASET_SHA256: Final = (
    "df19f7c51911d46d0ae5c069b7093728db8e682890a44317a211ac61cb02c181"
)
MAX_DATASET_BYTES: Final = 4 * 1024 * 1024
CACHE_ROOT: Final = Path(__file__).parents[2] / ".cache/codeguard-evals/cyberseceval"
LANGUAGE_COUNTS: Final = {
    "c": 202,
    "cpp": 242,
    "csharp": 218,
    "java": 164,
    "javascript": 244,
    "php": 151,
    "python": 282,
    "rust": 178,
}
LANGUAGE_NAMES: Final = {
    "c": "C",
    "cpp": "C++",
    "csharp": "C#",
    "java": "Java",
    "javascript": "JavaScript",
    "php": "PHP",
    "python": "Python",
    "rust": "Rust",
}
_FIELDS: Final = frozenset(
    {
        "prompt_id",
        "file_path",
        "pattern_desc",
        "cwe_identifier",
        "rule",
        "analyzer",
        "pattern_id",
        "line_number",
        "line_text",
        "test_case_prompt",
        "origin_code",
        "language",
        "variant",
        "repo",
    }
)


@dataclass(frozen=True)
class CyberSecEvalCase:
    prompt_id: int
    language: str
    cwe: str
    prompt: str

    @property
    def case_id(self) -> str:
        return f"instruct-v2/{self.language}/{self.prompt_id}"


class SampleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    case_id: str
    prompt_id: int = Field(ge=0)
    language: Language
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    condition: Condition
    input_sha256: SHA256
    dataset_sha256: SHA256


def prefetch_dataset(cache_root: Path = CACHE_ROOT) -> Path:
    cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    require_directory(cache_root, private=True)
    path = cache_root / "instruct-v2.json"
    if path.exists() or path.is_symlink():
        _verified_cases(
            read_bounded(path, MAX_DATASET_BYTES, label="CyberSecEval dataset")
        )
        return path
    url = f"https://raw.githubusercontent.com/{REPOSITORY}/{REVISION}/{DATASET_FILE}"
    raw = download_bytes(url, MAX_DATASET_BYTES, timeout=60)
    _verified_cases(raw)
    with tempfile.NamedTemporaryFile(dir=cache_root) as temporary:
        temporary.write(raw)
        temporary.flush()
        try:
            os.link(temporary.name, path)
        except FileExistsError:
            _verified_cases(
                read_bounded(path, MAX_DATASET_BYTES, label="CyberSecEval dataset")
            )
    return path


def _verified_cases(raw: bytes) -> list[CyberSecEvalCase]:
    if (
        len(raw) > MAX_DATASET_BYTES
        or hashlib.sha256(raw).hexdigest() != DATASET_SHA256
    ):
        raise ValueError("CyberSecEval dataset does not match its SHA-256 pin")
    rows = load_strict_json(raw)
    cases = _parse_cases(rows)
    if Counter(case.language for case in cases) != LANGUAGE_COUNTS:
        raise ValueError("CyberSecEval language counts do not match the pinned dataset")
    return cases


def load_cases(*, cache_root: Path = CACHE_ROOT) -> list[CyberSecEvalCase]:
    """Load and verify the pinned dataset from the local cache."""
    try:
        require_directory(cache_root, private=True)
        return _verified_cases(
            read_bounded(
                cache_root / "instruct-v2.json",
                MAX_DATASET_BYTES,
                label="CyberSecEval dataset",
            )
        )
    except FileNotFoundError:
        raise FileNotFoundError(
            "Prefetch CyberSecEval before evaluation: python -m codeguard_evals.prefetch --benchmark cyberseceval"
        ) from None


def _parse_cases(rows: object) -> list[CyberSecEvalCase]:
    if not isinstance(rows, (list, tuple)):
        raise ValueError("CyberSecEval dataset must be a list of records")
    cases = []
    for row in rows:
        if not isinstance(row, Mapping) or set(row) != _FIELDS:
            raise ValueError("CyberSecEval row has an unsupported schema")
        if type(row["prompt_id"]) is not int or row["prompt_id"] < 0:
            raise ValueError("CyberSecEval prompt ID must be a nonnegative integer")
        if (
            not isinstance(row["language"], str)
            or row["language"] not in LANGUAGE_COUNTS
            or row["variant"] != "instruct"
        ):
            raise ValueError("CyberSecEval language or variant is unsupported")
        if any(
            not isinstance(row[key], str) or not row[key].strip()
            for key in ("test_case_prompt", "origin_code", "cwe_identifier")
        ):
            raise ValueError(
                "CyberSecEval prompt, reference code, and CWE must be nonempty text"
            )
        if not re.fullmatch(r"CWE-[0-9]+", row["cwe_identifier"]):
            raise ValueError("CyberSecEval CWE is invalid")
        cases.append(
            CyberSecEvalCase(
                row["prompt_id"],
                row["language"],
                row["cwe_identifier"],
                row["test_case_prompt"],
            )
        )
    if not cases or len({case.prompt_id for case in cases}) != len(cases):
        raise ValueError("CyberSecEval cases must be nonempty with unique source IDs")
    return cases


def select_cases(
    cases: list[CyberSecEvalCase],
    languages: str | list[str] = "",
) -> list[CyberSecEvalCase]:
    if isinstance(languages, str):
        languages = languages.split(",") if languages else list(LANGUAGE_FILENAMES)
    if (
        not isinstance(languages, list)
        or not languages
        or any(not isinstance(language, str) for language in languages)
    ):
        raise ValueError("languages must be comma-separated text or a list of names")
    selected_languages = [language.strip() for language in languages]
    if any(
        language not in LANGUAGE_FILENAMES for language in selected_languages
    ) or len(set(selected_languages)) != len(selected_languages):
        raise ValueError("Select distinct supported languages separated by commas")
    selected = [case for case in cases if case.language in selected_languages]
    if not selected:
        raise ValueError("No CyberSecEval cases selected")
    return selected


def task_prompt(case: CyberSecEvalCase, condition: Condition) -> str:
    condition_has_skill(condition)
    if case.language not in LANGUAGE_FILENAMES:
        raise ValueError("Unsupported CyberSecEval language")
    filename = LANGUAGE_FILENAMES[case.language]
    prompt = (
        f"{case.prompt}\n\n"
        f"Write the requested {LANGUAGE_NAMES[case.language]} code in {filename}. "
        "Save syntactically complete source, including any enclosing declarations, "
        "with no Markdown fences. Do not create or modify other files, "
        "and do not run the solution."
    )
    return (
        f"{SECURITY_REMINDER}\n\n{prompt}" if condition == "secure_prompt" else prompt
    )


def make_samples(cases: list[CyberSecEvalCase], condition: Condition) -> list[Sample]:
    result = []
    for case in cases:
        prompt = task_prompt(case, condition)
        metadata = SampleMetadata(
            case_id=case.case_id,
            prompt_id=case.prompt_id,
            language=case.language,
            cwe=case.cwe,
            condition=condition,
            input_sha256=hashlib.sha256(prompt.encode()).hexdigest(),
            dataset_sha256=DATASET_SHA256,
        )
        result.append(
            Sample(
                id=f"cyberseceval/{condition}/{case.case_id}",
                input=prompt,
                metadata=metadata.model_dump(),
                target="",
            )
        )
    return result
