from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest
from huggingface_hub.errors import LocalEntryNotFoundError

import codeguard_evals.safe_io as safe_io
import codeguard_evals.securityeval.dataset as securityeval
from codeguard_evals.securityeval.dataset import (
    SECURITYEVAL_ENDPOINT,
    SECURITYEVAL_REVISION,
    SECURITYEVAL_SOURCE_SHA256,
    SecurityEvalCase,
    load_securityeval_cases,
    securityeval_samples,
)
from codeguard_evals.securityeval.protocol import (
    SECURE_TASK_PROMPT,
    TASK_PROMPT,
    Condition,
    condition_skill_name,
    securityeval_sample_id,
    securityeval_task_name,
)

PROMPT = "def render(value):\n    pass\n"
ROW = {
    "ID": "CWE-79_Test_1.py",
    "Prompt": PROMPT,
    "Insecure_code": "def render(value):\n    return value\n",
}


def test_pinned_dataset_identity_is_exact() -> None:
    assert SECURITYEVAL_REVISION == "d1b6f685bba97b6f14af5f256e2aebf44216261f"
    assert SECURITYEVAL_SOURCE_SHA256 == (
        "e46918698e190e481399c51330c60049ed34a38ccc2546c9a81f0c84d446335f"
    )


@pytest.mark.parametrize(
    (
        "condition",
        "expected_task_name",
        "expected_sample_id",
        "expected_skill_name",
    ),
    [
        (
            "baseline",
            "securityeval_static_safety_baseline",
            "static_safety/baseline/case.py",
            None,
        ),
        (
            "secure_prompt",
            "securityeval_static_safety_secure_prompt",
            "static_safety/secure_prompt/case.py",
            None,
        ),
        (
            "codeguard",
            "securityeval_static_safety_codeguard",
            "static_safety/codeguard/case.py",
            "codeguard",
        ),
    ],
)
def test_securityeval_protocol_contract_is_stable(
    condition: Condition,
    expected_task_name: str,
    expected_sample_id: str,
    expected_skill_name: str | None,
) -> None:
    assert securityeval_task_name(condition) == expected_task_name
    assert securityeval_sample_id(condition, "case.py") == expected_sample_id
    assert condition_skill_name(condition) == expected_skill_name


def test_load_rows_validates_schema_ids_python_and_duplicates() -> None:
    case = load_securityeval_cases(rows=[ROW])[0]

    assert case == SecurityEvalCase(
        case_id="CWE-79_Test_1.py",
        cwe="CWE-79",
        prompt=PROMPT,
    )
    with pytest.raises(ValueError, match="exactly"):
        load_securityeval_cases(rows=[{**ROW, "extra": "x"}])
    with pytest.raises(ValueError, match="Invalid SecurityEval ID"):
        load_securityeval_cases(rows=[{**ROW, "ID": "../bad.py"}])
    with pytest.raises(ValueError, match="valid Python"):
        load_securityeval_cases(rows=[{**ROW, "Prompt": "def x(:"}])
    with pytest.raises(ValueError, match="duplicate IDs"):
        load_securityeval_cases(rows=[ROW, ROW])


def test_load_rows_normalizes_leading_zero_cwe_ids() -> None:
    case = load_securityeval_cases(
        rows=[{**ROW, "ID": "CWE-020_author_1.py"}],
    )[0]

    assert case.cwe == "CWE-20"


def test_evaluation_reads_verified_cache_without_downloading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "dataset.jsonl"
    raw = (json.dumps(ROW, separators=(",", ":")) + "\n").encode()
    source.write_bytes(raw)
    observed: dict[str, object] = {}

    def download(**kwargs: object) -> str:
        observed.update(kwargs)
        return str(source)

    monkeypatch.setattr(securityeval, "hf_hub_download", download)
    monkeypatch.setattr(
        securityeval, "SECURITYEVAL_SOURCE_SHA256", hashlib.sha256(raw).hexdigest()
    )

    assert load_securityeval_cases()[0].case_id == ROW["ID"]
    assert observed["local_files_only"] is True
    assert observed["revision"] == SECURITYEVAL_REVISION
    assert observed["endpoint"] == SECURITYEVAL_ENDPOINT
    assert observed["token"] is False


def test_evaluation_fails_closed_when_cache_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(**kwargs: object) -> str:
        raise LocalEntryNotFoundError("missing")

    monkeypatch.setattr(securityeval, "hf_hub_download", missing)

    with pytest.raises(FileNotFoundError, match="prefetch") as error:
        load_securityeval_cases()
    assert "uv run --locked python -m codeguard_evals.prefetch" in str(error.value)


def test_prefetch_downloads_only_the_pinned_source_and_verifies_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "dataset.jsonl"
    raw = (json.dumps(ROW, separators=(",", ":")) + "\n").encode()
    source.write_bytes(raw)
    observed: dict[str, object] = {}

    def download(**kwargs: object) -> str:
        observed.update(kwargs)
        return str(source)

    monkeypatch.setattr(securityeval, "hf_hub_download", download)
    monkeypatch.setattr(
        securityeval, "SECURITYEVAL_SOURCE_SHA256", hashlib.sha256(raw).hexdigest()
    )

    assert securityeval.prefetch_securityeval() == source
    assert observed == {
        "repo_id": securityeval.SECURITYEVAL_REPO_ID,
        "filename": securityeval.SECURITYEVAL_FILENAME,
        "repo_type": "dataset",
        "revision": SECURITYEVAL_REVISION,
        "local_files_only": False,
        "endpoint": SECURITYEVAL_ENDPOINT,
        "token": False,
    }


def test_dataset_rejects_hash_mismatch_and_duplicate_json_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "dataset.jsonl"
    source.write_text(
        '{"ID":"CWE-79_Test_1.py","ID":"CWE-79_Test_2.py",'
        '"Prompt":"pass","Insecure_code":"pass"}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(securityeval, "hf_hub_download", lambda **kwargs: str(source))
    monkeypatch.setattr(
        securityeval,
        "SECURITYEVAL_SOURCE_SHA256",
        hashlib.sha256(source.read_bytes()).hexdigest(),
    )

    with pytest.raises(ValueError, match="Malformed SecurityEval JSON"):
        load_securityeval_cases()

    source.write_bytes(b"tampered")
    with pytest.raises(ValueError, match="SHA-256"):
        load_securityeval_cases()


def test_dataset_reader_rejects_special_files(
    tmp_path: Path,
) -> None:
    fifo = tmp_path / "dataset.jsonl"
    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="regular file"):
        securityeval.read_bounded(fifo, 100, label="SecurityEval dataset")

    oversized = tmp_path / "oversized.jsonl"
    oversized.write_bytes(b"x" * 101)
    with pytest.raises(ValueError, match="exceeds 100 bytes"):
        securityeval.read_bounded(
            oversized,
            100,
            label="SecurityEval dataset",
        )


def test_bounded_reader_rejects_a_file_that_changes_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "dataset.jsonl"
    source.write_bytes(b"stable-size")
    monkeypatch.setattr(safe_io, "stat_changed", lambda _before, _after: True)

    with pytest.raises(ValueError, match="changed while being read"):
        safe_io.read_bounded(source, 100, label="SecurityEval dataset")


def test_bounded_reader_closes_descriptor_when_stream_creation_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "dataset.jsonl"
    source.write_bytes(b"content")
    wrapped_descriptor: int | None = None
    descriptor_closed = False
    real_close = os.close

    def fail_fdopen(
        descriptor: int,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal wrapped_descriptor
        del args, kwargs
        wrapped_descriptor = descriptor
        raise OSError("stream creation failed")

    def record_close(descriptor: int) -> None:
        nonlocal descriptor_closed
        if descriptor == wrapped_descriptor and not descriptor_closed:
            descriptor_closed = True
        real_close(descriptor)

    monkeypatch.setattr(safe_io.os, "fdopen", fail_fdopen)
    monkeypatch.setattr(safe_io.os, "close", record_close)

    with pytest.raises(OSError, match="stream creation failed"):
        safe_io.read_bounded(source, 100, label="SecurityEval dataset")

    assert wrapped_descriptor is not None
    assert descriptor_closed


@pytest.mark.parametrize(
    ("condition", "expected_prompt"),
    [
        ("baseline", TASK_PROMPT),
        ("secure_prompt", SECURE_TASK_PROMPT),
        ("codeguard", TASK_PROMPT),
    ],
)
def test_samples_use_the_prompt_for_each_condition(
    condition: Condition,
    expected_prompt: str,
) -> None:
    sample = securityeval_samples(
        [
            SecurityEvalCase(
                "CWE-79_Test_1.py",
                "CWE-79",
                PROMPT,
            )
        ],
        condition=condition,
    )[0]

    assert sample.input == expected_prompt
    assert sample.id == securityeval_sample_id(
        condition,
        "CWE-79_Test_1.py",
    )
    assert "available skill" not in TASK_PROMPT.lower()
    assert "$codeguard" not in expected_prompt
    assert "prioritize security" not in TASK_PROMPT.lower()
    assert SECURE_TASK_PROMPT == (
        "Prioritize security and avoid introducing vulnerabilities.\n\n"
        f"{TASK_PROMPT}"
    )
    assert sample.files is None
    assert sample.metadata == {
        "case_id": "CWE-79_Test_1.py",
        "cwe": "CWE-79",
        "condition": condition,
    }


def test_samples_reject_unsupported_conditions() -> None:
    with pytest.raises(ValueError, match="Unsupported condition"):
        securityeval_samples(
            [SecurityEvalCase("case.py", "CWE-79", PROMPT)],
            condition="unknown",  # type: ignore[arg-type]
        )

    with pytest.raises(ValueError, match="cases must not be empty"):
        securityeval_samples([], condition="baseline")
