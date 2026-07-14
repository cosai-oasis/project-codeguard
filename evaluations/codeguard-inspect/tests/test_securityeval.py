from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import codeguard_evals.securityeval.dataset as securityeval
from codeguard_evals.python_output import MAX_PYTHON_SOURCE_BYTES, validate_output
from codeguard_evals.securityeval.dataset import (
    BANDIT_CASE_IDS,
    CONDITIONS,
    GENERIC_PREFIX,
    MAX_CODEGUARD_CONTEXT_BYTES,
    SECURITYEVAL_REVISION,
    SECURITYEVAL_SOURCE_SHA256,
    SYSTEM_PROMPT,
    SecurityEvalCase,
    bandit_securityeval_cases,
    load_securityeval_cases,
    securityeval_samples,
)

PROMPT = "def render(value):\n    pass\n"
ROW = {
    "ID": "CWE-79_Test_1.py",
    "Prompt": PROMPT,
    "Insecure_code": "def render(value):\n    return value\n",
}

SKILL = b"""# CodeGuard
- `codeguard-1-always.md`

| Language | Rule Files to Apply |
| --- | --- |
| python | codeguard-0-python.md |
"""
ALWAYS_RULE = "rules/codeguard-1-always.md"
PYTHON_RULE = "rules/codeguard-0-python.md"
OTHER_RULE = "rules/codeguard-0-other.md"


def _codeguard_snapshot() -> dict[str, bytes]:
    return {
        "SKILL.md": SKILL,
        ALWAYS_RULE: b"# Always\n",
        PYTHON_RULE: b"# Python\n",
        OTHER_RULE: b"# Other\n",
    }


def test_pinned_dataset_identity_is_exact() -> None:
    assert SECURITYEVAL_REVISION == "d1b6f685bba97b6f14af5f256e2aebf44216261f"
    assert SECURITYEVAL_SOURCE_SHA256 == (
        "e46918698e190e481399c51330c60049ed34a38ccc2546c9a81f0c84d446335f"
    )


def test_load_rows_validates_schema_ids_and_python() -> None:
    case = load_securityeval_cases(rows=[ROW], verify_canonical=False)[0]

    assert case == SecurityEvalCase(
        case_id="CWE-79_Test_1.py", cwe="CWE-79", prompt=PROMPT
    )

    with pytest.raises(ValueError, match="exactly"):
        load_securityeval_cases(rows=[{**ROW, "extra": "x"}], verify_canonical=False)
    with pytest.raises(ValueError, match="Invalid SecurityEval ID"):
        load_securityeval_cases(rows=[{**ROW, "ID": "../bad.py"}], verify_canonical=False)
    with pytest.raises(ValueError, match="valid Python"):
        load_securityeval_cases(rows=[{**ROW, "Prompt": "def x(:"}], verify_canonical=False)
    with pytest.raises(ValueError, match="duplicate IDs"):
        load_securityeval_cases(rows=[ROW, ROW], verify_canonical=False)


def test_load_rows_normalizes_leading_zero_cwe_ids() -> None:
    case = load_securityeval_cases(
        rows=[{**ROW, "ID": "CWE-020_author_1.py"}],
        verify_canonical=False,
    )[0]

    assert case.case_id == "CWE-020_author_1.py"
    assert case.cwe == "CWE-20"


def test_canonical_dataset_requires_exact_row_and_cwe_counts() -> None:
    rows = [
        {
            **ROW,
            "ID": f"CWE-{index % 69 + 1:03d}_test_{index + 1}.py",
        }
        for index in range(121)
    ]

    assert len(load_securityeval_cases(rows=rows)) == 121
    with pytest.raises(ValueError, match="121 rows"):
        load_securityeval_cases(rows=rows[:-1])
    one_cwe = [
        {**ROW, "ID": f"CWE-020_test_{index + 1}.py"}
        for index in range(121)
    ]
    with pytest.raises(ValueError, match="69 CWEs"):
        load_securityeval_cases(rows=one_cwe)


def test_bandit_subset_is_pinned_and_ordered() -> None:
    cases = [
        SecurityEvalCase(case_id, "CWE-1", "pass\n")
        for case_id in reversed(sorted(BANDIT_CASE_IDS))
    ]

    selected = bandit_securityeval_cases(cases)

    assert len(BANDIT_CASE_IDS) == 23
    assert selected == cases

    with pytest.raises(ValueError, match="missing the pinned Bandit subset"):
        bandit_securityeval_cases(cases[:-1])


def test_hugging_face_source_is_hashed_and_parsed_strictly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
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

    assert load_securityeval_cases(verify_canonical=False)[0].case_id == ROW["ID"]
    assert observed == {
        "repo_id": securityeval.SECURITYEVAL_REPO_ID,
        "filename": securityeval.SECURITYEVAL_FILENAME,
        "repo_type": "dataset",
        "revision": SECURITYEVAL_REVISION,
    }

    source.write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="SHA-256"):
        load_securityeval_cases(verify_canonical=False)


def test_hugging_face_loader_rejects_duplicate_json_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "dataset.jsonl"
    raw = b'{"ID":"CWE-79_Test_1.py","ID":"CWE-79_Test_2.py","Prompt":"pass","Insecure_code":"pass"}\n'
    source.write_bytes(raw)
    monkeypatch.setattr(securityeval, "hf_hub_download", lambda **kwargs: str(source))
    monkeypatch.setattr(
        securityeval, "SECURITYEVAL_SOURCE_SHA256", hashlib.sha256(raw).hexdigest()
    )

    with pytest.raises(ValueError, match="Malformed SecurityEval JSON"):
        load_securityeval_cases(verify_canonical=False)


def test_samples_add_codeguard_context_only_to_the_treatment() -> None:
    codeguard = _codeguard_snapshot()
    samples = securityeval_samples(
        [SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", PROMPT)],
        codeguard=codeguard,
    )

    assert [sample.metadata["condition"] for sample in samples] == list(CONDITIONS)
    for sample in samples:
        assert set(sample.metadata) == {"case_id", "cwe", "condition"}
        assert sample.files is None
        assert len(sample.input) == 2
        assert sample.input[0].role == "system"
        assert sample.input[1].role == "user"

    assert samples[0].input[0].text == SYSTEM_PROMPT
    assert samples[1].input[0].text == SYSTEM_PROMPT
    assert samples[2].input[0].text.endswith(SYSTEM_PROMPT)
    assert samples[0].input[1].text == PROMPT
    assert samples[1].input[1].text == GENERIC_PREFIX + PROMPT
    assert samples[2].input[1].text == PROMPT
    for path in {"SKILL.md", ALWAYS_RULE, PYTHON_RULE}:
        content = codeguard[path]
        assert f"--- {path} ---" in samples[2].input[0].text
        assert content.decode().strip() in samples[2].input[0].text
        assert path not in samples[0].input[0].text
        assert path not in samples[1].input[0].text
    assert OTHER_RULE not in samples[2].input[0].text


def test_samples_require_complete_utf8_codeguard_context() -> None:
    case = SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", PROMPT)

    with pytest.raises(ValueError, match="must not be empty"):
        securityeval_samples([case], codeguard={})

    missing = _codeguard_snapshot()
    del missing[PYTHON_RULE]
    with pytest.raises(ValueError, match="is missing"):
        securityeval_samples([case], codeguard=missing)

    invalid = _codeguard_snapshot()
    invalid[PYTHON_RULE] = b"\xff"
    with pytest.raises(ValueError, match="valid UTF-8"):
        securityeval_samples([case], codeguard=invalid)


def test_samples_reject_codeguard_routing_drift() -> None:
    case = SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", PROMPT)
    missing_row = _codeguard_snapshot()
    missing_row["SKILL.md"] = b"# CodeGuard\n- `codeguard-1-always.md`\n"
    with pytest.raises(ValueError, match="exactly one Python rule row"):
        securityeval_samples([case], codeguard=missing_row)

    missing_always_reference = _codeguard_snapshot()
    missing_always_reference["SKILL.md"] = SKILL.replace(
        b"- `codeguard-1-always.md`\n\n", b""
    )
    with pytest.raises(ValueError, match="every always-apply rule"):
        securityeval_samples([case], codeguard=missing_always_reference)


def test_samples_bound_codeguard_context() -> None:
    codeguard = _codeguard_snapshot()
    codeguard[PYTHON_RULE] = b"x" * MAX_CODEGUARD_CONTEXT_BYTES

    with pytest.raises(ValueError, match="context exceeds"):
        securityeval_samples(
            [SecurityEvalCase("CWE-79_Test_1.py", "CWE-79", PROMPT)],
            codeguard=codeguard,
        )


def test_output_validation_accepts_changed_valid_python() -> None:
    output = "def render(value):\n    return str(value)\n"
    result = validate_output(output, prompt=PROMPT, stop_reason="stop")

    assert result.valid
    assert result.reason is None
    assert result.text == output
    assert result.size_bytes == len(output.encode())
    assert result.sha256 == hashlib.sha256(output.encode()).hexdigest()


@pytest.mark.parametrize(
    ("output", "error"),
    [
        (None, "missing output"),
        ("   \n", "empty output"),
        (PROMPT, "unchanged"),
        (PROMPT + "# comment\n", "AST-equivalent"),
        ("value = 1\n", "requested interface"),
        ("def render():\n    return 'x'\n", "requested interface"),
        ("def render(:\n", "syntax error"),
        ("\udcff", "valid UTF-8"),
        ("x" * (MAX_PYTHON_SOURCE_BYTES + 1), "exceeds"),
        ("def render(value):\n    return " + "+" * 2_000 + "1\n", "too complex"),
    ],
)
def test_output_validation_rejects_invalid_outputs(
    output: str | None, error: str
) -> None:
    result = validate_output(output, prompt=PROMPT, stop_reason="stop")

    assert not result.valid
    assert error in result.reason


def test_output_validation_preserves_import_only_scaffolds() -> None:
    prompt = "import requests\n"
    accepted = validate_output(
        "import requests\nrequests.get('https://example.com', timeout=1)\n",
        prompt=prompt,
        stop_reason="stop",
    )
    rejected = validate_output(
        "value = 1\n",
        prompt=prompt,
        stop_reason="stop",
    )

    assert accepted.valid
    assert not rejected.valid
    assert rejected.reason == "output does not preserve the requested interface"


@pytest.mark.parametrize(
    ("prompt", "error"),
    [
        ("x" * (MAX_PYTHON_SOURCE_BYTES + 1), "prompt exceeds"),
        ("\udcff", "prompt must be valid UTF-8"),
    ],
)
def test_output_validation_rejects_unsafe_prompts(
    prompt: str, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        validate_output("pass\n", prompt=prompt, stop_reason="stop")


def test_generation_failure_is_unscored_even_with_valid_content() -> None:
    result = validate_output(
        "def render(value):\n    return str(value)\n",
        prompt=PROMPT,
        stop_reason="stop",
        generation_error="token limit exceeded",
    )

    assert not result.valid
    assert result.reason == "generation failed: token limit exceeded"


def test_generation_limit_is_unscored_even_with_valid_content() -> None:
    result = validate_output(
        "def render(value):\n    return str(value)\n",
        prompt=PROMPT,
        stop_reason="max_tokens",
    )

    assert not result.valid
    assert result.reason == "generation stopped with max_tokens"
