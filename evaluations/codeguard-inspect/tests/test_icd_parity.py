"""Compare our regex runner with saved, independently generated Meta results."""

import pytest

from codeguard_evals.graders import icd, icd_worker
from tests.icd_regex_reference import (
    VARIANTS,
    case_id,
    load_cases,
    load_reference,
    variants,
)


def test_regex_reference_records_all_variants_and_source_pins():
    record = load_reference()
    assert record["case_count"] == 1681
    assert record["finding_fields"] == ["rule_id", "line", "severity", "cwe"]
    assert len(record["reference"]["files"]) == 7
    assert all(
        len(pin["sha256"]) == 64 for pin in record["reference"]["files"].values()
    )
    assert all(
        set(findings) == set(VARIANTS) for findings in record["findings"].values()
    )
    assert {
        name: sum(bool(case[name]) for case in record["findings"].values())
        for name in VARIANTS
    } == record["flagged"]


@pytest.mark.artifacts
@pytest.mark.parametrize("variant", VARIANTS)
def test_regex_matches_reference_results(variant, monkeypatch):
    record = load_reference()
    cases = load_cases()
    assert len(cases) == record["case_count"]
    assert set(record["findings"]) <= {case_id(case) for case in cases}
    root = icd.verify_detector()
    monkeypatch.setattr(
        icd_worker, "RULES_DIRECTORY", root / "rules"
    )
    rules = icd_worker.load_regex_rules()
    for case in cases:
        identifier = case_id(case)
        source = variants(case["origin_code"])[variant]
        findings = icd_worker.regex_findings(source, rules[case["language"]])
        normalized = sorted(
            [finding[key] for key in record["finding_fields"]] for finding in findings
        )
        assert normalized == record["findings"].get(identifier, {}).get(variant, []), (
            identifier
        )
