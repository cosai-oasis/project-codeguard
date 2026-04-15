"""Tests for rule loading and parsing."""

from pathlib import Path

import pytest

from codeguard_mcp.rule_processor import RuleProcessor

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sources" / "core"


class TestRuleProcessor:
    def setup_method(self):
        self.processor = RuleProcessor(RULES_DIR)

    def test_loads_all_23_rules(self):
        rules = self.processor.get_all_rules()
        assert len(rules) == 23

    def test_every_rule_has_id_and_description(self):
        for rule in self.processor.get_all_rules():
            assert rule.rule_id, f"Missing rule_id for {rule.filename}"
            assert rule.description, f"Missing description for {rule.filename}"

    def test_every_rule_has_content(self):
        for rule in self.processor.get_all_rules():
            assert len(rule.content) > 100, (
                f"Rule {rule.rule_id} content too short ({len(rule.content)} chars)"
            )

    def test_always_apply_rules_have_no_languages(self):
        for rule in self.processor.get_all_rules():
            if rule.always_apply:
                assert rule.languages == [], (
                    f"{rule.rule_id}: always_apply rules must have empty languages"
                )

    def test_context_rules_have_languages(self):
        for rule in self.processor.get_all_rules():
            if not rule.always_apply:
                assert len(rule.languages) > 0, (
                    f"{rule.rule_id}: context rules must list languages"
                )

    def test_codeguard_1_rules_are_always_apply(self):
        rules = self.processor.get_all_rules()
        cg1 = [r for r in rules if r.rule_id.startswith("codeguard-1")]
        assert len(cg1) == 3
        for rule in cg1:
            assert rule.always_apply, f"{rule.rule_id} should be always_apply"

    def test_codeguard_0_rules_are_context_select(self):
        rules = self.processor.get_all_rules()
        cg0 = [r for r in rules if r.rule_id.startswith("codeguard-0")]
        assert len(cg0) == 20
        for rule in cg0:
            assert not rule.always_apply, f"{rule.rule_id} should not be always_apply"

    def test_missing_directory_returns_empty(self):
        proc = RuleProcessor("/nonexistent/path")
        assert proc.get_all_rules() == []

    def test_rule_id_is_filename_stem(self):
        for rule in self.processor.get_all_rules():
            expected = rule.filename.removesuffix(".md")
            assert rule.rule_id == expected
