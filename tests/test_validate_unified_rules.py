"""Validation of authored security rule frontmatter and CLI behavior."""

import contextlib
import io
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from rule_fixture import rule_text

import validate_unified_rules as rules


class ValidateUnifiedRulesTests(unittest.TestCase):
    """Test validate unified rules behavior."""

    def setUp(self):
        """Create isolated fixtures for each test."""
        temporary = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            prefix="codeguard-rules-"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def write_rule(self, content, name="codeguard-example.md"):
        """Create rule fixture."""
        rule = self.root / name
        rule.write_text(content, encoding="utf-8")
        return rule

    def test_valid_rule_and_unknown_language_warning(self):
        """Verify valid rule and unknown language warning."""
        rule = self.write_rule(rule_text())
        self.assertEqual(rules.validate_rule(rule), {"errors": [], "warnings": []})
        rule.write_text(rule_text(languages="[alien]"))
        result = rules.validate_rule(rule)
        self.assertEqual(result["errors"], [])
        self.assertIn("Unknown languages: alien", result["warnings"])

    def test_missing_or_invalid_frontmatter(self):
        """Verify missing or invalid frontmatter."""
        rule = self.write_rule("No YAML")
        self.assertIn("Missing or invalid YAML frontmatter", rules.validate_rule(rule)["errors"])

    def test_description_language_tags_and_body_errors(self):
        """Verify description language tags and body errors."""
        cases = (
            (rule_text().replace("description: Example\n", ""), "Missing required field"),
            (rule_text(description="''"), "description cannot be empty"),
            (rule_text(always_apply="true"), "should not have languages"),
            (rule_text(languages="[]"), "either languages or alwaysApply"),
            (rule_text(tags="[unknown-tag]"), "Unknown tags"),
            (rule_text(tags="[]"), "tags' list cannot be empty"),
            (rule_text(body=""), "Rule content cannot be empty"),
        )
        rule = self.write_rule("")
        for content, message in cases:
            with self.subTest(message=message):
                rule.write_text(content)
                self.assertTrue(
                    any(message in error for error in rules.validate_rule(rule)["errors"])
                )

    def test_file_read_errors_are_reported(self):
        """Verify file read errors are reported."""
        missing = self.root / "codeguard-missing.md"
        self.assertIn("Error reading file", rules.validate_rule(missing)["errors"][0])

    def test_cli_rejects_missing_directory_or_empty_rules(self):
        """Verify cli rejects missing directory or empty rules."""
        for directory, message in (
            (self.root / "missing", "does not exist"),
            (self.root, "No rule files found"),
        ):
            output = io.StringIO()
            with (
                mock.patch.object(sys, "argv", ["validate_unified_rules.py", str(directory)]),
                contextlib.redirect_stdout(output),
            ):
                with self.assertRaises(SystemExit) as error:
                    rules.main()
            self.assertEqual(error.exception.code, 1)
            self.assertIn(message, output.getvalue())

    def test_cli_reports_passes_warnings_and_failures(self):
        """Verify cli reports passes warnings and failures."""
        self.write_rule(rule_text())
        self.write_rule(rule_text(languages="[alien]"), "codeguard-warning.md")
        readme = self.root / "README.md"
        readme.write_text("Not a rule")
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["validate_unified_rules.py", str(self.root)]),
            contextlib.redirect_stdout(output),
        ):
            rules.main()
        self.assertIn("2 passed, 0 failed", output.getvalue())
        self.assertIn("Warnings: 1", output.getvalue())

        self.write_rule("No YAML", "codeguard-bad.md")
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["validate_unified_rules.py", str(self.root)]),
            contextlib.redirect_stdout(output),
        ):
            with self.assertRaises(SystemExit) as error:
                rules.main()
        self.assertEqual(error.exception.code, 1)
        self.assertIn("Validation failed", output.getvalue())

    def test_module_entry_point_and_default_sources_argument(self):
        """Verify module entry point and default sources argument."""
        with (
            mock.patch.object(sys, "argv", ["validate_unified_rules.py"]),
            mock.patch.object(rules, "Path", return_value=self.root / "missing"),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                rules.main()

        with (
            mock.patch.object(
                sys, "argv", ["validate_unified_rules.py", str(self.root / "missing")]
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                runpy.run_module("validate_unified_rules", run_name="__main__")


if __name__ == "__main__":
    unittest.main()
