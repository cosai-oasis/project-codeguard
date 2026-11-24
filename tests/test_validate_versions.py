"""Check release version parsing against real YAML structure."""

import json
from pathlib import Path
import tempfile
import unittest

from src.validate_versions import get_skill_codeguard_version, validate_versions


class SkillVersionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="codeguard-version-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.skill = self.root / "skills/codeguard/SKILL.md"
        self.skill.parent.mkdir(parents=True)
        (self.root / "pyproject.toml").write_text(
            '[project]\nversion = "2.0.0"\n', encoding="utf-8"
        )
        for name in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"version": "2.0.0"}), encoding="utf-8")
        (self.root / ".claude-plugin/marketplace.json").write_text(
            json.dumps({"plugins": [{"version": "2.0.0"}]}), encoding="utf-8"
        )

    def write_skill(self, front_matter):
        self.skill.write_text(
            f"---\n{front_matter}\n---\n\n# CodeGuard\n", encoding="utf-8"
        )

    def test_release_validation_uses_actual_version_not_description_text(self):
        for description_version, actual_version in (
            ("2.0.0", "9.9.9"),
            ("9.9.9", "2.0.0"),
        ):
            with self.subTest(actual_version=actual_version):
                self.write_skill(
                    "name: codeguard\n"
                    "description: |\n"
                    "  Secure coding guidance.\n"
                    f'  codeguard-version: "{description_version}"\n'
                    "metadata:\n"
                    f'  codeguard-version: "{actual_version}"'
                )
                self.assertEqual(
                    get_skill_codeguard_version(self.root), actual_version
                )
                checks = validate_versions("2.0.0", self.root)
                self.assertEqual(
                    all(check.matches for check in checks), actual_version == "2.0.0"
                )
                self.assertTrue(all(check.matches for check in checks[:-1]))

    def test_nested_and_legacy_yaml_string_formats(self):
        for field, expected in (
            ('metadata:\n  codeguard-version: "2.0.0"', "2.0.0"),
            ("metadata:\n  codeguard-version: '2.0.0'", "2.0.0"),
            ("metadata: {codeguard-version: 2.0.0}", "2.0.0"),
            ('codeguard-version: "1.4.0"', "1.4.0"),
            ("codeguard-version: '1.4.0'", "1.4.0"),
            ("codeguard-version: 1.4.0", "1.4.0"),
        ):
            with self.subTest(field=field):
                self.write_skill("name: codeguard\n" + field)
                self.assertEqual(get_skill_codeguard_version(self.root), expected)

    def test_nested_version_takes_precedence_over_legacy(self):
        self.write_skill(
            'codeguard-version: "9.9.9"\n'
            'metadata:\n  codeguard-version: "2.0.0"'
        )
        self.assertEqual(get_skill_codeguard_version(self.root), "2.0.0")

    def test_legacy_fallback_when_metadata_has_no_version(self):
        self.write_skill(
            'codeguard-version: "1.4.0"\nmetadata:\n  framework: Project CodeGuard'
        )
        self.assertEqual(get_skill_codeguard_version(self.root), "1.4.0")

    def test_description_cannot_supply_a_missing_version(self):
        self.write_skill('description: |\n  codeguard-version: "2.0.0"')
        with self.assertRaises(ValueError):
            get_skill_codeguard_version(self.root)

    def test_invalid_yaml_or_non_mapping_front_matter_is_rejected(self):
        for front_matter in ("", "null", "plain text", "- item", "metadata: ["):
            with self.subTest(front_matter=front_matter):
                self.write_skill(front_matter)
                with self.assertRaises(ValueError):
                    get_skill_codeguard_version(self.root)

    def test_invalid_metadata_is_rejected_even_with_legacy_version(self):
        for value in ("null", "[]", "plain text", "true"):
            with self.subTest(value=value):
                self.write_skill(f'codeguard-version: "2.0.0"\nmetadata: {value}')
                with self.assertRaises(ValueError):
                    get_skill_codeguard_version(self.root)

    def test_invalid_version_values_are_rejected_without_fallback(self):
        for value in ('""', '"   "', "null", "2", "2.0", "true", "[]", "{}"):
            for nested in (False, True):
                with self.subTest(value=value, nested=nested):
                    field = f"codeguard-version: {value}"
                    if nested:
                        field = 'codeguard-version: "2.0.0"\nmetadata:\n  ' + field
                    self.write_skill(field)
                    with self.assertRaises(ValueError):
                        get_skill_codeguard_version(self.root)

    def test_missing_or_unterminated_front_matter_is_rejected(self):
        for text in ("# No front matter\n", '---\ncodeguard-version: "2.0.0"\n'):
            with self.subTest(text=text):
                self.skill.write_text(text, encoding="utf-8")
                with self.assertRaises(ValueError):
                    get_skill_codeguard_version(self.root)


if __name__ == "__main__":
    unittest.main()
