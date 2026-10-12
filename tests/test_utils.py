"""YAML frontmatter, tag, and project-version helpers."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import utils


class UtilsTests(unittest.TestCase):
    """Test utils behavior."""

    def test_frontmatter_parser_accepts_valid_yaml(self):
        """Verify frontmatter parser accepts valid yaml."""
        frontmatter, body = utils.parse_frontmatter_and_content(
            "---\ndescription: Example\n---\n\n# Title\n"
        )
        self.assertEqual(frontmatter, {"description": "Example"})
        self.assertEqual(body, "# Title")

    def test_frontmatter_parser_rejects_missing_or_invalid_delimiters(self):
        """Verify frontmatter parser rejects missing or invalid delimiters."""
        for content in ("plain text", "---\ndescription: Example", "---\n: invalid\n---\nbody"):
            with self.subTest(content=content):
                self.assertEqual(utils.parse_frontmatter_and_content(content), (None, content))

    def test_tags_are_normalized_and_duplicate_free(self):
        """Verify tags are normalized and duplicate free."""
        self.assertEqual(
            utils.validate_tags(["Authentication", "authentication", "WEB"]),
            ["authentication", "web"],
        )

    def test_tags_reject_wrong_types_empty_values_and_whitespace(self):
        """Verify tags reject wrong types empty values and whitespace."""
        cases = (
            ("authentication", "must be a list"),
            ([], "cannot be empty"),
            ([1], "must be strings"),
            (["two words"], "whitespace"),
            ([""], "Empty tag"),
        )
        for value, message in cases:
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, message):
                utils.validate_tags(value, "codeguard-example.md")

    def test_version_reader_handles_success_and_all_errors(self):
        """Verify version reader handles success and all errors."""
        with tempfile.TemporaryDirectory() as directory:
            previous_directory = Path.cwd()
            os.chdir(directory)
            try:
                with self.assertRaises(FileNotFoundError):
                    utils.get_version_from_pyproject()

                project = Path("pyproject.toml")
                project.write_text('[project]\nversion = "1.5.0"\n', encoding="utf-8")
                self.assertEqual(utils.get_version_from_pyproject(), "1.5.0")

                project.write_text('[project]\nversion = " 1.5.0 "\n', encoding="utf-8")
                self.assertEqual(utils.get_version_from_pyproject(), "1.5.0")

                for text in ('[project]\nname = "example"\n', "[project]\nversion = 123\n"):
                    project.write_text(text, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "Version field not found"):
                        utils.get_version_from_pyproject()

                project.write_text("not = [valid TOML", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Invalid TOML syntax"):
                    utils.get_version_from_pyproject()

                with mock.patch.object(
                    utils.tomllib, "load", side_effect=RuntimeError("read failure")
                ):
                    with self.assertRaisesRegex(ValueError, "Unexpected error reading"):
                        utils.get_version_from_pyproject()
            finally:
                os.chdir(previous_directory)


if __name__ == "__main__":
    unittest.main()
