"""Language glob conversion contracts."""

import unittest

from language_mappings import (
    EXTENSION_TO_LANGUAGE,
    globs_to_languages,
    languages_to_globs,
)


class LanguageMappingsTests(unittest.TestCase):
    """Test language mappings behavior."""

    def test_reverse_mapping_preserves_first_language_for_shared_extensions(self):
        """Verify reverse mapping preserves first language for shared extensions."""
        self.assertEqual(EXTENSION_TO_LANGUAGE[".cpp"], "cpp")
        self.assertEqual(EXTENSION_TO_LANGUAGE[".py"], "python")

    def test_languages_to_globs_deduplicates_and_keeps_special_patterns(self):
        """Verify languages to globs deduplicates and keeps special patterns."""
        self.assertEqual(languages_to_globs([]), "")
        self.assertEqual(languages_to_globs(["unknown"]), "")
        self.assertEqual(languages_to_globs(["python", "python"]), "**/*.py,**/*.pyi,**/*.pyx")
        self.assertEqual(
            languages_to_globs(["docker"]),
            "**/*.dockerfile,Dockerfile*,docker-compose*",
        )

    def test_globs_to_languages_handles_universal_unknown_and_case(self):
        """Verify globs to languages handles universal unknown and case."""
        for pattern in ("", "**", "*", "**/*"):
            self.assertEqual(globs_to_languages(pattern), [])
        self.assertEqual(globs_to_languages("unknown"), [])
        self.assertEqual(globs_to_languages(" **/*.PY , **/*.JS "), ["javascript", "python"])


if __name__ == "__main__":
    unittest.main()
