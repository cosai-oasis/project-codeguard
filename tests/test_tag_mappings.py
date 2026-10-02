"""Known tag set used by rule validation."""

import unittest

from tag_mappings import KNOWN_TAGS


class TagMappingsTests(unittest.TestCase):
    """Test tag mappings behavior."""

    def test_known_rule_tags_are_available(self):
        """Verify known rule tags are available."""
        self.assertTrue({"authentication", "data-security", "web"} <= KNOWN_TAGS)


if __name__ == "__main__":
    unittest.main()
