"""Bundle target metadata shared by the converter and agent emitter."""

import unittest

from artifact_targets import AGENT_HOSTS, SKILL_COPY_HOSTS, TOML_AGENT_HOSTS


class ArtifactTargetsTests(unittest.TestCase):
    """Test artifact targets behavior."""

    def test_core_distribution_targets_exist(self):
        """Verify core distribution targets exist."""
        self.assertIn(".agents", SKILL_COPY_HOSTS)
        self.assertEqual(AGENT_HOSTS[".cursor"]["rule_ext"], ".mdc")
        self.assertEqual(TOML_AGENT_HOSTS["codex"]["output_dir"], ".codex/agents")


if __name__ == "__main__":
    unittest.main()
