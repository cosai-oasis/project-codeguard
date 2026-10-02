"""Per-host agent bundle generation and validation."""

# Direct checks of private helpers cover validation and escaping edge cases.
# pylint: disable=protected-access

import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

import emit_agents as agents
from artifact_targets import AgentHost, TomlAgentHost

AGENT_SOURCE = """---
name: Reviewer
description: Review security-sensitive code
---

# Reviewer

Read {RULES_DIR} files ending in {RULE_EXT}.
"""

MARKDOWN_HOST: dict[str, AgentHost] = {
    ".cursor": {
        "fm": {"model": "inherit"},
        "rules_dir": ".cursor/rules",
        "rule_ext": ".mdc",
        "filename": "{agent}.md",
    }
}
TOML_HOST: dict[str, TomlAgentHost] = {
    "codex": {
        "rules_dir": ".agents/skills/codeguard/rules",
        "rule_ext": ".md",
        "output_dir": ".codex/agents",
    }
}


class EmitAgentsTests(unittest.TestCase):
    """Test emit agents behavior."""

    def setUp(self):
        """Create isolated fixtures for each test."""
        temporary = tempfile.TemporaryDirectory(  # pylint: disable=consider-using-with
            prefix="codeguard-agents-"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = self.root / "sources" / "agents"
        self.output = self.root / "dist"

    def make_agent(self, content=AGENT_SOURCE, name="reviewer"):
        """Create agent fixture."""
        directory = self.sources / name
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "AGENT.md"
        path.write_text(content, encoding="utf-8")
        return path

    def make_host_rules(self):
        """Create host rules fixture."""
        for config in (*MARKDOWN_HOST.values(), *TOML_HOST.values()):
            (self.output / config["rules_dir"]).mkdir(parents=True, exist_ok=True)

    def test_emit_markdown_and_toml_agent_bundles(self):
        """Verify emit markdown and toml agent bundles."""
        self.make_agent()
        self.make_host_rules()

        agents.emit_agents(
            agents_source_dir=self.sources,
            output_dir=self.output,
            hosts=MARKDOWN_HOST,
            toml_hosts=TOML_HOST,
        )

        markdown = (self.output / ".cursor" / "agents" / "reviewer.md").read_text()
        self.assertIn("model: inherit", markdown)
        self.assertIn("Read .cursor/rules files ending in .mdc", markdown)
        toml = tomllib.loads((self.output / ".codex" / "agents" / "reviewer.toml").read_text())
        self.assertEqual(toml["name"], "Reviewer")
        self.assertIn(".agents/skills/codeguard/rules", toml["developer_instructions"])
        self.assertIn("ending in .md", toml["developer_instructions"])

    def test_missing_source_and_default_hosts_are_handled(self):
        """Verify missing source and default hosts are handled."""
        agents.emit_agents(agents_source_dir=self.sources, output_dir=self.output)
        self.make_agent()
        with (
            mock.patch.object(agents, "AGENT_HOSTS", {}),
            mock.patch.object(agents, "TOML_AGENT_HOSTS", {}),
        ):
            agents.emit_agents(agents_source_dir=self.sources, output_dir=self.output)

    def test_missing_agent_manifest_is_rejected(self):
        """Verify missing agent manifest is rejected."""
        (self.sources / "reviewer").mkdir(parents=True)
        with self.assertRaisesRegex(ValueError, "missing AGENT.md"):
            agents.emit_agents(
                agents_source_dir=self.sources,
                output_dir=self.output,
                hosts={},
                toml_hosts={},
            )

    def test_agent_source_requires_frontmatter_fields_and_placeholders(self):
        """Verify agent source requires frontmatter fields and placeholders."""
        invalid_sources = (
            ("No YAML", "missing or non-mapping"),
            (AGENT_SOURCE.replace("name: Reviewer\n", ""), "missing required key 'name'"),
            (
                AGENT_SOURCE.replace("description: Review security-sensitive code\n", ""),
                "missing required key 'description'",
            ),
            (AGENT_SOURCE.replace("name: Reviewer", "name: [Reviewer]"), "must be a string"),
            (
                AGENT_SOURCE.replace(
                    "description: Review security-sensitive code", "description: [Review]"
                ),
                "must be a string",
            ),
            (AGENT_SOURCE.replace("{RULES_DIR}", "rules"), "must reference"),
        )
        for source, message in invalid_sources:
            with self.subTest(message=message):
                path = self.make_agent(source)
                with self.assertRaisesRegex(ValueError, message):
                    agents._parse_agent_md(path)

    def test_merge_rejects_host_specific_key_collisions(self):
        """Verify merge rejects host specific key collisions."""
        with self.assertRaisesRegex(ValueError, "collides with host"):
            agents._merge_frontmatter(
                {"model": "custom"}, {"model": "inherit"}, "reviewer", ".cursor"
            )
        self.assertEqual(
            agents._merge_frontmatter(
                {"name": "Reviewer"}, {"model": "inherit"}, "reviewer", ".cursor"
            ),
            {"name": "Reviewer", "model": "inherit"},
        )

    def test_toml_helpers_reject_invalid_metadata_and_delimiter(self):
        """Verify toml helpers reject invalid metadata and delimiter."""
        self.assertEqual(
            agents._frontmatter_string({"name": "Reviewer"}, "name", "reviewer"), "Reviewer"
        )
        with self.assertRaisesRegex(ValueError, "must be a string"):
            agents._frontmatter_string({"name": ["Reviewer"]}, "name", "reviewer")
        self.assertEqual(agents._toml_string('Reviewer "one"'), '"Reviewer \\"one\\""')
        self.assertEqual(
            agents._toml_multiline_literal("Hello\n", agent="reviewer"), "'''\nHello\n'''"
        )
        with self.assertRaisesRegex(ValueError, "multiline literal terminator"):
            agents._toml_multiline_literal("bad ''' delimiter", agent="reviewer")

    def test_output_requires_a_preexisting_rules_directory(self):
        """Verify output requires a preexisting rules directory."""
        with self.assertRaisesRegex(FileNotFoundError, "rules_dir"):
            agents._require_rules_dir(
                output_base=self.output, host_name=".cursor", relative_path=".cursor/rules"
            )
        self.make_agent()
        with self.assertRaises(FileNotFoundError):
            agents.emit_agents(
                agents_source_dir=self.sources,
                output_dir=self.output,
                hosts=MARKDOWN_HOST,
                toml_hosts={},
            )
        (self.output / MARKDOWN_HOST[".cursor"]["rules_dir"]).mkdir(parents=True)
        with self.assertRaises(FileNotFoundError):
            agents.emit_agents(
                agents_source_dir=self.sources,
                output_dir=self.output,
                hosts=MARKDOWN_HOST,
                toml_hosts=TOML_HOST,
            )


if __name__ == "__main__":
    unittest.main()
