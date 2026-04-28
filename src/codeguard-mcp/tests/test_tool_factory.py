"""Tests for MCP tool creation from rules."""

import pytest

from codeguard_mcp.rule_processor import ProcessedRule
from codeguard_mcp.tool_factory import RuleToolFactory


class TestToolFactory:
    def setup_method(self):
        self.factory = RuleToolFactory()

    def test_tool_name_uses_underscores(self):
        rule = ProcessedRule(
            rule_id="codeguard-1-hardcoded-credentials",
            description="No hardcoded creds",
            always_apply=True,
            content="# Rule content",
            filename="codeguard-1-hardcoded-credentials.md",
        )
        tool = self.factory.create_tool(rule)
        assert tool.name == "codeguard_1_hardcoded_credentials"

    def test_tool_has_description(self):
        rule = ProcessedRule(
            rule_id="codeguard-0-logging",
            description="Logging security",
            languages=["python", "java"],
            content="# Logging",
            filename="codeguard-0-logging.md",
        )
        tool = self.factory.create_tool(rule)
        assert tool.description == "Logging security"

    @pytest.mark.asyncio
    async def test_tool_returns_rule_content(self):
        rule = ProcessedRule(
            rule_id="codeguard-1-test",
            description="Test rule",
            always_apply=True,
            content="# Test\nDo the right thing.",
            filename="codeguard-1-test.md",
        )
        tool = self.factory.create_tool(rule)
        result = await tool.fn()
        assert "codeguard-1-test" in result
        assert "Do the right thing." in result
