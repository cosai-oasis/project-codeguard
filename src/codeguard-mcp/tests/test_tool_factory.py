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

    @pytest.mark.asyncio
    async def test_tool_returns_language_metadata(self):
        rule = ProcessedRule(
            rule_id="codeguard-0-logging",
            description="Logging security",
            languages=["python", "java"],
            content="# Logging",
            filename="codeguard-0-logging.md",
            tags=["logging"],
        )
        tool = self.factory.create_tool(rule)
        result = await tool.fn()
        assert "Languages: python, java" in result
        assert "Tags: logging" in result


class TestSearchTool:

    def setup_method(self):
        self.factory = RuleToolFactory()
        self.rules = [
            ProcessedRule(
                rule_id="codeguard-1-hardcoded-credentials",
                description="No hardcoded creds",
                always_apply=True,
                content="# Creds",
                filename="codeguard-1-hardcoded-credentials.md",
                tags=["secrets"],
            ),
            ProcessedRule(
                rule_id="codeguard-0-input-validation-injection",
                description="Input validation and injection prevention",
                languages=["python", "java", "javascript"],
                content="# Injection",
                filename="codeguard-0-input-validation-injection.md",
                tags=["web", "input-validation"],
            ),
            ProcessedRule(
                rule_id="codeguard-0-authentication-mfa",
                description="Authentication and MFA best practices",
                languages=["python", "java"],
                content="# Auth",
                filename="codeguard-0-authentication-mfa.md",
                tags=["authentication", "web"],
            ),
        ]
        self.search_tool = self.factory.create_search_tool(self.rules)

    @pytest.mark.asyncio
    async def test_search_by_language(self):
        result = await self.search_tool.fn(language="javascript")
        assert "codeguard-0-input-validation-injection" in result
        # always_apply rules should also match
        assert "codeguard-1-hardcoded-credentials" in result
        # python/java only rule should not match
        assert "codeguard-0-authentication-mfa" not in result

    @pytest.mark.asyncio
    async def test_search_by_tag(self):
        result = await self.search_tool.fn(tag="secrets")
        assert "codeguard-1-hardcoded-credentials" in result
        assert "codeguard-0-input-validation-injection" not in result

    @pytest.mark.asyncio
    async def test_search_by_keyword(self):
        result = await self.search_tool.fn(keyword="injection")
        assert "codeguard-0-input-validation-injection" in result
        assert "codeguard-1-hardcoded-credentials" not in result

    @pytest.mark.asyncio
    async def test_search_combined_filters(self):
        result = await self.search_tool.fn(language="python", tag="web")
        assert "codeguard-0-input-validation-injection" in result
        assert "codeguard-0-authentication-mfa" in result
        # always_apply but no 'web' tag
        assert "codeguard-1-hardcoded-credentials" not in result

    @pytest.mark.asyncio
    async def test_search_no_matches(self):
        result = await self.search_tool.fn(tag="nonexistent-tag")
        assert "No rules matched" in result

    @pytest.mark.asyncio
    async def test_search_no_filters_returns_all(self):
        result = await self.search_tool.fn()
        assert "Found 3 matching rule(s)" in result
