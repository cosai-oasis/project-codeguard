"""Smoke tests — verify the right rules surface for known-vulnerable patterns."""

from pathlib import Path

import pytest

from codeguard_mcp.rule_processor import RuleProcessor
from codeguard_mcp.tool_factory import RuleToolFactory

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sources" / "rules" / "core"


@pytest.fixture(scope="module")
def tools_by_name():
    processor = RuleProcessor(RULES_DIR)
    factory = RuleToolFactory()
    return {
        rule.rule_id.replace("-", "_"): factory.create_tool(rule)
        for rule in processor.get_all_rules()
    }


class TestHardcodedSecret:
    """Scenario: code contains `API_KEY = "sk_live_abc123..."`."""

    @pytest.mark.asyncio
    async def test_hardcoded_credentials_rule_covers_api_keys(self, tools_by_name):
        tool = tools_by_name["codeguard_1_hardcoded_credentials"]
        content = await tool.fn()
        assert "API key" in content or "API keys" in content
        assert "NEVER" in content

    @pytest.mark.asyncio
    async def test_hardcoded_credentials_mentions_stripe(self, tools_by_name):
        content = await tools_by_name["codeguard_1_hardcoded_credentials"].fn()
        assert "sk_live_" in content


class TestSQLInjection:
    """Scenario: code uses string concatenation in SQL query."""

    @pytest.mark.asyncio
    async def test_injection_rule_covers_sql(self, tools_by_name):
        tool = tools_by_name["codeguard_0_input_validation_injection"]
        content = await tool.fn()
        assert "SQL" in content
        assert "parameterized" in content or "prepared statement" in content.lower()

    @pytest.mark.asyncio
    async def test_injection_rule_applies_to_python(self, tools_by_name):
        content = await tools_by_name["codeguard_0_input_validation_injection"].fn()
        assert "python" in content.lower()


class TestWeakCrypto:
    """Scenario: code uses `hashlib.md5(password.encode())`."""

    @pytest.mark.asyncio
    async def test_crypto_rule_bans_md5(self, tools_by_name):
        tool = tools_by_name["codeguard_1_crypto_algorithms"]
        content = await tool.fn()
        assert "MD5" in content

    @pytest.mark.asyncio
    async def test_crypto_rule_recommends_aes_gcm(self, tools_by_name):
        content = await tools_by_name["codeguard_1_crypto_algorithms"].fn()
        assert "AES-GCM" in content or "AES_GCM" in content or "AES‑GCM" in content
