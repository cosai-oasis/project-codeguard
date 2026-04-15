"""Smoke tests — verify rules are exposed as skills and contain expected content."""

import shutil
import tempfile
from pathlib import Path

import pytest

from fastmcp.server.providers.skills import SkillsDirectoryProvider

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "sources" / "core"


@pytest.fixture(scope="module")
def skills_dir():
    """Build a skill-compatible directory from rule files, same as the server does."""
    root = Path(tempfile.mkdtemp(prefix="codeguard-test-skills-"))
    for md in sorted(RULES_DIR.glob("codeguard-*.md")):
        if "template" in md.name.lower():
            continue
        skill_dir = root / md.stem
        skill_dir.mkdir()
        shutil.copy2(md, skill_dir / "SKILL.md")
    yield root
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(scope="module")
def skill_contents(skills_dir):
    """Return a dict of {rule_id: SKILL.md content}."""
    return {
        d.name: (d / "SKILL.md").read_text(encoding="utf-8")
        for d in sorted(skills_dir.iterdir())
        if d.is_dir() and (d / "SKILL.md").exists()
    }


class TestSkillStructure:
    def test_creates_23_skills(self, skill_contents):
        assert len(skill_contents) == 23

    def test_every_skill_has_content(self, skill_contents):
        for rule_id, content in skill_contents.items():
            assert len(content) > 100, f"Skill {rule_id} content too short"


class TestHardcodedSecret:
    def test_covers_api_keys(self, skill_contents):
        content = skill_contents["codeguard-1-hardcoded-credentials"]
        assert "API key" in content or "API keys" in content
        assert "NEVER" in content

    def test_mentions_stripe(self, skill_contents):
        content = skill_contents["codeguard-1-hardcoded-credentials"]
        assert "sk_live_" in content


class TestSQLInjection:
    def test_covers_sql(self, skill_contents):
        content = skill_contents["codeguard-0-input-validation-injection"]
        assert "SQL" in content
        assert "parameterized" in content or "prepared statement" in content.lower()

    def test_applies_to_python(self, skill_contents):
        content = skill_contents["codeguard-0-input-validation-injection"]
        assert "python" in content.lower()


class TestWeakCrypto:
    def test_bans_md5(self, skill_contents):
        content = skill_contents["codeguard-1-crypto-algorithms"]
        assert "MD5" in content

    def test_recommends_aes_gcm(self, skill_contents):
        content = skill_contents["codeguard-1-crypto-algorithms"]
        assert "AES-GCM" in content or "AES_GCM" in content or "AES‑GCM" in content
