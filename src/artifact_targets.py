"""Per-host emission targets.

``SKILL_COPY_HOSTS``: hosts that get a copy of the generated SKILL.md.
``AGENT_HOSTS``: hosts that get a Markdown ``codeguard-reviewer`` subagent bundle.
``TOML_AGENT_HOSTS``: hosts that get a TOML ``codeguard-reviewer`` subagent bundle.
"""

from __future__ import annotations

from typing import TypedDict


SKILL_COPY_HOSTS: list[str] = [
    ".claude",
    ".opencode",
    ".agents",  # Codex discovers skills under .agents/skills/ (cross-tool path)
    ".openclaw",
    ".hermes",
]


class AgentHost(TypedDict):
    fm: dict[str, object]
    rules_dir: str
    rule_ext: str
    filename: str


class TomlAgentHost(TypedDict):
    rules_dir: str
    rule_ext: str
    output_dir: str


# The agent reads rule bodies from ``rules_dir`` (which the converter has
# already populated for that host). ``rules_dir`` MUST NOT be under
# ``<host>/agents/`` — hosts scan that path for agent definitions.
AGENT_HOSTS: dict[str, AgentHost] = {
    ".claude": {
        "fm": {"skills": ["codeguard"]},
        "rules_dir": ".claude/skills/codeguard/rules",
        "rule_ext": ".md",
        "filename": "{agent}.md",
    },
    ".cursor": {
        "fm": {"model": "inherit"},
        "rules_dir": ".cursor/rules",
        "rule_ext": ".mdc",
        "filename": "{agent}.md",
    },
    ".opencode": {
        "fm": {
            "mode": "subagent",
            "permission": {
                "bash": "deny",
                "edit": {
                    "*": "deny",
                    "codeguard-findings-*.sarif": "ask",
                },
                "external_directory": "deny",
                "skill": "deny",
                "task": "deny",
                "webfetch": "deny",
                "websearch": "deny",
            },
        },
        "rules_dir": ".opencode/skills/codeguard/rules",
        "rule_ext": ".md",
        "filename": "{agent}.md",
    },
    ".github": {
        "fm": {"tools": ["read", "search", "edit/createFile"]},
        "rules_dir": ".github/instructions",
        "rule_ext": ".instructions.md",
        "filename": "{agent}.agent.md",
    },
}


TOML_AGENT_HOSTS: dict[str, TomlAgentHost] = {
    "codex": {
        "rules_dir": ".agents/skills/codeguard/rules",
        "rule_ext": ".md",
        "output_dir": ".codex/agents",
    },
}
