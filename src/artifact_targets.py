"""Per-host emission targets.

``SKILL_COPY_HOSTS``: hosts that get a copy of the generated SKILL.md.
``AGENT_HOSTS``: hosts that get a ``codeguard-reviewer`` subagent bundle.

Codex is absent from ``AGENT_HOSTS`` because its subagents use
``.codex/agents/*.toml`` (not Markdown), which needs a separate emitter.
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


# The agent reads rule bodies from ``rules_dir`` (which the converter has
# already populated for that host). ``rules_dir`` MUST NOT be under
# ``<host>/agents/`` — hosts scan that path for agent definitions.
AGENT_HOSTS: dict[str, AgentHost] = {
    ".claude": {
        "fm": {"skills": ["software-security"]},
        "rules_dir": ".claude/skills/software-security/rules",
        "rule_ext": ".md",
    },
    ".cursor": {
        "fm": {"model": "inherit"},
        "rules_dir": ".cursor/rules",
        "rule_ext": ".mdc",
    },
}
