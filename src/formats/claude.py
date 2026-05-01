"""Claude Code bundle format.

Emits rule files under ``.claude/skills/software-security/rules/`` so the
release bundle (``ide-rules-claude.zip``) ships the full skill alongside
the ``codeguard-reviewer`` subagent — parity with the per-host bundles
for OpenCode, Codex, OpenClaw, and Hermes. The Claude Code plugin remains
the recommended install path; this bundle is the drop-in-a-repo alternative.
"""

from formats.agentskills import AgentSkillsFormat


class ClaudeFormat(AgentSkillsFormat):
    """Claude Code bundle format (.md rule files under ``.claude/skills/``)."""

    def get_format_name(self) -> str:
        return "claude"

    def get_output_subpath(self) -> str:
        return ".claude/skills/software-security/rules"
