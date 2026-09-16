"""Devin Agent Skills format implementation.

Devin discovers repository skills from several Agent Skills locations,
including the product-specific ``.devin/skills/`` directory. This target
uses that directory so the Devin release bundle stays distinct from the
cross-tool ``.agents/skills/`` bundle.

See: https://docs.devin.ai/product-guides/skills
"""

from formats.agentskills import AgentSkillsFormat


class DevinFormat(AgentSkillsFormat):
    """Generate CodeGuard as a Devin-discoverable Agent Skill bundle."""

    def get_format_name(self) -> str:
        """Return the Devin format identifier."""
        return "devin"

    def get_output_subpath(self) -> str:
        """Return Devin's product-specific Agent Skills directory."""
        return ".devin/skills/codeguard/rules"
