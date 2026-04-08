"""
Hermes Format Implementation

Generates .md rule files for Hermes. The SKILL.md is copied from
Agent Skills output (see convert_to_ide_formats.py); rule files are
generated identically to Agent Skills via inheritance.

Hermes discovers skills by scanning for SKILL.md files in directory structures
like .hermes/skills/<skill-name>/SKILL.md. Individual rule files live in a
rules/ subdirectory that the skill tool discovers at runtime.

See: https://github.com/NousResearch/hermes-agent
"""

from formats.agentskills import AgentSkillsFormat


class HermesFormat(AgentSkillsFormat):
    """
    Hermes format implementation (.md rule files).

    Hermes (https://github.com/NousResearch/hermes-agent) is an AI coding
    agent by Nous Research that discovers skills by scanning for SKILL.md
    files in specific directory structures. Each skill must live in its own
    named directory:

        .hermes/skills/<skill-name>/SKILL.md

    Individual rule files are placed in a rules/ subdirectory:

        .hermes/skills/<skill-name>/rules/<rule>.md

    The rule files preserve the original YAML frontmatter (description,
    languages, alwaysApply) so rules remain complete and can be referenced
    by the AI coding agent.

    Inherits generate() from AgentSkillsFormat since the rule file format
    is identical.
    """

    def get_format_name(self) -> str:
        return "hermes"

    def get_output_subpath(self) -> str:
        return ".hermes/skills/software-security/rules"
