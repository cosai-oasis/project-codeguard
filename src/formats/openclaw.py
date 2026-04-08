"""
OpenClaw Format Implementation

Generates .md rule files for OpenClaw. The SKILL.md is copied from
Agent Skills output (see convert_to_ide_formats.py); rule files are
generated identically to Agent Skills via inheritance.

OpenClaw discovers skills by scanning for SKILL.md files in directory structures
like .openclaw/skills/<skill-name>/SKILL.md. Individual rule files live in a
rules/ subdirectory that the skill tool discovers at runtime.

See: https://github.com/openclaw/openclaw
"""

from formats.agentskills import AgentSkillsFormat


class OpenClawFormat(AgentSkillsFormat):
    """
    OpenClaw format implementation (.md rule files).

    OpenClaw (https://github.com/openclaw/openclaw) is an AI assistant that
    discovers skills by scanning for SKILL.md files in specific directory
    structures. Each skill must live in its own named directory:

        .openclaw/skills/<skill-name>/SKILL.md

    Individual rule files are placed in a rules/ subdirectory:

        .openclaw/skills/<skill-name>/rules/<rule>.md

    The rule files preserve the original YAML frontmatter (description,
    languages, alwaysApply) so rules remain complete and can be referenced
    by the AI coding agent.

    Inherits generate() from AgentSkillsFormat since the rule file format
    is identical.
    """

    def get_format_name(self) -> str:
        return "openclaw"

    def get_output_subpath(self) -> str:
        return ".openclaw/skills/software-security/rules"
