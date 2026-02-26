"""
OpenCode Format Implementation

Generates .md rule files for OpenCode. The SKILL.md is copied from
Agent Skills output (see convert_to_ide_formats.py); rule files are
generated identically to Agent Skills via inheritance.

OpenCode discovers skills by scanning for SKILL.md files in directory structures
like .opencode/skills/<skill-name>/SKILL.md. Individual rule files live in a
rules/ subdirectory that the skill tool discovers at runtime.

See: https://opencode.ai/docs/skills/
"""

from formats.agentskills import AgentSkillsFormat


class OpenCodeFormat(AgentSkillsFormat):
    """
    OpenCode format implementation (.md rule files).

    OpenCode (https://opencode.ai/) is an open-source AI coding agent that
    discovers skills by scanning for SKILL.md files in specific directory
    structures. Each skill must live in its own named directory:

        .opencode/skills/<skill-name>/SKILL.md

    Individual rule files are placed in a rules/ subdirectory:

        .opencode/skills/<skill-name>/rules/<rule>.md

    The rule files preserve the original YAML frontmatter (description,
    languages, alwaysApply) so rules remain complete and can be referenced
    by the AI coding agent.

    Inherits generate() from AgentSkillsFormat since the rule file format
    is identical.
    """

    def get_format_name(self) -> str:
        return "opencode"

    def get_output_subpath(self) -> str:
        return ".opencode/skills/software-security/rules"
