"""
Codex Format Implementation

Generates .md rule files for OpenAI Codex. The SKILL.md is copied from
Agent Skills output (see convert_to_ide_formats.py); rule files are
generated identically to Agent Skills via inheritance.

Codex discovers skills by scanning for SKILL.md files in directory structures
like .codex/skills/<skill-name>/SKILL.md. Individual rule files live in a
rules/ subdirectory that the skill tool discovers at runtime.

See: https://developers.openai.com/codex/skills/
"""

from formats.agentskills import AgentSkillsFormat


class CodexFormat(AgentSkillsFormat):
    """
    Codex format implementation (.md rule files).

    OpenAI Codex (https://openai.com/codex) is an AI coding agent that
    discovers skills by scanning for SKILL.md files in specific directory
    structures. Each skill must live in its own named directory:

        .codex/skills/<skill-name>/SKILL.md

    Individual rule files are placed in a rules/ subdirectory:

        .codex/skills/<skill-name>/rules/<rule>.md

    The rule files preserve the original YAML frontmatter (description,
    languages, alwaysApply) so rules remain complete and can be referenced
    by the AI coding agent.

    Inherits generate() from AgentSkillsFormat since the rule file format
    is identical.
    """

    def get_format_name(self) -> str:
        return "codex"

    def get_output_subpath(self) -> str:
        return ".codex/skills/software-security/rules"
