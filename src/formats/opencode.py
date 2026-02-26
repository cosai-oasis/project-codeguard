"""
OpenCode Format Implementation

Generates .md rule files for OpenCode with YAML frontmatter,
and provides utilities for OpenCode-compliant SKILL.md generation.

OpenCode discovers skills by scanning for SKILL.md files in directory structures
like .opencode/skills/<skill-name>/SKILL.md, where the directory name must match
the `name` field in the SKILL.md YAML frontmatter.

See: https://opencode.ai/docs/skills/
"""

import re

from formats.agentskills import AgentSkillsFormat

OPENCODE_NAME_REGEX = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
OPENCODE_NAME_MAX_LENGTH = 64
OPENCODE_DESCRIPTION_MAX_LENGTH = 1024


def validate_opencode_name(name: str) -> str:
    """
    Validate an OpenCode skill name against the specification.

    Rules:
        - 1-64 characters
        - Lowercase alphanumeric with single hyphen separators
        - Cannot start or end with hyphen
        - No consecutive hyphens
        - Regex: ^[a-z0-9]+(-[a-z0-9]+)*$

    Args:
        name: The skill name to validate

    Returns:
        The validated name (unchanged)

    Raises:
        ValueError: If the name does not meet OpenCode requirements
    """
    if not name:
        raise ValueError("OpenCode skill name cannot be empty")

    if len(name) > OPENCODE_NAME_MAX_LENGTH:
        raise ValueError(
            f"OpenCode skill name must be 1-{OPENCODE_NAME_MAX_LENGTH} characters, "
            f"got {len(name)}"
        )

    if not OPENCODE_NAME_REGEX.match(name):
        raise ValueError(
            f"OpenCode skill name '{name}' is invalid. Must be lowercase "
            "alphanumeric with single hyphen separators (regex: "
            "^[a-z0-9]+(-[a-z0-9]+)*$)"
        )

    return name


def validate_opencode_description(description: str) -> str:
    """
    Validate an OpenCode skill description against the specification.

    Rules:
        - 1-1024 characters
        - Must not be empty or whitespace-only

    Args:
        description: The description text

    Returns:
        The validated description (unchanged)

    Raises:
        ValueError: If the description does not meet OpenCode requirements
    """
    if not description or not description.strip():
        raise ValueError("OpenCode skill description cannot be empty")

    if len(description) > OPENCODE_DESCRIPTION_MAX_LENGTH:
        raise ValueError(
            f"OpenCode skill description must be 1-{OPENCODE_DESCRIPTION_MAX_LENGTH} "
            f"characters, got {len(description)}"
        )

    return description


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
