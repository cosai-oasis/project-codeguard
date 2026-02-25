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

from formats.base import BaseFormat, ProcessedRule

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


def truncate_description(description: str, max_length: int = OPENCODE_DESCRIPTION_MAX_LENGTH) -> str:
    """
    Ensure a description fits within OpenCode's length limit.

    Args:
        description: The description text
        max_length: Maximum allowed length (default: 1024)

    Returns:
        The description, truncated with ellipsis if necessary
    """
    if len(description) <= max_length:
        return description
    return description[: max_length - 3] + "..."


class OpenCodeFormat(BaseFormat):
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
    """

    def get_format_name(self) -> str:
        """Return OpenCode format identifier."""
        return "opencode"

    def get_file_extension(self) -> str:
        """Return OpenCode format file extension."""
        return ".md"

    def get_output_subpath(self) -> str:
        """Return OpenCode output subdirectory for rule files."""
        return ".opencode/skills/software-security/rules"

    def generate(self, rule: ProcessedRule, globs: str) -> str:
        """
        Generate OpenCode .md format with YAML frontmatter.

        Preserves the original YAML frontmatter (description, languages,
        alwaysApply) so rules remain complete and can be referenced by
        the AI coding agent, consistent with the Agent Skills format.

        Args:
            rule: The processed rule to format
            globs: Glob patterns (not used for OpenCode rule files)

        Returns:
            Complete markdown with original YAML frontmatter preserved
        """
        yaml_lines = []

        desc = self._format_yaml_field("description", rule.description)
        if desc:
            yaml_lines.append(desc)

        if rule.languages:
            yaml_lines.append("languages:")
            for lang in rule.languages:
                yaml_lines.append(f"- {lang}")

        yaml_lines.append(f"alwaysApply: {str(rule.always_apply).lower()}")

        return self._build_yaml_frontmatter(yaml_lines, rule.content)
