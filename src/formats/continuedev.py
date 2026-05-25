"""
Continue.dev Format Implementation

Generates .md rule files for Continue.dev AI coding assistant.
"""

from formats.base import BaseFormat, ProcessedRule


class ContinueDevFormat(BaseFormat):
    """
    Continue.dev format implementation (.md rule files).

    Continue.dev uses .md files in a .continue/rules/ directory with YAML frontmatter containing:
    - name: Display name/title for the rule
    - globs: File matching patterns for conditional activation
    - alwaysApply: Whether the rule always loads
    - version: Rule version
    """

    def get_format_name(self) -> str:
        """Return Continue.dev format identifier."""
        return "continuedev"

    def get_file_extension(self) -> str:
        """Return Continue.dev format file extension."""
        return ".md"

    def get_output_subpath(self) -> str:
        """Return Continue.dev output subdirectory."""
        return ".continue/rules"

    def generate(self, rule: ProcessedRule, globs: str) -> str:
        """
        Generate Continue.dev .md format with YAML frontmatter.

        Args:
            rule: The processed rule to format
            globs: Glob patterns for file matching

        Returns:
            Formatted .md content
        """
        yaml_lines = []

        # Continue.dev uses 'name' instead of 'description'
        name = self._format_yaml_field("name", rule.description)
        if name:
            yaml_lines.append(name)

        # Glob-based activation or always-on
        if rule.always_apply:
            yaml_lines.append("alwaysApply: true")
        else:
            yaml_lines.append(f"globs: \"{globs}\"")

        # Add version
        yaml_lines.append(f"version: {self.version}")

        return self._build_yaml_frontmatter(yaml_lines, rule.content)
