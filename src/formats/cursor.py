"""
Cursor Format Implementation

Generates .mdc files for Cursor IDE with YAML frontmatter.
"""

from formats.base import BaseFormat, ProcessedRule


class CursorFormat(BaseFormat):
    """
    Cursor IDE format implementation (.mdc files).

    Cursor uses .mdc files with YAML frontmatter containing:
    - description: Rule description
    - globs: File matching patterns
    - version: Rule version
    - alwaysApply: (optional) Whether to apply to all files
    """

    def get_format_name(self) -> str:
        """Return Cursor format identifier."""
        return "cursor"

    def get_file_extension(self) -> str:
        """Return Cursor format file extension."""
        return ".mdc"

    def get_output_subpath(self) -> str:
        """Return Cursor output subdirectory."""
        return ".cursor/rules"

    def generate(self, rule: ProcessedRule, globs: str) -> str:
        """
        Generate Cursor .mdc format with YAML frontmatter.

        Args:
            rule: The processed rule to format
            globs: Glob patterns for file matching

        Returns:
            Formatted .mdc content
        """
        yaml_lines = []

        # Add description if present
        desc = self._format_yaml_field("description", rule.description)
        if desc:
            yaml_lines.append(desc)

        # Add globs and version
        yaml_lines.append(f"globs: {globs}")
        yaml_lines.append(f"version: {self.version}")

        # Add alwaysApply if needed
        if rule.always_apply:
            yaml_lines.append("alwaysApply: true")

        return self._build_yaml_frontmatter(yaml_lines, rule.content)
