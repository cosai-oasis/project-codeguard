"""
Windsurf Format Implementation

Generates .md files for Windsurf IDE with YAML frontmatter.
"""

from formats.base import BaseFormat, ProcessedRule


class WindsurfFormat(BaseFormat):
    """
    Windsurf IDE format implementation (.md files).

    Windsurf uses .md files with YAML frontmatter containing:
    - trigger: 'always_on' or 'glob'
    - globs: (if trigger is 'glob') File matching patterns
    - title: Rule title/description
    - version: Rule version
    """

    def get_format_name(self) -> str:
        """Return Windsurf format identifier."""
        return "windsurf"

    def get_file_extension(self) -> str:
        """Return Windsurf format file extension."""
        return ".md"

    def get_output_subpath(self) -> str:
        """Return Windsurf output subdirectory."""
        return ".windsurf/rules"

    def generate(self, rule: ProcessedRule, globs: str) -> str:
        """
        Generate Windsurf .md format with YAML frontmatter.

        Args:
            rule: The processed rule to format
            globs: Glob patterns for file matching

        Returns:
            Formatted .md content
        """
        yaml_lines = []

        # Use trigger: always_on for rules that should always apply
        if rule.always_apply:
            yaml_lines.append("trigger: always_on")
        else:
            yaml_lines.append("trigger: glob")
            yaml_lines.append(f"globs: {globs}")

        # Add title (Windsurf uses 'title' instead of 'description')
        title = self._format_yaml_field("title", rule.description)
        if title:
            yaml_lines.append(title)

        # Add version
        yaml_lines.append(f"version: {self.version}")

        return self._build_yaml_frontmatter(yaml_lines, rule.content)
