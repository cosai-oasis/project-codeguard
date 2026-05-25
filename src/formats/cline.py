"""
Cline Format Implementation

Generates .md rule files for Cline AI coding agent.
"""

from formats.base import BaseFormat, ProcessedRule


class ClineFormat(BaseFormat):
    """
    Cline format implementation (.md rule files).

    Cline uses .md files in a .clinerules/ directory with YAML frontmatter containing:
    - description: Rule description
    - paths: List of glob patterns for conditional activation
    - alwaysApply: Whether the rule always loads
    - version: Rule version
    """

    def get_format_name(self) -> str:
        """Return Cline format identifier."""
        return "cline"

    def get_file_extension(self) -> str:
        """Return Cline format file extension."""
        return ".md"

    def get_output_subpath(self) -> str:
        """Return Cline output subdirectory."""
        return ".clinerules"

    def generate(self, rule: ProcessedRule, globs: str) -> str:
        """
        Generate Cline .md format with YAML frontmatter.

        Args:
            rule: The processed rule to format
            globs: Glob patterns for file matching

        Returns:
            Formatted .md content
        """
        yaml_lines = []

        # Add description
        desc = self._format_yaml_field("description", rule.description)
        if desc:
            yaml_lines.append(desc)

        # Cline uses 'paths' for conditional activation
        if rule.always_apply:
            yaml_lines.append("alwaysApply: true")
        else:
            # Convert comma-separated globs to YAML list of paths
            yaml_lines.append("paths:")
            for pattern in globs.split(","):
                pattern = pattern.strip()
                if pattern:
                    yaml_lines.append(f"- \"{pattern}\"")

        # Add version
        yaml_lines.append(f"version: {self.version}")

        return self._build_yaml_frontmatter(yaml_lines, rule.content)
