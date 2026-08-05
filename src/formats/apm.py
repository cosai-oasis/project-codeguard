"""APM instruction format implementation.

Generates ``.instructions.md`` files for the Microsoft Agent Package Manager
(APM) canonical ``.apm/instructions/`` layout. APM deploys these to each
detected harness (Cursor, Copilot, Claude, Windsurf, etc.).
"""

from formats.base import BaseFormat, ProcessedRule


class ApmInstructionFormat(BaseFormat):
    """APM package instruction primitive (``.apm/instructions/*.instructions.md``).

    Uses the same ``applyTo`` frontmatter as GitHub Copilot instructions because
    APM's instruction transformer accepts that shape across targets.
    """

    def get_format_name(self) -> str:
        """Return APM format identifier."""
        return "apm"

    def get_file_extension(self) -> str:
        """Return APM instruction file extension."""
        return ".instructions.md"

    def get_output_subpath(self) -> str:
        """Return APM instructions output subdirectory."""
        return ".apm/instructions"

    def generate(self, rule: ProcessedRule, globs: str) -> str:
        """Generate an APM instruction file with YAML frontmatter.

        Args:
            rule: The processed rule to format.
            globs: Glob patterns for file matching.

        Returns:
            Formatted ``.instructions.md`` content.
        """
        yaml_lines = []

        apply_to = globs if globs else "**"
        yaml_lines.append(f"applyTo: '{apply_to}'")

        description = self._format_yaml_field("description", rule.description)
        if description:
            yaml_lines.append(description)

        yaml_lines.append(f"version: {self.version}")

        if rule.tags:
            tags_str = ", ".join(rule.tags)
            yaml_lines.append(f"tags: [{tags_str}]")

        content = self._build_yaml_frontmatter(yaml_lines, rule.content)
        return content
