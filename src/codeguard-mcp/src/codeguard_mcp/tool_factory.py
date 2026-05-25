"""Create MCP Tool objects from ProcessedRule instances."""

from __future__ import annotations

import logging

from fastmcp.tools.tool import Tool

from codeguard_mcp.rule_processor import ProcessedRule

logger = logging.getLogger(__name__)


class RuleToolFactory:
    """Convert a ``ProcessedRule`` into a FastMCP ``Tool``."""

    def create_tool(self, rule: ProcessedRule) -> Tool:
        async def _handler() -> str:
            logger.debug("Tool invoked: %s", rule.rule_id)
            meta_parts = [
                f"Rule ID: {rule.rule_id}",
                f"Description: {rule.description}",
            ]
            if rule.languages:
                meta_parts.append(f"Languages: {', '.join(rule.languages)}")
            if rule.tags:
                meta_parts.append(f"Tags: {', '.join(rule.tags)}")
            header = "\n".join(meta_parts)
            return f"{header}\n---\n{rule.content}"

        tool_name = rule.rule_id.replace("-", "_")
        tool = Tool.from_function(fn=_handler, name=tool_name, description=rule.description)
        logger.debug("Created tool: %s", tool_name)
        return tool

    def create_search_tool(self, rules: list[ProcessedRule]) -> Tool:
        """Create a ``search_rules`` tool that filters the rule catalogue.

        Filters by language, tag, or free-text keyword.  All filters are
        optional and combined with AND logic.
        """

        async def _search(
            language: str | None = None,
            tag: str | None = None,
            keyword: str | None = None,
        ) -> str:
            """Search CodeGuard security rules by language, tag, or keyword.

            Args:
                language: Filter by programming language (e.g. 'python').
                tag: Filter by security domain tag (e.g. 'authentication').
                keyword: Free-text search across rule ID and description.

            Returns:
                A formatted list of matching rules with their metadata.
            """
            matches = rules

            if language:
                lang_lower = language.lower().strip()
                matches = [
                    r for r in matches
                    if r.always_apply or lang_lower in r.languages
                ]

            if tag:
                tag_lower = tag.lower().strip()
                matches = [r for r in matches if tag_lower in r.tags]

            if keyword:
                kw_lower = keyword.lower().strip()
                matches = [
                    r for r in matches
                    if kw_lower in r.rule_id.lower()
                    or kw_lower in r.description.lower()
                ]

            if not matches:
                return "No rules matched the given filters."

            lines = [f"Found {len(matches)} matching rule(s):\n"]
            for r in matches:
                langs = ", ".join(r.languages) if r.languages else "all"
                tags = ", ".join(r.tags) if r.tags else "none"
                lines.append(
                    f"- {r.rule_id}  [languages: {langs}]  [tags: {tags}]\n"
                    f"  {r.description.splitlines()[0]}"
                )
            return "\n".join(lines)

        return Tool.from_function(
            fn=_search,
            name="search_rules",
            description=(
                "Search and filter CodeGuard security rules by programming "
                "language, security domain tag, or free-text keyword. "
                "Returns a summary list of matching rules."
            ),
        )
