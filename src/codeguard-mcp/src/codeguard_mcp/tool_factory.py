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
            header = f"Rule ID: {rule.rule_id}\nDescription: {rule.description}"
            return f"{header}\n---\n{rule.content}"

        tool_name = rule.rule_id.replace("-", "_")
        tool = Tool.from_function(fn=_handler, name=tool_name, description=rule.description)
        logger.debug("Created tool: %s", tool_name)
        return tool
