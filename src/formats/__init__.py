"""
Formats Package

This package contains all IDE format implementations for rule conversion.

Available Formats:
- CursorFormat: Generates .mdc files for Cursor IDE
- WindsurfFormat: Generates .md files for Windsurf IDE
- CopilotFormat: Generates .instructions.md files for GitHub Copilot
- AgentSkillsFormat: Generates .md files for Agent Skills (OpenAI Codex, Claude Code, other AI coding tools)
- AntigravityFormat: Generates .md files for Google Antigravity
- OpenCodeFormat: Generates .md files for OpenCode AI coding agent
- CodexFormat: Generates .md files for OpenAI Codex
- OpenClawFormat: Generates .md files for OpenClaw AI assistant
- HermesFormat: Generates .md files for Hermes AI coding agent
- ClaudeFormat: Generates .md files for Claude Code Agent Skills under .claude/

Usage:
    from formats import BaseFormat, ProcessedRule, CursorFormat, WindsurfFormat, CopilotFormat, AgentSkillsFormat, AntigravityFormat, OpenCodeFormat, CodexFormat, OpenClawFormat, HermesFormat, ClaudeFormat

    version = "1.0.0"
    formats = [
        CursorFormat(version),
        WindsurfFormat(version),
        CopilotFormat(version),
        AgentSkillsFormat(version),
        AntigravityFormat(version),
        OpenCodeFormat(version),
        CodexFormat(version),
        OpenClawFormat(version),
        HermesFormat(version),
        ClaudeFormat(version),
    ]
"""

from formats.base import BaseFormat, ProcessedRule
from formats.cursor import CursorFormat
from formats.windsurf import WindsurfFormat
from formats.copilot import CopilotFormat
from formats.agentskills import AgentSkillsFormat
from formats.antigravity import AntigravityFormat
from formats.opencode import OpenCodeFormat
from formats.codex import CodexFormat
from formats.openclaw import OpenClawFormat
from formats.hermes import HermesFormat
from formats.claude import ClaudeFormat

__all__ = [
    "BaseFormat",
    "ProcessedRule",
    "CursorFormat",
    "WindsurfFormat",
    "CopilotFormat",
    "AgentSkillsFormat",
    "AntigravityFormat",
    "OpenCodeFormat",
    "CodexFormat",
    "OpenClawFormat",
    "HermesFormat",
    "ClaudeFormat",
]
