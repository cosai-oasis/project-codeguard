# CodeGuard Claude Code Plugin

The Claude Code plugin includes CodeGuard and the [security-review and memory-safe-migration skills](skills.md).

## Install

With Claude Code installed, run these commands in your terminal:

```bash
claude plugin marketplace add cosai-oasis/project-codeguard
claude plugin install codeguard-security@project-codeguard
```

Start a new Claude Code session and use the skill with your task:

```text
/codeguard-security:codeguard Review this authentication code for security issues.
```

The [plugin manifest](https://github.com/cosai-oasis/project-codeguard/blob/main/.claude-plugin/plugin.json) registers `skills/` and `sources/skills/`.
