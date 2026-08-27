# CodeGuard Codex Plugin

## Overview

Project CodeGuard ships a `.codex-plugin/plugin.json` manifest so Codex can
install and update the `skills/codeguard` skill through its plugin marketplace.

The plugin intentionally packages only `./skills/`, even though Codex supports
multiple skill paths. It does not include `sources/skills/`, the
`codeguard-reviewer` custom agent, hooks, or an MCP server. See
[Choosing an Install Path](install-paths.md) for those routes.

## Installation

### Prerequisites

- [Codex CLI 0.142.0](https://github.com/openai/codex/releases/tag/rust-v0.142.0)
  or newer. Version 0.142.0 added support for marketplace plugins whose source
  is the repository root (`./`), which is the layout this repository uses.

!!! warning "Trust note"
    Plugins can provide skills, hooks, and MCP servers.
    Only install marketplaces and plugins from sources you trust.

### Installation steps

1. **Add the Project CodeGuard marketplace:**

   ```text
   codex plugin marketplace add cosai-oasis/project-codeguard
   ```

2. **Install the CodeGuard plugin from that marketplace:**

   ```text
   codex plugin add codeguard-security@project-codeguard
   ```

### Verifying the installed plugin

Confirm that Codex reports `codeguard-security` as installed and enabled:

```text
codex plugin list --marketplace project-codeguard
```

Start a new Codex session after installation so the refreshed skill catalog is
available to the model.

## Updating

```text
codex plugin marketplace upgrade project-codeguard
codex plugin list --marketplace project-codeguard
```

Use the second command to confirm the installed plugin's version and enabled
state, then start a new Codex session.

## Relationship to the other install routes

- [Claude Code Plugin](claude-code-skill-plugin.md) — the equivalent managed
  install for Claude Code.
- [Choosing an Install Path](install-paths.md) — rule files, Agent Skills, ZIP
  bundles, and MCP, including the routes that cover the reviewer agent and the
  `sources/skills/` content.
- [Skills](skills.md) — what the skill contains and how it activates.
