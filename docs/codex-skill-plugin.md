# CodeGuard Codex Plugin

## Overview

This document explains how Project CodeGuard is packaged as a Codex plugin and
how to install and verify it.

Codex reads a plugin manifest from `.codex-plugin/plugin.json`. This repository
ships one alongside the existing Claude Code manifest, so the same
`skills/codeguard` skill can be installed and updated by Codex without copying
files by hand.

## Scope of the first version

The manifest packages skills only:

| Included | Not included |
| --- | --- |
| The `skills/codeguard` skill and its rules | The `codeguard-reviewer` agent |
| Version metadata kept in step with `pyproject.toml` | Bundled MCP servers (`mcpServers`) |
| | Hooks (`hooks`) |
| | The skills under `sources/skills/` |

Two reasons for that boundary:

- Codex's `skills` field takes a single path, unlike the Claude Code manifest
  which accepts a list. `./skills/` therefore resolves to the `codeguard`
  skill; `sources/skills/` is still available through the ZIP and rules
  install routes described in [Choosing an Install Path](install-paths.md).
- Agents, hooks, and MCP servers are separate distribution decisions. Adding
  them later is additive to this manifest and does not change how the skill is
  installed.

Users who need the reviewer agent or the MCP server should keep using the
existing routes; this plugin does not replace them.

## Installation

### Prerequisites

- [Codex CLI 0.142.0](https://github.com/openai/codex/releases/tag/rust-v0.142.0)
  or newer. Version 0.142.0 added support for marketplace plugins whose source
  is the repository root (`./`), which is the layout this repository uses.
- Basic familiarity with Codex's plugin and marketplace commands

!!! warning "Trust note"
    Plugins can provide skills, hooks, MCP servers, and executable components.
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

The repository's legacy-compatible marketplace entry declares the plugin at the
repository root, which is where `.codex-plugin/plugin.json` lives.

### Verifying the installed plugin

Confirm that Codex reports `codeguard-security` as installed and enabled:

```text
codex plugin list --marketplace project-codeguard
```

Start a new Codex session after installation so the refreshed skill catalog is
available to the model.

### Validating repository metadata

The commands below are maintainer checks for a source checkout; they do not
verify a user's installed plugin. From the repository root, inspect the manifest
version with:

```bash
python -c "import json; print(json.load(open('.codex-plugin/plugin.json'))['version'])"
```

To confirm the version matches every other place it is recorded:

```bash
python src/validate_versions.py "$(python -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])')"
```

That check covers `pyproject.toml`, both plugin manifests, the Claude Code
marketplace entry, and the skill front matter, so a release cannot ship with the
Codex manifest left behind.

## Updating

```text
codex plugin marketplace upgrade project-codeguard
codex plugin list --marketplace project-codeguard
```

The first command refreshes the configured Git marketplace snapshot; it is not
an initial install command. Restart Codex after refreshing, then use the second
command to confirm the installed plugin's version and enabled state.

The plugin version tracks the repository version. `sync_plugin_metadata()` in
the build writes it into this manifest along with the others, so published
plugin metadata stays aligned with the rules it packages.

## Relationship to the other install routes

- [Claude Code Plugin](claude-code-skill-plugin.md) — the equivalent managed
  install for Claude Code.
- [Choosing an Install Path](install-paths.md) — rule files, Agent Skills, ZIP
  bundles, and MCP, including the routes that cover the reviewer agent and the
  `sources/skills/` content.
- [Skills](skills.md) — what the skill contains and how it activates.
