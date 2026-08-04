# Installing with APM

[APM (Agent Package Manager)](https://github.com/microsoft/apm) is the
recommended way to install CodeGuard when your team uses more than one AI
coding harness, or when you want reproducible, lockfile-pinned agent context.

One command deploys CodeGuard rules, skills, and the reviewer agent to every
detected IDE — Cursor, GitHub Copilot, Claude Code, Windsurf, Codex, and
others — without downloading separate ZIP files per tool.

## Why APM instead of manual ZIP copy?

| Manual ZIP install | APM install |
|:---|:---|
| Pick the ZIP for your IDE | One package for all harnesses |
| Copy `.cursor/`, `.windsurf/`, etc. by hand | `apm install` writes the right paths |
| No lockfile or integrity pins | `apm.lock.yaml` pins content hashes |
| Hard to update across a team | `apm update` refreshes all targets |
| Each IDE needs its own release artifact | Same manifest everywhere |

APM does **not** replace the [CodeGuard MCP Server](mcp-server.md). Use MCP when
you want centrally managed, live rules without vendoring files into every repo.
Use APM when you want rules committed to the project with reproducible installs.

## Prerequisites

Install the APM CLI:

=== "macOS / Linux"

    ```bash
    curl -sSL https://aka.ms/apm-unix | sh
    apm --version
    ```

=== "Windows"

    ```powershell
    irm https://aka.ms/apm-windows | iex
    apm --version
    ```

See the [APM installation guide](https://microsoft.github.io/apm/) for
Homebrew, Scoop, and pip options.

## Quick start

From your project root:

```bash
# Initialize APM (skip if apm.yml already exists)
apm init my-project -y

# Install CodeGuard (pin a release tag in production)
apm install cosai-oasis/project-codeguard#v1.4.0
```

APM auto-detects harnesses from directories already present (for example
`.cursor/` or `.github/`). On a fresh repo with no harness markers yet, pass
explicit targets:

```bash
apm install cosai-oasis/project-codeguard#v1.4.0 \
  --target cursor,copilot,claude,windsurf,codex
```

## What gets installed

After `apm install`, CodeGuard deploys:

| Primitive | Purpose |
|:---|:---|
| **Instructions** (23 rules) | Glob-scoped security rules per harness |
| **Skill** (`codeguard/SKILL.md`) | Workflow skill with language/tag mappings |
| **Skill rules** (`codeguard/rules/`) | Full rule bodies for skill-based tools |
| **Agent** (`codeguard-reviewer`) | SARIF security review subagent |

Example paths after install:

- Cursor: `.cursor/rules/codeguard-*.mdc`
- Copilot: `.github/instructions/codeguard-*.instructions.md`
- Claude: `.claude/rules/codeguard-*.md`
- Shared skills: `.agents/skills/codeguard/`

## Commit these files

After installing into a team repository, commit:

| Path | Commit? |
|:---|:---|
| `apm.yml` | Yes — declares the dependency |
| `apm.lock.yaml` | Yes — pins resolved versions and hashes |
| `.cursor/`, `.github/`, `.claude/`, `.agents/`, etc. | Yes — gives every contributor instant access on clone |
| `apm_modules/` | No — rebuilt from the lockfile (APM adds this to `.gitignore`) |

## Updating CodeGuard

```bash
apm update cosai-oasis/project-codeguard
```

Or pin a new release explicitly:

```bash
apm install cosai-oasis/project-codeguard#v1.5.0
```

## Local development (this repository)

Contributors regenerate the APM package layout from unified sources:

```bash
uv run python src/convert_to_ide_formats.py
```

This writes:

- `.apm/instructions/` — APM instruction primitives
- `.apm/skills/codeguard/` — skill bundle
- `.apm/agents/codeguard-reviewer.agent.md` — reviewer agent
- `apm.yml` — package manifest (version synced from `pyproject.toml`)

Validate an install locally:

```bash
./scripts/validate_apm_install.sh
```

## Enterprise governance

Organizations can enforce allowed sources and audit installs with
[`apm-policy.yml`](https://microsoft.github.io/apm/enterprise/governance-guide/)
and CI gates via `apm audit --ci`. See the
[APM governance guide](https://microsoft.github.io/apm/enterprise/governance-guide/).

## Fallback: pre-built ZIP releases

If APM is not available in your environment, continue using the
[release ZIP files](getting-started.md#option-1-install-pre-built-rules-recommended)
for your specific IDE. The underlying rules are identical.

## Further reading

- [APM documentation](https://microsoft.github.io/apm/)
- [Choosing an Install Path](install-paths.md)
- [Getting Started](getting-started.md)
