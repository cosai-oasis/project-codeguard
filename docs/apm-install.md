# Installing with APM

[APM (Agent Package Manager)](https://github.com/microsoft/apm) provides an
**optional, additive** install path for the CodeGuard Agent Skill. Use it when
your team already uses APM for agent context, or when you want lockfile-pinned
skill installs across multiple harnesses.

APM does **not** replace pre-built rule ZIPs, the Claude Code plugin, or the
[CodeGuard MCP Server](mcp-server.md). Those paths remain the primary ways to
install glob-scoped security rules and centrally managed guidance. The APM
package ships the **CodeGuard Agent Skill only** — `SKILL.md` and its rule
bodies — to avoid duplicating the same guidance across formats.

This aligns with ongoing skill modernization tracked in
[#125](https://github.com/cosai-oasis/project-codeguard/issues/125).

## When to use APM

| Use APM when… | Use another path when… |
|:---|:---|
| You want the CodeGuard skill in multiple harnesses from one command | You need always-on, glob-scoped rule files |
| Your team already standardizes on `apm.yml` | APM CLI is unavailable in your environment |
| You want `apm.lock.yaml` integrity pins for the skill bundle | You want centrally managed live rules → use MCP |

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

# Install CodeGuard skill (pin a release tag in production)
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

After `apm install`, CodeGuard deploys the Agent Skill bundle:

| Primitive | Purpose |
|:---|:---|
| **Skill** (`codeguard/SKILL.md`) | On-demand security workflow with language/tag mappings |
| **Skill rules** (`codeguard/rules/`) | Full rule bodies referenced by the skill |

Example path after install:

- Shared skills: `.agents/skills/codeguard/SKILL.md` and `.agents/skills/codeguard/rules/`

Harness-specific skill directories may also receive copies depending on your
APM targets. The package does **not** deploy glob-scoped instruction files or
the CodeGuard reviewer agent — use [release ZIPs](getting-started.md#option-2-install-pre-built-rules)
for per-IDE rule files.

## Commit these files

After installing into a team repository, commit:

| Path | Commit? |
|:---|:---|
| `apm.yml` | Yes — declares the dependency |
| `apm.lock.yaml` | Yes — pins resolved versions and hashes |
| `.agents/skills/codeguard/` (and harness skill dirs) | Yes — gives every contributor the skill on clone |
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

Contributors regenerate the APM skill layout from unified sources:

```bash
uv run python src/convert_to_ide_formats.py
```

This writes:

- `.apm/skills/codeguard/` — skill bundle copied from `skills/codeguard/`
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
[release ZIP files](getting-started.md#option-2-install-pre-built-rules)
for your specific IDE. The underlying rules are identical.

## Further reading

- [APM documentation](https://microsoft.github.io/apm/)
- [Choosing an Install Path](install-paths.md)
- [Getting Started](getting-started.md)
