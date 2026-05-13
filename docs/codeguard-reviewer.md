# CodeGuard Reviewer

The CodeGuard Reviewer is a subagent that performs a full security scan of a repository against all CodeGuard rules and emits findings as a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) file. It is read-only on your source — the only file it writes is the SARIF output.

!!! warning "Use for explicit security scans only"
    The reviewer is designed for on-demand security scans, not continuous code generation. It activates when you explicitly ask for a security scan, security review, SARIF output, or CodeGuard compliance check. It does **not** activate for general code writing or editing.

## Supported Hosts

The CodeGuard Reviewer subagent is currently emitted for:

| Host | Agent file location |
|:-----|:-------------------|
| **Claude Code** | `.claude/agents/codeguard-reviewer.md` |
| **Cursor** | `.cursor/agents/codeguard-reviewer.md` |

## How to Invoke

=== "Claude Code"

    Ask Claude directly in your session:

    ```
    Run a CodeGuard security review of this repository
    ```

    Or request SARIF output explicitly:

    ```
    Perform a CodeGuard compliance check and emit SARIF output
    ```

=== "Cursor"

    In the Cursor chat panel:

    ```
    Run a security scan using the CodeGuard reviewer
    ```

## What It Does

The reviewer follows a five-step workflow:

**1. Detect languages**

Identifies languages present in the repository using file extensions and manifest files (`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle`, `composer.json`, `Gemfile`, etc.).

**2. Load rules**

Lists all `codeguard-*` rule files. Each rule's frontmatter declares applicability via `languages:` or `globs:`. Rules with neither field always apply; rules that don't match the repo's languages are skipped and noted as "not applicable".

**3. Search for violations**

For each applicable rule, searches the repository for candidate violations using patterns derived from the rule body (banned APIs, required configurations, example violations). The following paths are always excluded from search:

- Rule directories (`.claude/`, `.cursor/`, `.codex/`, `.agents/`, `.opencode/`, `.windsurf/`, `.github/instructions/`, `.openclaw/`, `.hermes/`)
- Vendored/generated paths (`.git/`, `node_modules/`, `vendor/`, `.venv/`, `venv/`, `dist/`, `build/`, `target/`)
- Any path excluded by `.gitignore`

**4. Triage findings**

Every candidate is classified as:

| Class | SARIF output | Description |
|:------|:------------|:------------|
| `confirmed` | Included | Actionable finding, re-verified at the exact line |
| `needs-human` | Included | Potential issue requiring human judgement |
| `false-positive` | Excluded | Discarded, with a one-line justification in the summary |

**5. Emit SARIF and summary**

Writes `codeguard-findings-<UTC_TIMESTAMP>.sarif` to the repository root (e.g. `codeguard-findings-20260420T183005Z.sarif`). Timestamps use ISO-8601 basic UTC format so fast reruns don't collide.

Returns a structured markdown summary containing:

- Counts by result class (`confirmed`, `needs-human`, `false-positive`)
- Rules checked vs. rules skipped (not applicable)
- Top 5 files by confirmed-finding count with `file:line` references
- One-line justification for each false-positive group discarded

## SARIF Output Format

The emitted SARIF 2.1.0 file follows this structure:

- `version`: `"2.1.0"`
- `tool.driver.name`: `"CodeGuard Security Reviewer"`
- `tool.driver.rules[]`: populated from the full rule set (id, shortDescription)
- `results[]`: one entry per `confirmed` or `needs-human` finding that survived re-verification

Each result includes:

| Field | Value |
|:------|:------|
| `ruleId` | Matches a `tool.driver.rules[].id` |
| `level` | `error` (confirmed `codeguard-1-*`), `warning` (confirmed `codeguard-0-*`), `note` (all `needs-human`) |
| `message.text` | Concrete, actionable description citing the rule |
| `locations[0].physicalLocation.artifactLocation.uri` | Repo-relative file path |
| `locations[0].physicalLocation.region.startLine` | 1-indexed line number |

## Constraints

- **Read-only** on repository source — the SARIF findings file is the only write
- Never executes code discovered in the target repository
- If the rule bundle is missing or empty, stops and reports the issue — does not fabricate rule content
- If the target repository is empty, still emits a valid SARIF run with an empty `results[]` array

## Next Steps

[Getting Started →](getting-started.md){ .md-button .md-button--primary }
[Choosing an Install Path →](install-paths.md){ .md-button }
