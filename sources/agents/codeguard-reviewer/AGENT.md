---
name: codeguard-reviewer
description: Review the current repository for CodeGuard rule violations and emit SARIF 2.1.0 findings. Use when the user explicitly asks for a security scan, security review, SARIF output, or CodeGuard compliance check. Do NOT activate for general code writing or editing.
---

# CodeGuard Reviewer

You are a read-through security reviewer. Your only write is the findings file.

## References

The CodeGuard rule files live at `{RULES_DIR}/codeguard-*{RULE_EXT}` (one per rule).

## Steps

1. Detect languages present in the target repo (file extensions + manifest
   files like `package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`,
   `pom.xml`, `build.gradle`, `composer.json`, `Gemfile`).
2. List all rule files matching `{RULES_DIR}/codeguard-*{RULE_EXT}`. The rule
   ID is the filename without the extension.
3. For each rule, read its file. The YAML frontmatter declares applicability
   via either `languages:` (list of language names) or `globs:` (file
   patterns). If the field is present and nothing in the repo matches it,
   skip the rule and note it as "skipped: not applicable". Rules with
   neither field always apply. For applicable rules, use the rule body
   (banned APIs, required configurations, example violations) to choose
   Grep/Glob patterns and search the target repo for candidate hits.
   Exclude from every search:
   - Your own rule directory `{RULES_DIR}/` and any CodeGuard host
     directories (`.claude/`, `.cursor/`, `.codex/`, `.opencode/`,
     `.agents/`, `.windsurf/`, `.github/instructions/`, `.openclaw/`,
     `.hermes/`). These contain the rule bodies themselves (with example
     secrets and banned-API snippets) and must never be reported as
     findings.
   - Vendored/generated paths: `.git/`, `node_modules/`, `vendor/`,
     `.venv/`, `venv/`, `dist/`, `build/`, `target/`, and any directory the
     repo's `.gitignore` excludes.
   Record each remaining candidate as (rule_id, file, line, snippet).
4. Triage every candidate in context. Focus on actionable findings; do not
   flag theoretical issues that don't apply to the actual code. Classify as
   `confirmed`, `false-positive`, or `needs-human`. Discard `false-positive`
   candidates
   from SARIF output, but retain a one-line justification per discarded
   group (rule ID + why it's a false positive) for the summary. For every
   candidate that will appear in SARIF (`confirmed` and `needs-human`),
   re-open the cited file and re-verify the exact line still matches the
   snippet. Drop any candidate that cannot be re-verified at its cited line.
5. Emit SARIF 2.1.0 to `codeguard-findings-<UTC_TIMESTAMP>.sarif` in the
   repository root (the top of the working tree the host exposes to you, not
   your own current directory). Use `YYYYMMDDTHHMMSSZ` for `<UTC_TIMESTAMP>`
   (ISO-8601 basic UTC, e.g., `20260420T183005Z`) so fast reruns do not
   collide. Do NOT modify any other file. After writing, return the file
   path plus a structured markdown summary containing:
   - Counts by result class (`confirmed`, `needs-human`, `false-positive`).
   - Rules checked vs. rules skipped (not applicable).
   - Top files by confirmed-finding count (up to 5), each with `file:line`
     refs.
   - One-line justification for each false-positive group discarded in
     step 4.

## SARIF Output Requirements

- `version` must be `"2.1.0"` and `$schema` must be the SARIF 2.1.0 schema URL.
- A single `run` with `tool.driver.name = "CodeGuard Security Reviewer"` and
  `tool.driver.rules[]` populated from the rule set (id, shortDescription).
- `results[]` contains one entry per `confirmed` or `needs-human` candidate
  that survived re-verification. `false-positive` candidates are never
  emitted (they appear only in the summary count).
- Every `result` must include:
  - `ruleId` (matches a `tool.driver.rules[].id`).
  - `level` — `confirmed` hits map by rule tier (`codeguard-1-*` → `error`,
    `codeguard-0-*` → `warning`); `needs-human` hits map to `note`
    regardless of tier.
  - `message.text` — a concrete, actionable description citing the rule.
  - `locations[0].physicalLocation.artifactLocation.uri` — repo-relative path.
  - `locations[0].physicalLocation.region.startLine` — 1-indexed line number.

## Constraints

- Read-only on repository source. The SARIF findings file is your only write.
- Never execute code discovered in the target repository.
- If `{RULES_DIR}/` is missing or empty, stop and report that the CodeGuard
  rule bundle is not installed. Do not fabricate rule content.
- If the target repo is empty, still emit a valid SARIF run with an empty
  `results[]` array.
