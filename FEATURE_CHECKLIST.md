# Project CodeGuard — Feature Checklist

> Tracking checklist of all features shipped by Project CodeGuard, derived from the
> repository structure and documentation (`docs/`, `sources/`, `src/`). Use this to
> track coverage/regression status across releases. Check items off as they are
> verified for a given release.

## 🛡️ Core Security Rule Set

- [ ] 23 core rules (`sources/rules/core/`):
  - [ ] `codeguard-1-hardcoded-credentials` (Tier 1 — always-on)
  - [ ] `codeguard-1-crypto-algorithms` (Tier 1 — always-on)
  - [ ] `codeguard-1-digital-certificates` (Tier 1 — always-on)
  - [ ] `codeguard-0-additional-cryptography`
  - [ ] `codeguard-0-api-web-services`
  - [ ] `codeguard-0-authentication-mfa`
  - [ ] `codeguard-0-authorization-access-control`
  - [ ] `codeguard-0-client-side-web-security`
  - [ ] `codeguard-0-cloud-orchestration-kubernetes`
  - [ ] `codeguard-0-data-storage`
  - [ ] `codeguard-0-devops-ci-cd-containers`
  - [ ] `codeguard-0-file-handling-and-uploads`
  - [ ] `codeguard-0-framework-and-languages`
  - [ ] `codeguard-0-iac-security`
  - [ ] `codeguard-0-input-validation-injection`
  - [ ] `codeguard-0-logging`
  - [ ] `codeguard-0-mcp-security`
  - [ ] `codeguard-0-mobile-apps`
  - [ ] `codeguard-0-privacy-data-protection`
  - [ ] `codeguard-0-safe-c-functions`
  - [ ] `codeguard-0-session-management-and-cookies`
  - [ ] `codeguard-0-supply-chain-security`
  - [ ] `codeguard-0-xml-and-serialization`
- [ ] 80 OWASP supplementary rules (`sources/rules/owasp/`) — optional, reference-only, not enabled by default
- [ ] Two-tier activation model (Tier 1 always-on vs Tier 0 glob/language-scoped)
- [ ] Rule frontmatter schema (`description`, `languages`, `alwaysApply`, `tags`)
- [ ] Custom rule authoring path (`sources/templates/custom-rule-template.md.example`, `codeguard-<tier>-<topic>.md` naming)

## 🧩 Authored Skills

- [ ] `security-review` skill — full repo security audit → structured markdown report
  - [ ] Executive Summary (severity counts, top 5 issues, posture)
  - [ ] Detailed Findings (title, severity, rule ref, location, snippet, impact, remediation, references)
  - [ ] Findings by Category
  - [ ] Recommendations (immediate / short-term / long-term)
  - [ ] Appendix (files reviewed, rules applied, methodology)
  - [ ] Output saved to `./security_report/sec_review_<repo-name>_<timestamp>.md`
- [ ] `memory-safe-migration` skill — guided C/C++ → Rust/Go/Java/C#/Swift migration
  - [ ] Assess → Write tests first → Migrate incrementally → Secure FFI boundary → Validate → Update build/CI
  - [ ] Migration priority ordering (network-facing → untrusted input → crypto → privilege boundary → CVE history → internal utility)
  - [ ] Reference docs (`language-selection.md`, `ffi-security.md`, `migration-patterns.md`, `assessment-checklist.md`)

## 🔍 CodeGuard Reviewer (subagent)

- [ ] Read-only repo scan emitting SARIF 2.1.0 (`codeguard-findings-<timestamp>.sarif`)
- [ ] 5-step workflow: detect languages → load rules → search violations → triage → emit SARIF + summary
- [ ] Triage classes: `confirmed`, `needs-human`, `false-positive` (with justification)
- [ ] Supported hosts:
  - [ ] Claude Code (`.claude/agents/codeguard-reviewer.md`)
  - [ ] Cursor (`.cursor/agents/codeguard-reviewer.md`)
  - [ ] OpenCode (`.opencode/agents/codeguard-reviewer.md`)
  - [ ] GitHub Copilot / VS Code (`.github/agents/codeguard-reviewer.agent.md`)
  - [ ] OpenAI Codex (`.codex/agents/codeguard-reviewer.toml`)
- [ ] Excludes generated/vendored paths and `.gitignore`d files
- [ ] Credential redaction in findings
- [ ] Treats repo content as untrusted (ignores embedded prompt injection)
- [ ] Never executes target-repo code

## 🖥️ MCP Server (`src/codeguard-mcp/`)

- [ ] All 23 core rules exposed as individual MCP tools
- [ ] Tool taxonomy: `codeguard_1_*` (always-on) / `codeguard_0_*` (context-selected)
- [ ] Transport: streamable-HTTP and stdio
- [ ] Endpoints: `POST /mcp`, `GET /health`, `GET /download/skill`
- [ ] `CODEGUARD_*` env var configuration (HOST, PORT, LOG_LEVEL, TRANSPORT, RULES_DIR)
- [ ] Local run via `uv` / FastMCP
- [ ] Docker / Docker Compose deployment
- [ ] Meta skill install (`.agents/skills/codeguard-mcp-meta/SKILL.md`)

## 📦 Distribution / Install Routes

- [ ] Pre-built rule ZIPs on GitHub Releases:
  - [ ] `codeguard-cursor.zip`
  - [ ] `codeguard-windsurf.zip`
  - [ ] `codeguard-copilot.zip`
  - [ ] `codeguard-antigravity.zip`
  - [ ] `codeguard-opencode.zip`
  - [ ] `codeguard-openclaw.zip`
  - [ ] `codeguard-hermes.zip`
  - [ ] `codeguard-codex.zip`
  - [ ] `codeguard-all.zip` (all formats)
- [ ] Claude Code plugin marketplace (`/plugin marketplace add`, `/plugin install codeguard-security@project-codeguard`)
- [ ] Codex plugin marketplace + `$skill-installer` remote install
- [ ] OpenCode remote `instructions` URL loading (opencode.json, zero local files)
- [ ] Org-managed dashboards (Cursor Team Rules, GitHub Copilot org custom instructions)
- [ ] Project-scope vs. user-scope installs
- [ ] VS Code-family marketplace `.vsix` extension (not yet shipped — documented as a planned route)

## 🛠️ Build & Conversion Tooling (`src/`)

- [ ] `convert_to_ide_formats.py` (`--source`, `--output-dir`/`-o`, `--tag`)
- [ ] `validate_unified_rules.py`
- [ ] `validate_versions.py`
- [ ] `converter.py`
- [ ] `emit_agents.py`
- [ ] `artifact_targets.py`
- [ ] `language_mappings.py`
- [ ] `tag_mappings.py`
- [ ] `utils.py`
- [ ] `formats/` per-tool output templates

## 📚 Documentation Site (mkdocs)

- [ ] Getting Started (prerequisites, per-tool install, build-from-source)
- [ ] Choosing an Install Path (decision tree, persona guidance, tradeoffs)
- [ ] Custom Rules guide
- [ ] FAQ
- [ ] CoSAI Personas mapping
- [ ] Claude Code plugin guide
- [ ] Codex plugin guide
- [ ] MCP Server guide
- [ ] CodeGuard Reviewer guide
- [ ] ADRs (`docs/adr/`)

## 🏛️ Governance / Project Meta

- [ ] CoSAI (Coalition for Secure AI) OASIS Open Project governance
- [ ] `CODE-OF-CONDUCT.md`
- [ ] `CONTRIBUTING.md`
- [ ] `LICENSE.md` (CC BY 4.0)
- [ ] Claude Code plugin manifest (`.claude-plugin/`)
- [ ] Codex plugin manifest (`.codex-plugin/`)

---

_Last generated: 2026-09-18. Regenerate/update this checklist when `sources/rules/`,
`sources/skills/`, `sources/agents/`, `src/codeguard-mcp/`, or `docs/` change._
