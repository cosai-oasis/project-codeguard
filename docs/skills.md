# Authored Skills

Project CodeGuard ships two authored skills in `sources/skills/` that go beyond the core security rules. Unlike the generated rule files, these skills define complete workflows — they tell the AI assistant not just *what* to check, but *how* to carry out a multi-step task.

| Skill | What it does |
|:------|:------------|
| [`security-review`](#security-review) | Full codebase security review producing a structured markdown report |
| [`memory-safe-migration`](#memory-safe-migration) | Guided migration of C/C++ code to a memory-safe language |

Both skills are included in the Claude Code plugin and are available in `sources/skills/` for use with other agents.

---

## Security Review

**Skill file:** `sources/skills/security-review/SKILL.md`

Performs a comprehensive security review of a target repository and produces a formal markdown report with prioritized findings and remediation guidance. The skill loads all 23 CodeGuard core rules plus relevant OWASP supplementary rules for the detected tech stack.

### When to use

Use when you want a full, structured security audit of a codebase — not for inline code generation. This produces a standalone report, not inline code suggestions.

### How to trigger

Ask your AI assistant to perform a security review, for example:

```
Review this repository for security issues and produce a report
```

If the repository path is ambiguous, the skill will ask for it before proceeding.

### What the report includes

- **Executive Summary** — total findings by severity (Critical / High / Medium / Low / Info), top 5 issues, overall security posture
- **Detailed Findings** — for each issue: title, severity, rule reference, location, code snippet, description, impact, remediation with examples, and references
- **Findings by Category** — grouped view across all findings
- **Recommendations** — immediate actions, short-term (1–3 months), long-term improvements, tooling and process suggestions
- **Appendix** — files reviewed, rules applied, methodology notes

### Output location

Reports are saved to:

```
./security_report/sec_review_<repo-name>_<YYYY-MM-DD_HH-mm-ss>.md
```

---

## Memory-Safe Migration

**Skill file:** `sources/skills/memory-safe-migration/SKILL.md`

Guides secure migration of code from memory-unsafe languages (C, C++, Assembly) to memory-safe alternatives (Rust, Go, Java, C#, Swift). Also activates when an AI agent is about to generate new C/C++ code that could be written in a memory-safe language instead.

### When it activates

- Migrating, porting, or rewriting C/C++ code to Rust, Go, Java, C#, or Swift
- Adding a new module or feature to an existing C/C++ project
- Designing an FFI boundary between safe and unsafe code
- Reviewing mixed-language code for memory safety issues
- Discussing memory safety roadmaps or CISA/NSA compliance
- AI agent is about to generate new C/C++ code

### Migration workflow

The skill follows a six-step process:

1. **Assess** — evaluate migration priority and feasibility using `scripts/assess-migration.py` or the assessment checklist
2. **Write tests first** — establish a correctness oracle against the C/C++ implementation before touching anything
3. **Migrate incrementally** — one function or module at a time; never rewrite an entire codebase in one pass
4. **Secure the FFI boundary** — validate all inputs from the unsafe side, minimize `unsafe` blocks, document every `unsafe` block with a `// SAFETY:` comment
5. **Validate** — run existing tests, fuzz FFI boundaries, check memory safety tools (Miri, race detector, ASan), benchmark performance
6. **Update build and CI** — integrate the memory-safe toolchain, add linting and formatting checks, add safety-specific CI steps

### Migration priority order

| Priority | Code type |
|:---------|:----------|
| 1 | Network-facing code (parsers, protocol handlers, TLS) |
| 2 | Code handling untrusted input (file parsers, deserialization) |
| 3 | Cryptographic implementations |
| 4 | Privilege boundary code (auth enforcement) |
| 5 | Code with a history of memory-related CVEs |
| 6 | Internal utility code |

### Reference documents

The skill bundles detailed reference docs in `sources/skills/memory-safe-migration/references/`:

| Document | Contents |
|:---------|:---------|
| `language-selection.md` | Guide for choosing between Rust, Go, Java, C#, and Swift |
| `ffi-security.md` | Rules for securing FFI boundaries between safe and unsafe code |
| `migration-patterns.md` | Common patterns for buffers, strings, concurrency, and error handling |
| `assessment-checklist.md` | Checklist for evaluating migration priority and feasibility |

---

## Next Steps

[Getting Started →](getting-started.md){ .md-button .md-button--primary }
[Custom Rules →](custom-rules.md){ .md-button }
