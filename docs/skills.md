# Authored Skills

The primary [CodeGuard skill](https://github.com/cosai-oasis/project-codeguard/blob/main/skills/codeguard/SKILL.md) guides coding and review. The repository also includes the workflows described below in `sources/skills/` for more focused tasks.

| Skill | Purpose |
|---|---|
| [security-review](#security-review) | Review a repository and produce a structured Markdown report. |
| [memory-safe-migration](#memory-safe-migration) | Plan and carry out migration of memory-unsafe code, including FFI boundaries. |

Both are registered by the Claude Code plugin and are available as source folders for other integrations. The Codex plugin registers only CodeGuard. See [Getting Started](getting-started.md#choose-an-install-path) for installation instructions.

## Security Review

The `security-review` skill defines a repository review that produces findings, remediation guidance, and a record of coverage. Its input is the target repository.

The workflow asks the agent to save a Markdown report at `./security_report/sec_review_<repo-name>_<YYYY-MM-DD_HH-mm-ss>.md`. This path is relative to the agent's working directory. Review the findings and claimed coverage before relying on the report.

The [skill definition](https://github.com/cosai-oasis/project-codeguard/blob/main/sources/skills/security-review/SKILL.md) defines the task inputs and report requirements. Its [review guidelines](https://github.com/cosai-oasis/project-codeguard/blob/main/sources/skills/security-review/Security_Code_Reviewer_Guidelines.md) describe rule loading and the detailed procedure.

## Memory-Safe Migration

The `memory-safe-migration` skill helps assess C/C++ migration, select a memory-safe language, and review boundaries between safe and unsafe code.

The [skill definition](https://github.com/cosai-oasis/project-codeguard/blob/main/sources/skills/memory-safe-migration/SKILL.md) owns the migration sequence and priorities. Its [assessment script](https://github.com/cosai-oasis/project-codeguard/blob/main/sources/skills/memory-safe-migration/scripts/assess-migration.py) and [references](https://github.com/cosai-oasis/project-codeguard/tree/main/sources/skills/memory-safe-migration/references) support planning, FFI design, and validation. Keep these files with the skill when installing it.
