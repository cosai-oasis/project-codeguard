# CodeGuard Codex Plugin

The Codex plugin includes the primary CodeGuard skill.

## Install

With Codex CLI installed, run these commands in your terminal:

```bash
codex plugin marketplace add cosai-oasis/project-codeguard
codex plugin add codeguard-security@project-codeguard
```

Start a new Codex session and select CodeGuard from the skill picker, or include it in your request:

```text
$codeguard Review this authentication code for security issues.
```

The [plugin manifest](https://github.com/cosai-oasis/project-codeguard/blob/main/.codex-plugin/plugin.json) registers `skills/`. The [additional skills](skills.md) are available separately in the repository.
