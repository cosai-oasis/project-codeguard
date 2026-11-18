# Frequently Asked Questions

## Q: Where can I access the rules?

**A:** You can access the rules in the [Project CodeGuard GitHub repository](https://github.com/cosai-oasis/project-codeguard). The latest stable release is available on the [releases page](https://github.com/cosai-oasis/project-codeguard/releases).

---

## Q: How do I install the rules?

**A:** See [Getting Started](getting-started.md) for plugin and skill-folder installation instructions.

---

## Q: Will these rules consume a lot of the AI agent's **context window**?

**A:** Context use depends on the client, task, and amount of guidance loaded. CodeGuard does not have a fixed context cost; refer to the [skill definition](https://github.com/cosai-oasis/project-codeguard/blob/main/skills/codeguard/SKILL.md) for its current instructions and supporting material.

---

## Q: What is the difference between always-on rules and glob-scoped rules?

**A:** These terms describe activation in the [legacy native rule bundles](https://github.com/cosai-oasis/project-codeguard/blob/v1.5.0/docs/getting-started.md). The current distribution provides an Agent Skill; its intended use is described in the [skill definition](https://github.com/cosai-oasis/project-codeguard/blob/main/skills/codeguard/SKILL.md).

---

## Q: What are the OWASP supplementary rules?

**A:** The `sources/rules/owasp/` collection contains OWASP-based guidance used by the `security-review` workflow. It is separate from the primary CodeGuard skill and is not included in its release archive.

---

## Q: Why does the downloaded release folder appear empty?

**A:** Legacy native bundles use hidden dot-directories; follow the [v1.5.0 installation guide](https://github.com/cosai-oasis/project-codeguard/blob/v1.5.0/docs/getting-started.md). The skill archive uses a visible `codeguard/` directory.

---

## Q: Can I use this with Claude Code?

**A:** Yes. Follow the [Claude Code plugin instructions](claude-code-skill-plugin.md).

## Q: How can I report a problem or enhancement to any of the rules?

**A:** [Open an issue](https://github.com/cosai-oasis/project-codeguard/issues) with the affected guidance, client and model, and a reproducible example.

---

## Q: How can I contribute to these rules and this project?

**A:** Follow [CONTRIBUTING.md](https://github.com/cosai-oasis/project-codeguard/blob/main/CONTRIBUTING.md) for proposing changes, validation, and pull requests.

---

## Q: Does Project CodeGuard replace my security scanners?

**A:** No. CodeGuard provides guidance to the agent; it does not guarantee review coverage or detection of vulnerabilities. Use it alongside your existing security scanners, functional tests, and human review.

---

## Still have questions?

If your question is not covered here, [open an issue](https://github.com/cosai-oasis/project-codeguard/issues) or [start a discussion](https://github.com/cosai-oasis/project-codeguard/discussions) with the community.
