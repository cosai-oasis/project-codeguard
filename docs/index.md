# Project CodeGuard: Security Skills and Rules for AI Coding Agents

[![Latest Release](https://img.shields.io/github/v/release/cosai-oasis/project-codeguard)](https://github.com/cosai-oasis/project-codeguard/releases/latest)

[Project CodeGuard](https://github.com/cosai-oasis/project-codeguard) is an open-source, model-agnostic security framework that embeds secure-by-default practices into AI coding agent workflows. It provides security guidance that AI assistants can use during code generation and review.

## Why Project CodeGuard?

AI coding agents can produce code that omits important security controls or uses unsafe patterns. Common problems include:

- Missing input validation
- Hardcoded secrets and credentials
- Weak cryptographic algorithms
- Unsafe functions
- Missing authentication or authorization checks

CodeGuard makes relevant security guidance available while an agent plans, implements, or reviews a change. For example, its input-validation guidance can help an agent choose appropriate checks during implementation and identify missing checks during review.

The results still need independent testing and review because they depend on the client, model, and task.

## Security Coverage

Our rules cover essential security domains:

- **Cryptography**: Safe algorithms (including post-quantum cryptography), secure key management, certificate validation
- **Input Validation**: SQL injection prevention, XSS protection, command injection defense
- **Authentication**: MFA best practices, OAuth/OIDC, secure session management
- **Authorization**: RBAC/ABAC, access control, IDOR prevention
- **Supply Chain**: Dependency security, SBOM generation, vulnerability management
- **Cloud Security**: IaC hardening, container security, Kubernetes best practices
- **Platform Security**: Mobile apps, web services, API security
- **Data Protection**: Privacy, encryption at rest/transit, secure storage

## Quick Start

CodeGuard is an Agent Skill: a folder of instructions and security guidance for your coding agent. For personal use, install a released version in your user skill directory so it is available across projects.

1. Download **Source code (zip)** from the [latest release](https://github.com/cosai-oasis/project-codeguard/releases/latest) and extract it. The skill folder is `skills/codeguard/` inside the extracted directory.
2. Copy that complete `codeguard/` folder to your client's personal skill location:

   | Client | Personal skill location |
   |---|---|
   | Claude Code | `~/.claude/skills/codeguard/` |
   | Codex | `~/.agents/skills/codeguard/` |

   Here, `~` means your home directory. For other clients, use their supported Agent Skills location.
3. Start a new client session and ask: “Use CodeGuard to review this authentication code for security issues.”

See [Getting Started](getting-started.md) for updating an existing installation, project-level installation, and plugin options.

## How It Works

CodeGuard gives your agent security guidance to consult while planning, writing, or reviewing code. The skill's instructions describe when to use that guidance and how to apply it to the task.

Use CodeGuard alongside your existing tests, security scanners, and human review. For more focused tasks, the repository also includes [security-review and memory-safe-migration workflows](skills.md).

## Community

- **📋 Issues**: [Report bugs or request features](https://github.com/cosai-oasis/project-codeguard/issues)
- **💬 Discussions**: [Join the conversation](https://github.com/cosai-oasis/project-codeguard/discussions)
- **🤝 Contributing**: [Learn how to contribute](https://github.com/cosai-oasis/project-codeguard/blob/main/CONTRIBUTING.md)

