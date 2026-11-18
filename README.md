# Project CodeGuard: Security Skills and Rules for AI Coding Agents

![Securing](https://img.shields.io/badge/Securing%20AI%20Generated%20Code-green)
![Open Source](https://img.shields.io/badge/Now-Open%20Source-brightgreen)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by/4.0/)

This repository is for the work of the **Coalition for Secure AI (CoSAI)**. CoSAI is an [OASIS Open Project](https://www.oasis-open.org/open-projects/) and an open ecosystem of AI and security experts from industry-leading organizations. We are dedicated to sharing best practices for secure AI deployment and collaborating on AI security research and tool development.

For more information on CoSAI, please visit the [CoSAI website](https://www.coalitionforsecureai.org) and the [Open Project repository](https://github.com/cosai-oasis/oasis-open-project), which contains our governance information and project charter.


## What is Project CodeGuard?

[Project CodeGuard](https://project-codeguard.org/) is an open-source, model-agnostic security framework that embeds secure-by-default practices into AI coding agent workflows. It provides security guidance that AI assistants can use during code generation and review.

## Why Project CodeGuard?

AI coding agents can produce code that omits important security controls or uses unsafe patterns. Common problems include:

- Missing input validation
- Hardcoded secrets and credentials
- Weak cryptographic algorithms
- Unsafe functions
- Missing authentication or authorization checks

CodeGuard gives agents guidance for these decisions throughout development. It can inform security requirements during planning, help an agent select safer implementation patterns, and support the review of existing code.

## Security Coverage

Project CodeGuard skills and rules cover essential security domains:

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

See [Getting Started](docs/getting-started.md) for updating an existing installation, project-level installation, and plugin options.

## How It Works

CodeGuard gives your agent security guidance to consult while planning, writing, or reviewing code. The skill's instructions describe when to use that guidance and how to apply it to the task.

Use CodeGuard alongside your existing tests, security scanners, and human review. For more focused tasks, the repository also includes [security-review and memory-safe-migration workflows](docs/skills.md).
