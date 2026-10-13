---
description: AI Agent Skill Security Guidelines for safe autonomous execution
languages:
- markdown
- yaml
- python
- javascript
alwaysApply: false
tags:
- agents
- data-security
---

# AI Agent Skill Security Guidelines

AI agent skills extend the capabilities of autonomous agents. They MUST be designed with explicit security boundaries to prevent abuse, privilege escalation, and unintended execution.

### Tool Access and Constrainment
- NEVER grant unconstrained tool access to an agent
- Avoid "do anything" tools (e.g., raw bash execution) unless absolutely necessary and heavily sandboxed
- Implement strict allowlists for commands, APIs, and accessible resources

### Filesystem and Network Boundaries
- Explicitly define filesystem boundaries (e.g., restrict reads/writes to a specific workspace or `/tmp` directory)
- Do NOT allow agents to read sensitive system files (e.g., `/etc/shadow`, `~/.ssh/`)
- Define network boundaries: restrict outbound requests to approved domains or internal services
- Block access to internal metadata services (e.g., AWS IMDS `169.254.169.254`)

### Dangerous Shell Executions
- Parameterize shell commands; NEVER concatenate untrusted input directly into shell commands
- If shell execution is required, run it inside a tightly constrained sandbox or container
- Use least privilege for the execution environment (e.g., non-root user)
- Implement timeouts for all tool executions to prevent resource exhaustion

### Validation and Auditing
- Validate all inputs and outputs of a skill against a strict schema
- Log all actions taken by an agent skill for auditability
- Include a human-in-the-loop (approval prompt) for high-risk actions (e.g., deleting files, pushing code, modifying infrastructure)
