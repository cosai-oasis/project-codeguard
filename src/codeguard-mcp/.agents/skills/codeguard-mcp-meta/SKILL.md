---
name: CodeGuard MCP Meta Skill
description: Instructs AI coding agents to invoke CodeGuard MCP Server security rules before writing or reviewing code.
---

# CodeGuard MCP Server Integration

## MANDATORY: Always Invoke CodeGuard MCP Server

When writing, reviewing, or modifying code, you MUST invoke the CodeGuard MCP Server to retrieve relevant security rules. This is a non-optional security requirement.

**IMPORTANT: IF YOU ARE NOT ABLE TO SEE/INVOKE CODEGUARD TOOLS, IMMEDIATELY INFORM THE USER**

### How to Use the MCP Server

The CodeGuard MCP Server exposes security rules as individual tools. Each tool returns comprehensive security guidance for specific scenarios.

**Tool Invocation Pattern:**
```
Tool: {rule_tool_name}
Arguments: None (tools automatically include metadata)
Returns: Complete security guidance with rule ID, description, and content
```

## Tool Selection Guide

### Step 1: Discover Available CodeGuard Tools

Before any coding activity:
1. Identify all available MCP tools whose names contains `codeguard_`.
2. Read each tool's description to understand:
   - The security domain it covers
   - Which languages/artifacts it applies to (if specified)

If you cannot discover/invoke CodeGuard tools, stop and inform the user.

### Step 2: Always-Invoke `codeguard_1_*`

**MANDATORY:** Before writing/reviewing/modifying code, invoke **every available tool** whose name contains:

- `codeguard_1_`

These are "always-on" guardrails and must be enforced regardless of language or domain.

### Step 3: Context-Select `codeguard_0_*`

After invoking `codeguard_1_*`, decide which `codeguard_0_*` tools to invoke by using the tool descriptions plus your current task context.

#### 3A) Determine the current language(s)/artifact(s)

Infer from one or more of:
- The file(s) being edited (extensions like `.py`, `.js`, `.ts`, `.yaml`, `.yml`, `.Dockerfile`, etc.)
- Framework/tooling in use (Django/Flask/Express/K8s/Terraform/etc.)
- The user's explicit statement ("in Python", "Node", "Kubernetes manifest", etc.)

#### 3B) Determine the security domain(s) from the task

Use the tool descriptions to map the task to domains such as auth, API/web services, input validation, storage, file handling, DevOps/IaC, privacy, logging/monitoring, XML/serialization, mobile, etc.

#### 3C) Select tools using tool descriptions (language + domain)

For each available `codeguard_0_*` tool:
- **Language filter**: select it only if the description says it applies to the current language/artifact type (or is broadly applicable when no language is specified).
- **Domain filter**: select it if the domain in the description matches the task you are performing.

If uncertain and the change is security-sensitive, err on the side of invoking the relevant `codeguard_0_*` tools (while avoiding clearly unrelated tools).

## Apply the Guidance and Document It

When you implement changes:
- Follow the retrieved guidance
- Avoid anti-patterns called out by the rules
- Add minimal security comments where they clarify intent

In your response to the user, explicitly state:
- Which **CodeGuard tools** you invoked (all `codeguard_1_*` plus the selected `codeguard_0_*`)
- A brief note on **how each rule influenced** the implementation

## Tool Invocation Is Not Optional

If you are about to write/review/modify code and you have not invoked CodeGuard tools per this meta rule, stop and invoke them first.
