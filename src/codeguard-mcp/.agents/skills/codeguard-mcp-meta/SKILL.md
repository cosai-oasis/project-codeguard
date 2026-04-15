---
name: codeguard-mcp-meta
description: Instructs AI coding agents to use the CodeGuard MCP Server to retrieve and apply security rules before writing or reviewing code. This skill is a must read according to security policies.
---

# CodeGuard MCP Server Integration

## MANDATORY: Always Read CodeGuard Security Rules

When writing, reviewing, or modifying code, you MUST read the relevant security rules from the CodeGuard MCP Server. This is a non-optional security requirement.

**IMPORTANT: IF YOU CANNOT ACCESS CODEGUARD RESOURCES, IMMEDIATELY INFORM THE USER**

## How to Use the MCP Server

The CodeGuard MCP Server exposes a security skill containing all CodeGuard rules as MCP resources. Resources are identified by `skill://` URIs.

### Step 1: Read the Manifest

Read the manifest resource at `skill://software-security/_manifest` to get a JSON listing of all available rule files with their paths, sizes, and hashes.

### Step 2: Read the Main Skill

Read `skill://software-security/SKILL.md` to get the skill overview and a language-to-rules mapping table that tells you which rules apply to which programming languages.

### Step 3: Always Read `codeguard-1-*` Rules

**MANDATORY:** Before writing/reviewing/modifying code, read **every rule** whose name contains `codeguard-1-*`:

These are "always-on" guardrails and must be enforced regardless of language or domain.

### Step 4: Context-Select `codeguard-0-*` Rules

After reading the `codeguard-1-*` rules, select which `codeguard-0-*` rules to read based on your current task context.

**4A) Determine the current language(s)/artifact(s)**

Infer from one or more of:
- The file(s) being edited (extensions like `.py`, `.js`, `.ts`, `.yaml`, `.Dockerfile`, etc.)
- Framework/tooling in use (Django/Flask/Express/K8s/Terraform/etc.)
- The user's explicit statement ("in Python", "Node", "Kubernetes manifest", etc.)

**4B) Determine the security domain(s) from the task**

Map the task to domains: auth, API/web services, input validation, storage, file handling, DevOps/IaC, privacy, logging/monitoring, XML/serialization, mobile, etc.

**4C) Read the relevant rules**

Use the language-to-rules mapping from `SKILL.md` and the manifest to identify the right files, then read them. For example:
- Writing a Python API endpoint → read `codeguard-0-api-web-services.md`, `codeguard-0-input-validation-injection.md`, `codeguard-0-authentication-mfa.md`
- Writing a Dockerfile → read `codeguard-0-devops-ci-cd-containers.md`, `codeguard-0-supply-chain-security.md`
- Writing C code → read `codeguard-0-safe-c-functions.md`

For each available `codeguard_0_*` tool:
- **Language filter**: select it only if the description from SKILL.md says it applies to the current language/artifact type (or is broadly applicable when no language is specified).
- **Domain filter**: select it if the domain in the description from SKILL.md matches the task you are performing.

If uncertain and the change is security-sensitive, err on the side of reading more rules.

## Apply the Guidance and Document It

When you implement changes:
- Follow the retrieved guidance
- Avoid anti-patterns called out by the rules
- Add minimal security comments where they clarify intent

In your response to the user, explicitly state:
- Which **CodeGuard rules** you read (all `codeguard-1-*` plus the selected `codeguard-0-*`)
- A brief note on **how each rule influenced** the implementation

## Reading Rules Is Not Optional

If you are about to write/review/modify code and you have not read the relevant CodeGuard rules, stop and read them first.
