# CoSAI Personas for Project CodeGuard

Project CodeGuard aligns with the [CoSAI standard personas](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/personas.yaml) so that deployment responsibilities are described using the same vocabulary used across the Coalition for Secure AI (CoSAI) ecosystem.

This page summarizes each persona in the context of **deploying and operating CodeGuard** so that install-path and test-plan documentation can reference a shared mental model.

!!! info "Scope of this page"
    This page does not replace the upstream CoSAI persona definitions. It explains how each persona typically shows up when implementing CodeGuard across individual developers, teams, and organizations.

## Persona Summary

| Persona | Role in CodeGuard deployment |
|:---|:---|
| Application Developer | Installs CodeGuard into repositories and user profiles; consumes rules through their AI coding tool. |
| AI System Governance | Defines and enforces org-wide CodeGuard policy; owns vendor dashboards and managed-settings deployments. |
| Agentic Platform and Framework Providers | Provide the IDEs, agent frameworks, plugin marketplaces, and remote loaders that activate CodeGuard rules/skills. |
| AI Platform Provider | Hosts centrally operated services such as an internal MCP server or device-management-managed client configuration. |
| AI System Users | Developers and other end users who benefit from CodeGuard-guided AI output but do not configure the install path. |
| Model Provider | Upstream model developer; not a CodeGuard implementer but benefits from CodeGuard nudging safe patterns at the tool layer. |
| Data Provider | Supplies data used to train or evaluate models; out of scope for install path implementation. |
| AI Model Serving | Operates runtime model-serving infrastructure; out of scope for CodeGuard install path implementation. |

## Personas Directly Involved in CodeGuard Install Paths

### Application Developer

The most common persona implementing CodeGuard.

- Installs rule files and Agent Skills into repositories and user profiles.
- Runs the update workflow or re-downloads release artifacts.
- Uses the AI tool (Cursor, Windsurf, GitHub Copilot, Claude Code, Codex, OpenCode, etc.) that consumes CodeGuard.
- Can operate either at user scope (personal machine) or project scope (committed to a repo).

**Typical install routes owned**

- Rule / instruction files (project and user scope)
- Agent Skills (project and user scope)
- Plugin marketplace (Claude Code)
- Remote instructions / installer (OpenCode, Codex)
- Self-service build from source

### AI System Governance

Represents AI risk, security, and compliance owners at the organization level.

- Decides which CodeGuard rules are mandatory for the organization.
- Owns the contents of vendor admin dashboards (Cursor Team Rules, GitHub Copilot organization custom instructions, Claude Code managed settings).
- Reviews and approves rule updates landing in repositories through PRs.
- Defines audit, rollback, and change-control procedures for CodeGuard rollouts.

**Typical install routes owned**

- Org-managed vendor dashboards
- Policy review for project-scoped installations
- Governance of MCP-served policy

### Agentic Platform and Framework Providers

Providers of the IDEs, agent frameworks, and orchestration tools that actually consume CodeGuard rules.

- Define how rule files, skills, and remote loaders are discovered and activated.
- Determine how managed settings and marketplaces are enforced.
- Shape the effective guarantees CodeGuard can make in each tool.

**Examples**

- IDEs and coding agents: Cursor, Windsurf, GitHub Copilot, Claude Code, Codex, OpenCode, Antigravity, OpenClaw, Hermes
- Agent frameworks and orchestration: LangChain, Semantic Kernel, and similar

**Typical install routes influenced**

- Agent Skills activation behavior
- Plugin marketplace enforcement
- Remote instruction loading
- Managed settings propagation
- Org-wide rule push mechanisms

### AI Platform Provider

Platform, SRE, or infrastructure teams that host shared services supporting CodeGuard at scale.

- Operates internally hosted MCP servers that serve CodeGuard rules.
- Manages device management (MDM/Jamf/Intune) flows that push managed settings.
- Runs the CI/CD and artifact pipelines used to build and distribute CodeGuard packages inside an organization.
- Handles uptime, observability, rollback, and access control for shared CodeGuard infrastructure.

**Typical install routes owned**

- MCP server (self-hosted)
- Internal redistribution of built-from-source artifacts
- Endpoint-managed settings deployment

### AI System Users

End users consuming AI-assisted output produced by tools that have CodeGuard applied.

- Typically do not configure CodeGuard themselves.
- Benefit from secure-by-default behavior shaped by CodeGuard rules.
- May request new rules or report false positives, feeding back into other personas.

## Personas Indirectly Connected to CodeGuard

### Model Provider

- Provides the underlying models used by coding agents.
- Does not implement CodeGuard install paths, but benefits when CodeGuard shapes prompts and outputs toward safer patterns.

### Data Provider

- Supplies training, evaluation, or inference data to model providers.
- Not directly involved in CodeGuard install path implementation.

### AI Model Serving

- Operates runtime environments that serve model predictions.
- Not directly involved in CodeGuard install path implementation, though CodeGuard-guided client-side behavior can reduce unsafe patterns reaching the serving layer.

## Persona-to-Install-Route Mapping

For the canonical per-route mapping used across the documentation, see [Choosing an Install Path → Responsible CoSAI Personas Per Install Route](install-paths.md#responsible-cosai-personas-per-install-route).

## Further Reading

- [CoSAI persona definitions (upstream YAML)](https://github.com/cosai-oasis/secure-ai-tooling/blob/main/risk-map/yaml/personas.yaml)
- [About Coalition for Secure AI](https://www.coalitionforsecureai.org/about/)
- [Choosing an Install Path](install-paths.md)
- [Getting Started](getting-started.md)
