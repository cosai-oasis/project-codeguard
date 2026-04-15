---
description: Model Context Protocol (MCP) security — workload identity, transport, sandboxing, human-in-the-loop
languages:
  - python
  - javascript
  - typescript
  - go
  - rust
  - java
alwaysApply: false
rule_id: rule-mcp-security
---

# MCP (Model Context Protocol) Security

MCP gives an LLM controlled access to tools, resources, and prompts. That access is precisely the attack surface: a malicious MCP server can exfiltrate data, a compromised client can be tricked into calling dangerous tools, and prompt injection travels across both. The control set below is the baseline for any production MCP deployment.

## Workload identity

- Use cryptographic workload identity — SPIFFE / SPIRE is the reference for multi-cloud; the cloud vendor's equivalent (AWS IAM Roles for Service Accounts, GCP Workload Identity Federation, Azure Managed Identity) is fine for single-cloud.
- Identities are short-lived (SVIDs with minutes-scale TTL), rotated automatically.
- One identity per logical service. Do not share identities across servers that have different authority profiles.

## Input and data sanitization

Treat **every** MCP input as untrusted, regardless of source:

- User prompts, tool schemas, resource contents, metadata — any of them can carry a prompt injection that a downstream LLM will execute.
- Apply allow-list validation at each trust boundary.
- Canonicalize file paths before file-system operations; reject anything that escapes the allowed root.
- Parameterize database queries (`rule-input-validation-injection.md`).
- Apply context-aware output encoding before returning data (SQL, shell, HTML contexts each require the appropriate encoding).

### Tool output hygiene

- Return only the minimum fields the caller needs. An entire record dump from an internal database is a gift to a compromised model.
- Redact PII before the data leaves the server.
- Apply a hard size cap on each response.

### Prompt injection

- Deploy a prompt-injection detection layer (heuristics + a small classifier model) on untrusted inputs that the LLM will see.
- Use strict JSON schemas to mark the boundary between "instructions" and "data" — the parser refuses ambiguous structures.
- Log prompt-injection matches as a security event, not as noise.

## Sandboxing and isolation

- MCP servers run with least privilege — separate user, separate filesystem namespace, limited capabilities.
- Any server that touches the host environment (files, commands, network) adds a sandbox layer: `gVisor`, Kata Containers, Firecracker, SELinux / AppArmor profiles, seccomp filters.
- LLM-generated code — treat as hostile. Never execute it with full user privileges; the minimum viable sandbox is a per-call container with no host access.

## Cryptographic verification

- Sign server code and publish an SBOM.
- The client verifies the signature before loading a server. Unknown publisher → refuse by default.
- TLS for everything in transit.
- Remote attestation when the threat model warrants it — the server proves it is running expected code.

## Transport

### `stdio` (local)

- Preferred for local MCP servers — eliminates network-layer attack classes (DNS rebinding, cross-origin leaks).
- Pipe communication is still an IPC channel — sandbox the server so it cannot escalate out of its process.

### HTTP streaming (remote)

Enforce the following controls, or do not run an MCP server over HTTP:

- Payload limits — per-request size cap, per-message cap, nesting cap, total streaming window cap. Defends against large-payload and recursive-payload DoS.
- Rate limits — per tool, per client, per identity.
- Mutual authentication — client and server both present credentials.
- mTLS — client certificate required, server certificate verified.
- TLS encryption (1.3 preferred).
- CORS — explicit origin allow-list; never `*`.
- CSRF protection — custom header requirement, SameSite cookies if session-based.
- Integrity — message counters, nonces, or signed responses to block replay and spoofing.

## Secure tool and UX design

- Each tool is single-purpose with an explicit contract. Avoid "do anything" tools whose authority scope depends on the prompt — those become prompt-injection amplifiers.
- The LLM does not make authorization decisions on its own. The server enforces authz independently.
- **Two-stage commits** for high-impact operations: a draft / preview call returns a ticket ID and shows the exact action; a second commit call with the ticket performs it.
- Provide rollback paths (draft IDs, snapshots, reversible operations). Time-bound any commit — the ticket expires.

## Human in the loop

- Require confirmation on risky operations. Use the MCP "elicitation" facility so the server requests user approval through a channel the client is meant to honor.
- Security-relevant confirmation messages clearly state the implication: "This will delete 3,412 records from the production database."
- Do **not** rely solely on human approval. A tired user clicks through. Combine with bounded authority — the tool cannot do anything the server would refuse to do even with approval.

## Logging and observability

- Log: tool called, parameters (with secret redaction), the originating prompt, the identity used, the outcome.
- OpenTelemetry traces that connect the LLM call → tool invocation → downstream action. End-to-end linkability is necessary for investigation.
- Immutable, access-controlled log storage. The identity that writes logs cannot modify them.

## Deployment-pattern considerations

### All-local (stdio or http on localhost)

- Security depends on the host posture.
- Prefer `stdio` to avoid DNS rebinding.
- Sandbox limits the blast radius.
- Appropriate for personal use and development; not for multi-user production.

### Single-tenant remote (http)

- Client-server authentication is **required**.
- Secure credential storage — OS keychain, secret manager. Not an `~/.config/*.json`.
- Encrypted and authenticated communication end-to-end.
- Enterprise clients enforce server discovery against an explicit allow-list.

### Multi-tenant remote (http)

- Tenant isolation is a hard requirement — per-tenant identities, per-tenant encryption keys, strict RBAC inside the server.
- Prefer servers hosted directly by the service provider (you trust them for the data already).
- Remote attestation where possible — the client verifies the server is running the expected code.

## Summary

MCP security is the intersection of all the other skill rules (auth, authz, transport, parsing, logging) plus two MCP-specific concerns — prompt injection across tool schemas, and the fact that the LLM is not an authorization layer. Design the server so that a misbehaving model is still constrained by the server's own controls.
