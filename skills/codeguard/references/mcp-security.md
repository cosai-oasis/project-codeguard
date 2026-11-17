---
description: MCP (Model Context Protocol) Security based on CoSAI MCP Security guidelines
languages:
- python
- javascript
- typescript
- go
- rust
- java
alwaysApply: false
---

rule_id: codeguard-0-mcp-security

## MCP (Model Context Protocol) Security

Never deploy MCP servers or clients without proper security controls: cryptographic workload identity, untrusted-input handling, sandboxing, verified server code, secure transport, narrowly scoped tools, human confirmation for risky actions, and auditable logs.

### Workload Identity and Authentication
- Use cryptographic workload identities (e.g., SPIFFE/SPIRE) for service-to-service authentication.
  - SPIFFE (Secure Production Identity Framework For Everyone) provides a standard for service identity.
  - SPIRE (SPIFFE Runtime Environment) issues and rotates short-lived cryptographic identities (SVIDs).
- For HTTP servers, follow the MCP authorization specification: accept only access tokens issued for this server (validate audience/resource), and never pass a client's token through to upstream APIs; obtain separate tokens for upstream calls.
- A server that proxies a third-party OAuth provider under one static client ID must record and check each user's consent per MCP client (client_id, scopes, redirect URI) before sending them to the third party.

### Input and Data Sanitization
- Validate all inputs using allowlists at every trust boundary.
- Sanitize file paths through canonicalization.
- Use parameterized queries for database operations.
- Before fetching OAuth or resource metadata, client metadata documents, or model-supplied URLs, require HTTPS and an allowlist, and block private, loopback, link-local, and cloud-metadata addresses, rechecking after redirects and DNS resolution.
- Apply context-aware output encoding (shell, HTML).
- Sanitize tool outputs: return only minimum fields, redact all PII and sensitive data.
- Treat all inputs, tool schemas, metadata, prompts, and resource content as untrusted input.
- Use prompt injection detection only as a supplementary layer; it is not a security boundary, so enforce authorization and limits outside the model.
- Validate tool arguments against strict JSON schemas (e.g., `additionalProperties: false`), bound schema depth and size, and never auto-fetch network `$ref`s; text inside valid fields is still untrusted.
- Clients: pin a hash of each approved tool definition (description, schemas, annotations), require re-approval when it changes, and treat each server as a separate trust domain.

### Sandboxing and Isolation
- Design MCP servers to execute with least privilege.
- MCP servers interacting with the host environment (files, commands, network) must implement sandboxing controls.
- LLM-generated code must not run with full user privileges.
- Do not treat containers alone as a strong boundary; consider stronger isolation such as gVisor, Kata Containers, or SELinux sandboxes.

### Cryptographic Verification of Resources
- Provide cryptographic signatures and SBOMs for all server code.
- Implement signature verification in your MCP client before loading servers.
- Use TLS for all data in transit.
- Where infrastructure supports it, implement remote attestation to verify servers are running expected code.

### Transport Security

#### stdio Transport (Local Servers)
- Strongly recommended for local MCP to eliminate DNS rebinding risks.
- Uses direct pipe-based stream communication.
- Implement a sandbox to prevent privilege escalation.

#### Streamable HTTP Transport (Remote Servers)
- If a request has an `Origin` header, reject disallowed origins with 403; non-browser clients may send none.
- Payload limits to prevent large payload and recursive payload DoS.
- Rate limiting for tool calls and transport requests.
- Client-server authentication and authorization.
- Mutual TLS authentication where both client and server are under your control.
- TLS encryption.
- CORS protection.
- CSRF protection.
- Integrity checks to prevent replay, spoofing, and poisoned responses.

### Secure Tool and UX Design
- Create single-purpose tools with explicit boundaries; avoid "do anything" tools.
- Do not rely on the LLM for validation or authorization decisions.
- Use two-stage commit for high-impact actions: draft/preview first, explicit commit with confirmation second.
- Provide rollback/undo paths (draft IDs, snapshots, reversible actions) and time-bound commits when possible.

### Human-in-the-Loop
- Keep confirmation prompts for risky tool calls enabled in MCP hosts and clients, locked by configuration that unprivileged users cannot change.
- Use elicitation on the MCP server side to request user confirmation of risky actions.
- Security-relevant messages must clearly indicate their implications.
- Do not rely solely on human approval (users can become fatigued).

### Logging and Observability
- Implement logging in your MCP servers and clients.
- Log the tools that were used, with allow-listed, redacted audit metadata (such as tool name, caller, outcome, redacted parameters, and correlation IDs linking each call to the request that triggered it); never log credentials, tokens, or unredacted prompts or parameters (see [logging](logging.md)).
- Use distributed tracing (e.g., OpenTelemetry) for end-to-end linkability of actions.
- Maintain immutable records of actions and authorizations.

### Deployment Patterns

#### All-Local (stdio or HTTP)
- Security depends entirely on host system posture.
- Use `stdio` transport to avoid DNS rebinding risks.
- If a local server uses HTTP, bind only to localhost (not `0.0.0.0`), validate the `Origin` header on every request, and require authentication.
- Use sandboxing to limit privilege escalation attacks.
- Appropriate for development and personal use.

#### Single-Tenant Remote (HTTP)
- Authentication between client and server is required.
- Use secure credential storage (OS keychains, secret managers).
- Communication must be authenticated and encrypted.
- Enterprise clients should enforce authenticated server discovery with explicit allowlists.

#### Multi-Tenant Remote (HTTP)
- Require robust tenant isolation, identity, and access control.
- Implement strong multi-tenancy controls (per-tenant encryption, role-based access control).
- Prefer MCP servers hosted directly by the service provider.
- Provide remote attestation when possible.

### Implementation Checklist
- Workloads authenticated with short-lived cryptographic identities (e.g., SPIFFE/SPIRE).
- All inputs, tool schemas, metadata, prompts, and resource content treated as untrusted and validated; tool outputs minimized and redacted.
- Servers run with least privilege and are sandboxed when they touch files, commands, or the network; LLM-generated code never runs with full user privileges.
- Server code signed and shipped with SBOMs; clients verify signatures before loading servers.
- Local servers use stdio, or HTTP bound to localhost with `Origin` validation and authentication; remote servers enforce payload and rate limits, authentication and authorization (tokens audience-checked, never passed through), mutual TLS where both ends are controlled, CORS, CSRF, and integrity checks.
- Single-purpose tools; two-stage commit and rollback for high-impact actions; validation and authorization never delegated to the LLM.
- Risky operations require clear user confirmation, without relying on approval alone.
- Tool use logged as allow-listed audit metadata with prompts and parameters redacted by data classification, immutable and traced end to end.
- Remote deployments authenticate and encrypt all traffic; multi-tenant deployments isolate tenants.
