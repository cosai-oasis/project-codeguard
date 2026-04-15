---
description: API and web service security — REST, GraphQL, SOAP, schema validation, authn/z, SSRF
languages:
  - c
  - go
  - java
  - javascript
  - php
  - python
  - ruby
  - typescript
  - xml
  - yaml
alwaysApply: false
rule_id: rule-api-web-services
---

# API & Web Services Security

Covers REST, GraphQL, and SOAP/WS endpoints end-to-end: transport, authentication, authorization, schema validation, SSRF controls, DoS mitigations, and microservice-safe patterns.

## Transport

- HTTPS only. Internal service-to-service traffic benefits from **mTLS** when the environment supports it — gateway-terminated TLS plus plaintext inside a VPC is weaker than it looks once any workload on that network is compromised.
- Validate peer certificates strictly — CN/SAN, revocation (OCSP stapling or short-lived certificates). No mixed content.

## Authentication

- For clients (browser, mobile, third-party app): standard flows (OAuth 2.0 / OIDC). Do not invent a bespoke auth scheme.
- For service-to-service: mTLS, or signed service tokens tied to a workload identity (SPIFFE SVID, AWS IAM SigV4, GCP service account tokens).
- **JWT** specifics when you do use them:
  - Pin the algorithm server-side, never accept `alg: none`.
  - Validate `iss`, `aud`, `exp`, `nbf` on every verification.
  - Short lifetimes (minutes). Rotation on refresh. A denylist for logout and revocation.
  - Prefer opaque tokens backed by a central store when revocation actually matters.
- **API keys**: scope them narrowly (a key that can do anything is a disaster waiting). Rate-limit them. Monitor usage. They are adequate for non-sensitive read endpoints; they are not adequate as the sole auth for anything that can change state.

## Authorization

- Every endpoint enforces an explicit authorization check. Deny by default.
- Check resource ownership / relationship in addition to role. See `rule-authorization-access-control.md`.
- In microservice meshes:
  - **Coarse** authorization at the gateway — authenticated, member of tenant, not rate-limited out.
  - **Fine** authorization at the service — this particular caller may perform this particular action on this particular resource.
  - Never forward the external token to internal services. Mint a signed internal identity that includes only what the internal services need.

## Input and content handling

- Define the contract explicitly — OpenAPI / JSON Schema for REST, GraphQL SDL with directives, XSD for SOAP. Generate validation from the contract rather than hand-writing it.
- Reject unknown fields (`additionalProperties: false` in JSON Schema) — otherwise attackers can smuggle state changes via undefined fields.
- Set explicit size limits (request body, header count, header size). Reject oversize requests early.
- Enforce `Content-Type` and `Accept` explicitly. A mismatch between what the client declares and what the server parses is a frequent source of bugs and exploits.
- Harden XML parsers — see `rule-xml-serialization-hardening.md`.

## Injection inside handlers and resolvers

Handlers / GraphQL resolvers / RPC methods often reach into databases or downstream services. The same rules apply there as anywhere else:

- Parameterized queries, not string concatenation (`rule-input-validation-injection.md`).
- No shell execution with untrusted input.
- Safe deserialization (`rule-xml-serialization-hardening.md`).

## GraphQL-specific controls

GraphQL's flexibility is also its attack surface.

- **Query depth and complexity**: set hard limits (depth ≤ 10 is a reasonable starting default; tune to your schema). Reject queries above the limit before execution.
- **Pagination**: require `first` / `last` on list fields; cap the value.
- **Timeouts** on execution; budget per request.
- **Introspection disabled in production**. Leaving it on gives attackers a full schema dump for free.
- **GraphiQL / Playground disabled in production**.
- **Field-level authorization**: check authz on each resolver, not only at the top-level mutation boundary. A nested field with lax authz is a BOLA / IDOR waiting to happen.
- **Batching** can be used as a rate-limit bypass. Rate-limit per operation and per field, not only per HTTP request.

## SSRF prevention

An API that makes outbound calls on behalf of the user is a natural SSRF target.

Rule of thumb: **do not accept raw URLs from users**.

When you must:

- Restrict the scheme to `http` and `https`. Reject `file://`, `gopher://`, `ftp://`, `jar://`, and friends at parse time, not at request time.
- Validate the host.

### Case 1 — fixed set of upstream partners

- Strict domain allow-list. Only the domains in this list may be fetched.
- Disable HTTP redirects — a 302 to `http://169.254.169.254/...` defeats a naive allow-list check.
- Network-layer egress allow-lists as defense in depth.

### Case 2 — arbitrary user-provided URLs (e.g., webhook targets)

- Block private, link-local, and loopback ranges — IPv4 `10/8`, `127/8`, `169.254/16`, `172.16/12`, `192.168/16`; IPv6 `::1/128`, `fc00::/7`, `fe80::/10`, IPv4-mapped addresses.
- Resolve the hostname yourself, check every returned IP, and make the outbound connection by IP — otherwise a DNS rebind converts a passing check into an internal call.
- Require the caller to prove ownership of the target (for example a signed challenge file at a known path) if the use case permits it.
- Cap response size and timeout.

## SOAP / WS and XML payloads

- Validate every SOAP payload against a pinned XSD; limit message size and nesting depth.
- Enable XML Signatures / Encryption as required by the interface contract.
- Configure the parser against XXE, entity expansion, and recursive payloads — see `rule-xml-serialization-hardening.md`.
- Scan attachments.

## Rate limiting and DoS

- Apply rate limits at multiple levels: per IP, per user, per API key, per tenant. Global is the last line.
- **Circuit breakers** between services — a downstream slowdown should not cascade into a resource exhaustion upstream.
- **Timeouts** on every outbound call — no "infinite" in production configuration.
- Use server-side batching and caching to amortize load. Cache-Control response headers can shape public client behavior, but do not rely on them for security.

## Management and internal endpoints

- Metrics endpoints, health checks that expose detail, database admin UIs, `/debug/...` handlers — do not expose over the Internet.
- Require strong auth (MFA), IP allow-lists, separate hostnames or ports, and ideally a separate network.

## Assessment and testing

- Keep an API spec in version control; drive contract tests, fuzzing, and security scans from it.
- Test **every** HTTP method per endpoint — many auth bugs only show up when you try `OPTIONS`, `HEAD`, `TRACE`, or `PATCH` on a handler the developers only thought about for `GET` and `POST`.
- Look for parameters in URL path, headers, and structured JSON — not only query strings.
- Exercise authn bypass, authz bypass, SSRF, injection, information disclosure in logs/errors, and missing rate-limits.

## Microservice practices

- Policy as code, with decision points either as sidecars or as library PDPs embedded in each service.
- Service identity via mTLS or signed tokens; never re-use external tokens for internal calls.
- Structured logging with a correlation/trace ID that threads through the call graph. Strip PII at the edge.

## Implementation checklist

- HTTPS / mTLS; certificates managed; no mixed content.
- Schema validation at the edge; unknown fields rejected; body and header size limits enforced.
- Authz per endpoint; GraphQL depth and complexity limits applied; introspection off in production.
- SSRF protections at application and network layers; redirects disabled; allow-lists in place.
- Rate limiting, circuit breakers, timeouts on all outbound calls.
- Management endpoints isolated and strongly authenticated.
- Logs structured, correlation-ID-carrying, and PII-safe.

## Test plan

- Schema-driven contract tests and fuzzing.
- Authn/authz tests: token replay, scope downgrade, audience mismatch.
- SSRF tests using private-IP and DNS-rebind payloads.
- Rate-limit tests: linear, burst, and distributed patterns.
- Performance tests that hit the declared limits exactly, then 1% over.
