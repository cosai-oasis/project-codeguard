---
description: Security event logging for structured, safe, reviewable application telemetry
languages:
- c
- javascript
alwaysApply: false
tags:
- privacy
---

rule_id: codeguard-0-logging

## Security Event Logging

Instrument application decision points so security-relevant activity can be detected and investigated. Emit concise, structured events that describe what the application decided and what changed, without exposing secrets or unnecessary personal data. Application code owns event meaning and coverage; this rule does not prescribe logging backends or detection operations.

### Choose Events at Security Decision Points

Identify the decisions and state changes that matter to the application's threat model, then emit an event where the authoritative decision is made. Prefer the authentication, authorization, business-service, or state-change layer over a generic request logger: request logs alone cannot say whether access was granted or why an operation changed sensitive state.

Record the outcome of relevant events such as:

- Authentication attempts (`authentication.attempt`, with `succeeded` or `denied` outcome), account lockout or recovery, and changes to credentials or MFA.
- Authorization decisions (`authorization.decision`, with `allowed` or `denied` outcome) for sensitive operations, including the action and resource category.
- Administrative actions and changes to roles, permissions, security policy, or security-relevant configuration (for example, `security.role_change` or `security.policy_change` with an accurate outcome).
- Access to, export of, or deletion of sensitive records when that access is security- or compliance-relevant.
- Security control decisions such as rate limiting, request forgery checks, and validation rejection when they indicate a meaningful attack signal.

Avoid logging every routine request or low-value invalid field. Choose events that answer who or what acted, what was attempted, the decision or outcome, and the affected resource or security setting. Emit success for a state-changing operation only when the change commits; represent denied, failed, and rolled-back outcomes accurately. Do not emit duplicate events at multiple layers for the same decision.

### Use a Stable, Structured Event Shape

Use the application's structured logger and stable event names and field names. Keep fields typed and machine-readable; use bounded enumerations for `event`, `outcome`, and `reason_code` rather than parsing prose. A useful event usually includes:

- A stable `event` name and `outcome` (for example, `authorization.decision` and `denied`).
- UTC timestamp, service or component, and environment when available from trusted application context.
- A server-generated request or interaction identifier for correlation.
- Actor or principal type and a pseudonymous identifier when needed; include an anonymous or system actor explicitly when applicable.
- Action and target type, with a stable target identifier only when needed for investigation.
- A bounded reason code or policy decision category that explains the outcome without exposing internal secrets or sensitive policy details.

Include only fields useful for the event and permitted by the application's data classification. Treat account IDs and stable pseudonyms as potentially personal data. Source IP, user agent, and session context are not automatic fields: include them only when necessary, minimize precision or retention where appropriate, and never use a raw session identifier as a correlation ID.

Example authorization decision:

```json
{
  "timestamp": "2026-04-18T14:23:05Z",
  "event": "authorization.decision",
  "outcome": "denied",
  "reason_code": "tenant_scope_mismatch",
  "actor": { "type": "user", "id": "user_ref_7f2a" },
  "action": "invoice.read",
  "target": { "type": "invoice", "id": "inv_4821" },
  "request_id": "req_01JQ8M2A",
  "service": "billing-api"
}
```

Use the framework's JSON or equivalent structured logging API; do not build records by concatenating untrusted values into log lines. Keep free-form messages supplemental, not the only representation of a security event. Bound or classify values with a defined schema so downstream consumers can review and compare events consistently.

### Protect Logs from Disclosure and Forgery

- Never log passwords, authentication secrets, access or refresh tokens, API keys, recovery codes, raw session identifiers, private keys, or authorization headers.
- Do not log full request or response bodies, sensitive records, payment data, or raw exception messages by default. Select safe fields and use approved redaction or pseudonymization where identifiers are needed.
- Treat client-controlled values and exception text as untrusted. Prefer validated enums and identifiers; rely on structured encoders to escape values and reject or bound fields that could create forged records or excessive log volume.
- Keep application responses separate from security events. A useful internal event must not cause secrets or stack traces to be returned to the caller.
- Avoid logging the same sensitive value in a second field or in a free-form message after redacting it from the structured fields.

### Review for Missing Events

During implementation and review, build a small event coverage table from the threat model and the changed security-sensitive code:

| Decision or state change | Expected event and outcomes | Authoritative code path | Required safe context |
| --- | --- | --- | --- |
| Sensitive resource access | `authorization.decision` (`allowed` / `denied`) | Authorization decision for the operation | Actor, action, target type, outcome, request ID |
| Role or policy change | `security.role_change` or `security.policy_change` (accurate success or failure outcome) | Administrative update and commit result | Actor, changed setting or target, outcome, request ID |

For each row, trace the allow and deny paths, relevant exceptions, and transaction or rollback paths. Confirm every security-relevant outcome reaches one event at the decision point, successful changes are logged only after commit, and event fields are populated from trusted context. Search the changed code for the decision and state mutation sites and verify each is covered; an event-name search alone cannot prove coverage. Record an explicit reason when a decision is intentionally not logged, such as to avoid high-volume, low-value noise.

When adding or changing event behavior, update the application's logging tests or review evidence to assert required events and outcomes are present and sensitive fields are absent. Validation should inspect both the emitted event shape and the code paths that produce it; a passing redaction check does not establish event coverage.
