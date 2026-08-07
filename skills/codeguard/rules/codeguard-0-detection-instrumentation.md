---
description: Detection instrumentation (emit structured security events at security-relevant decision points so downstream detection has signal)
languages:
- c
- go
- java
- javascript
- kotlin
- php
- python
- ruby
- swift
- typescript
alwaysApply: false
tags:
- authentication
- data-security
- privacy
- web
---

rule_id: codeguard-0-detection-instrumentation

## Detection Instrumentation

Treat detectability as a generation requirement. When you generate a security-relevant decision point, also emit the structured security event a detector would later need. Preventing a vulnerability is not enough: if the code ships without instrumentation, downstream detection (SIEM/alerting) has nothing to work with.

This rule complements `codeguard-0-logging.md` (how to log safely) and `codeguard-0-logging-vocabulary.md` (the standardized event taxonomy). Use the OWASP logging vocabulary as the event key so events are greppable and SIEM-consumable.

Scope boundary: CodeGuard owns emitting the event in the generated application code. It does not own or operate the detection backend, alerting rules, or agent runtime hooks.

### When to Emit an Event (Security-Relevant Sinks)
Emit a structured event whenever you generate code at these decision points, on **both the success and the failure/denial path**:

- Authentication: login success/failure, logout, MFA challenge result, password/credential change, token issue/revoke/reuse.
- Authorization: access granted vs. denied for a protected resource; role/permission/entitlement changes; privileged/admin actions.
- Input validation: server-side validation rejection at a trust boundary.
- Sensitive data: create/read/update/delete of regulated or sensitive records.
- Session lifecycle: session created/renewed/expired; use of an expired or revoked session.
- Account/user management: user created/updated/archived/deleted.
- Excessive use / abuse: rate-limit exceeded; repeated failures; known-attack-tool or anomalous-request indicators.
- Security configuration: security monitoring or a control being disabled/enabled.

If a generated function is a security-relevant sink but has no matching event, that is a gap to fix before completing the change.

### How to Emit (Requirements)
- Key each event to the OWASP logging vocabulary event name (e.g., `authn_login_fail`, `authz_fail`, `input_validation_fail`, `sensitive_read`, `privilege_permissions_changed`). Do not invent ad-hoc strings for events the taxonomy already covers.
- Emit on **both** outcomes. A denial path with no event is the most common blind spot; the absence of a signal is invisible to a scanner.
- Include correlation context: request/correlation ID, actor (user/session ID, non-PII), source IP, timestamp (UTC, RFC 3339 / ISO 8601 with offset), and the target resource.
- Emit structured records (JSON or the app's structured logger) with stable field names, so events are greppable and machine-parseable.
- Set severity consistently with the vocabulary (INFO / WARN / CRITICAL); denials, privilege changes, and token reuse are high-severity.
- Fail closed on errors and denials: deny the action and roll back partial state, then emit the event. Never swallow an exception on a security-relevant path such that no event is recorded. See `codeguard-0-error-handling.md`.
- Follow `codeguard-0-logging.md` for safety: sanitize event fields against log injection, and never log secrets, tokens, raw session IDs, or PII in the event.

Example (Python – authorization check, both paths instrumented):
```python
def get_document(user, doc_id, request_id):
    if not user.can_read(doc_id):
        # Denial path MUST emit an event - this is what a detector needs.
        logger.warning(
            "authz_fail",
            extra={
                "event": "authz_fail",
                "userid": user.id,
                "resource": f"document:{doc_id}",
                "request_id": request_id,
                "source_ip": request.remote_addr,
            },
        )
        raise PermissionDenied()

    doc = repo.load(doc_id)
    logger.info(
        "sensitive_read",
        extra={
            "event": "sensitive_read",
            "userid": user.id,
            "resource": f"document:{doc_id}",
            "request_id": request_id,
        },
    )
    return doc
```

Example (TypeScript – login failure keyed to the vocabulary):
```typescript
if (!passwordValid) {
  logger.warn({
    event: "authn_login_fail",   // OWASP logging-vocabulary event name
    userid: username,            // identifier only; never the password
    source_ip: req.ip,
    request_id: req.id,
    datetime: new Date().toISOString(),
  });
  return res.status(401).json({ message: "Invalid credentials" });
}
```

### Identifying Missing Events During Review
Missing instrumentation is the opposite of a vulnerability pattern: there is nothing to match, so a pattern scanner reports clean. Verify presence explicitly instead:

- For each security-relevant sink changed or added, confirm a matching vocabulary event exists on **every** exit path (success and denial/exception). Denial paths that only `return`/`throw` without emitting an event are the primary failure mode.
- Grep the diff for the sink and confirm a co-located event keyed to the vocabulary (e.g., an `authz_fail` near every place that raises "permission denied").
- Confirm each event carries correlation context (request/correlation ID + actor + resource) and uses a taxonomy event name rather than free-form text.
- Confirm the event does not leak secrets or PII and is sanitized against log injection.
- Prefer specifying required events up front (spec/design) for new features; retrofitting instrumentation into code that was not built for it is expensive and is how these gaps arise.

### Implementation Checklist
- Every generated security-relevant sink emits a structured event on success and denial paths.
- Events are keyed to the OWASP logging vocabulary and carry correlation IDs + actor + resource.
- Denial/exception paths verified to emit (not just success paths).
- No secrets/PII in events; fields sanitized per `codeguard-0-logging.md`.
- Required events for new security features are specified before implementation.

### Validation
- Unit/integration tests assert that the expected event is emitted for each outcome (success and denial), including negative tests that exercise the failure path.
- Review or lint step flags security-relevant functions with no matching event.
- Periodic audit greps for taxonomy event names to confirm coverage across auth, authz, validation, and sensitive-data paths.
