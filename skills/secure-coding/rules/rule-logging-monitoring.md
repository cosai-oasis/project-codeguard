---
description: Structured, privacy-aware logging and monitoring — redaction, integrity, alerting
languages:
  - c
  - javascript
  - yaml
alwaysApply: false
rule_id: rule-logging-monitoring
---

# Logging & Monitoring

Logs are the primary record of what the system did and what the attacker did next. They need to be useful enough to drive detection and forensics, structured enough to query, and careful enough not to become a credential dump themselves.

## What to log

At minimum:

- Authentication events — success, failure, reason code (uniform), MFA events.
- Authorization decisions — denies in full, allows at the resource level for high-value actions.
- Administrative actions — role assignments, permission changes, audit-log configuration changes.
- Configuration changes — application and infrastructure.
- Sensitive-data access — reads and writes, at least for the restricted class.
- Input validation failures — pattern and payload (with secrets masked).
- Security errors — crypto failures, certificate validation failures, token verification failures.

Each event carries:

- A stable correlation / trace ID (propagated across services).
- User ID (or a stable pseudonym), session ID hash — never raw.
- Source IP and user agent.
- Tenant / organization identifier.
- UTC timestamp in RFC 3339 with millisecond precision.
- Event type / name from a small closed vocabulary.

## How to log

### Structure

Use JSON (or equivalent structured format) with stable field names. Free-form log strings are a search problem you will regret.

```json
{
  "ts": "2026-04-15T13:45:09.123Z",
  "level": "warn",
  "event": "auth.login.failed",
  "request_id": "req-8f12...",
  "user_id": "u-7c9a...",
  "source_ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "reason_code": "invalid_credentials"
}
```

### Log injection

Any data from outside the trust boundary that goes into a log entry can contain newline characters, field delimiters, or control characters that break downstream parsers. Strip or escape CR, LF, and the format's delimiters. Framework-provided structured loggers handle this correctly — hand-built concatenation often does not.

### Redaction

Never write to logs:

- Raw passwords, password hashes, MFA codes, recovery codes
- Session IDs (log a salted hash if correlation is needed)
- API keys, tokens, OAuth codes, JWTs
- Full credit card numbers, bank accounts, SSNs — apply a masking filter
- Request bodies for endpoints that carry credentials or health data

Build redaction as a field-name allow-list (what to log) or deny-list (what to drop), applied at serialization time so a developer cannot bypass it by writing to the wrong logger.

### Integrity

- Append-only storage or WORM where compliance requires. Tamper detection (hash chaining, per-hour Merkle roots) for audit logs.
- Centralized aggregation — the logs that matter live somewhere other than the host that generated them. An attacker who roots the host can otherwise erase their footprints.
- Access controls on the log store — the compute account that *writes* logs cannot *modify* them.

## Detection and alerting

Alert on:

- Authentication anomalies — credential stuffing (many users × few passwords × many IPs), impossible travel, bursts of failed logins, repeated MFA failures.
- Privilege changes — role grants, new admin accounts, changes to service-account permissions.
- Excessive validation failures — indicates an attacker probing.
- SSRF indicators — outbound requests to private ranges or unexpected domains.
- Data exfiltration patterns — bulk reads, unusual response sizes, new bulk-egress destinations.
- Crypto failures — repeated signature verification failures, TLS handshake failures from a single client.

Each alert has a runbook pointing to the playbook for that signal. Alerts that do not result in action are noise and should be retuned or deleted.

## Storage and protection

- Isolate log storage from application storage. Separate partition, separate database, separate account in cloud.
- Files and directories with strict permissions; not under the web root.
- Time synchronized across systems (NTP) — forensics requires consistent timestamps.
- Use TLS for the log pipeline. Authenticate the shipper end-to-end.

## Privacy and compliance

- Maintain a data inventory — what personal data appears in logs, where, and why.
- Minimize PII. A user identifier that is not the email is usually sufficient for troubleshooting.
- Retention driven by policy (legal, contractual, operational). Default to "less is more" for fields that are not load-bearing.
- Support user-linked deletion where the regulation requires it (GDPR right to erasure). This usually means pseudonymizing the log entries rather than deleting them; the hash index goes away on the user record.

## Implementation checklist

- JSON logging everywhere; stable field names; shared correlation ID.
- Log-injection mitigations present in the logging path.
- Redaction filters active; coverage verified by a unit test that tries to log a credential and asserts it is redacted.
- Centralized log pipeline, tamper-resistant destination, retention configured.
- Security alerts defined, runbooks linked, and periodically tested.
- Dashboards on the high-value signals (auth, privilege, data access).

## Validation

- Unit and integration tests assert key fields are present and credential-like fields are absent.
- Periodic automated audits scan logs for secret patterns — the same regexes that would alert on source-code leaks.
- Tabletop exercises that start from a log query and walk through the incident workflow.
