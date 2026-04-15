---
description: Privacy and data protection — minimization, transparency, cryptography, user rights
languages:
  - javascript
  - matlab
  - yaml
alwaysApply: false
rule_id: rule-privacy-data-protection
---

# Privacy & Data Protection

Privacy is a superset of data security: even well-protected data is a privacy problem if it should not have been collected in the first place. The five questions to ask about every piece of personal data:

1. Do we need it? (If not — delete the field.)
2. Do we need it forever? (If not — retention policy.)
3. Who should be able to read it? (Minimize — narrow IAM, separate keys.)
4. How do we prove (to auditors and to users) what we did with it? (Audit trail.)
5. How do we delete it when requested? (User rights — access, export, delete.)

## Minimization

- Collect only the fields the feature requires. An email that is only used for password reset does not require a phone number.
- Avoid "just in case" logging of request bodies, user input, or document contents.
- Pseudonymize where possible — an opaque user ID is usually sufficient for analytics; the email address is not.

## Cryptography

- TLS with HSTS everywhere. See `rule-additional-cryptography.md`.
- Encryption at rest for databases, file stores, backups.
- Strong password hashing with per-user salt (Argon2id / scrypt / bcrypt) — see `rule-authentication-mfa.md`.
- Certificate pinning only where it fits (mobile apps with a controlled update channel) and with a plan for rotation. See `rule-additional-cryptography.md`.

## Transport privacy

- Prefer connections that do not leak metadata: avoid DNS-over-HTTP-without-TLS; use DoH or DoT where available.
- Consider OCSP stapling so clients do not query the CA directly for revocation — the query itself is telemetry to a third party.
- Block third-party content from loading over non-TLS paths. A non-TLS image on a TLS page can leak cookies via URL parameters or IP reveal.

## Sessions and authentication — privacy angle

- Invalid-login response is generic ("Invalid username or password") to avoid account enumeration.
- Reset flow returns the same response for existent and non-existent accounts.
- Session IDs generated via CSPRNG and stored server-side; only a session cookie on the client. See `rule-sessions-cookies.md`.
- Do not leak user identifiers in URLs, `Referer` headers, or analytics events. Use opaque redirects, `Referrer-Policy: no-referrer`, and first-party analytics that see only the fields they need.

## Transparency

- Publish a privacy policy that describes what data is collected, why, retention, and third-party sharing.
- In the product: just-in-time notices at the point of collection, not only buried in a ToS page.
- For third-party integrations (analytics, A/B testing, ads): list them by name and by purpose. Offer opt-out where the jurisdiction requires it.
- Inform users about the limits — "This feature requires sharing your city with the weather provider, not your exact location."

## User rights

Support, at a minimum:

- **Access** — the user can see what data you hold on them.
- **Export** — a machine-readable download.
- **Delete** — the user can erase. "Pseudonymize" is often the correct implementation; a chain of events that reference the user ID is tombstoned rather than rewritten, and the user table row is cleared.
- **Correct** — the user can fix wrong data.

Automate these flows where volume warrants it. Manually-handled data-rights requests become inconsistent and slow.

## Audit trail for privacy

- Log access to sensitive records (who viewed the user's SSN, who ran the bulk export).
- Keep the log distinct from the data it audits — same-system logs are an insider-threat soft spot.
- Review periodically; surface anomalies (an engineer who suddenly reads every customer record) via monitoring.
- When a data-rights request is fulfilled, log that too — with a handle, not the data itself.

## Third-party data sharing

- Contractual: vendor agreements, DPAs where jurisdictions require them.
- Technical: the vendor gets only the minimum fields needed. An analytics vendor does not need email; an email vendor does not need purchase history.
- Inventory the sharing — a single list of "who gets what" is the document an auditor will ask for first.

## Implementation checklist

- Every collected field has a purpose documented somewhere in code or config.
- Retention policy enforced by a job, not by hope. Lifecycle rules on object storage, TTL on database records, scheduled deletes.
- Encryption in transit and at rest for everything above the "public" classification.
- Generic error messages for authentication / enumeration-sensitive flows.
- Sessions via CSPRNG, server-stored, cookie-only for transport.
- Audit trail for access to restricted-class data.
- Data-rights flows implemented end-to-end and exercised in tests.
- Vendor inventory current; DPAs on file.
