---
description: Authentication and MFA — password handling, MFA factors, OAuth/OIDC, SAML, password reset, tokens
languages:
  - c
  - go
  - java
  - javascript
  - kotlin
  - matlab
  - php
  - python
  - ruby
  - swift
  - typescript
alwaysApply: false
rule_id: rule-authentication-mfa
---

# Authentication & MFA

## Design goals

A good authentication system rejects credential-based attacks, keeps secrets out of attacker reach, offers strong second factors, and gives users a sane recovery path when things go wrong. Every decision below feeds one of those four goals.

## Identifiers and UX

- **Internal identifier** should be a random, non-sequential, non-public value (UUID or equivalent). Reserve email/username for authentication UX only — never expose the internal ID in URLs or tokens meant for the client.
- **Login identifier** — allow email *or* username where possible; emails require proof of ownership before they become a login path.
- **Error messages** on failed login must be generic: "Invalid username or password." Never indicate which half was wrong. Account enumeration via signup or reset flows is equally bad — see the "Recovery" section.
- **Timing** of the response must be roughly constant across (user exists / user does not / password wrong). A 50 ms difference is enough for an attacker to build a user directory.
- **Password manager friendliness** — use `<input type="password" autocomplete="current-password">`, allow paste, do not block right-click, do not fragment the field into N single-character inputs.

## Password policy

- Accept passphrases. Allow the full Unicode range and any printable ASCII, including spaces.
- Minimum length 8 characters; practical floor for new systems is 12.
- Maximum length at least 64; 128 is a reasonable upper bound for DoS protection. Never truncate silently.
- **Do not** impose composition rules (one uppercase, one digit, one symbol). They reduce entropy in practice by funneling users into predictable patterns.
- Check new passwords against a breach corpus — use a k-anonymity API (HIBP Pwned Passwords) so the plaintext never leaves the server. Reject anything on the list.

## Password storage — hash, don't encrypt

Choose an algorithm, tune the parameters so the verify step takes roughly 500 ms – 1 s on your production hardware, and update the parameters as hardware improves.

| Algorithm | Parameters (baseline) | Notes |
|-----------|-----------------------|-------|
| **Argon2id** (preferred) | `m=19–46 MiB`, `t=2–1`, `p=1` | Modern, memory-hard, PHC-winner |
| **scrypt** | `N=2^17`, `r=8`, `p=1` | Older but still fine |
| **bcrypt** | `cost ≥ 10` | Legacy; beware the 72-byte input truncation |
| **PBKDF2-HMAC-SHA-256** | ≥ 600 000 iterations | Required only when FIPS mandates it |

Universal rules:

- Generate a per-user random salt (at least 16 bytes from a CSPRNG). The library usually does this; verify it does.
- Store only `algorithm + parameters + salt + hash`, concatenated in the library's canonical format.
- Compare hashes with a constant-time function. The language-supplied `verify` in the crypto library usually is; manual comparisons usually aren't.
- When the algorithm or cost changes, *rehash transparently* on the next successful login. Do not force all users to reset.

Optional pepper (a secret value shared across the application, outside the DB — typically in a KMS or HSM):

- Applied via `HMAC(pepper, password)` **before** the password hashing algorithm, or by encrypting the resulting hash.
- Requires a rotation/re-hash plan if it ever leaks; do not add this unless you have that plan.

Unicode and null bytes must round-trip through your hasher intact. Some bcrypt implementations silently stop at the first NUL — verify.

## Login flow hardening

- HTTPS for every auth endpoint; HSTS enabled site-wide.
- Rate limit per IP, per account, and globally. Credential-stuffing comes from thousands of IPs at once — per-IP limits alone are not enough.
- Use throttling with progressive back-off over hard lockouts. Permanent lockouts are a denial-of-service weapon against your own users.
- Alternative anti-automation (CAPTCHA, proof-of-work) is acceptable as an escalation, not a default.
- Keep response status codes, bodies, timing, and downstream code paths uniform across all failure cases.

## Multi-factor authentication

### Factor hierarchy

| Tier | Factors | Use for |
|------|---------|---------|
| Strong (phishing-resistant) | WebAuthn / passkeys, FIDO2 hardware keys | Default for sensitive accounts |
| Acceptable | TOTP (RFC 6238), smart card + PIN | Baseline |
| Weak — avoid if possible | SMS, voice call, email code | Only when nothing better is available |
| Do not use | Security questions | Treat as opaque data, not an authentication factor |

### When to require MFA

At minimum: login, changes to the password or primary email, disabling MFA, privilege elevation, high-value transactions, and any login from a new device/location/IP-range. Adaptive signals (device fingerprint, geo-velocity, IP reputation, breached-credential match) should lower the threshold further.

### Recovery

- Generate single-use backup codes at enrollment. Encourage enrollment of more than one factor.
- Resetting MFA should require strong identity proofing — the same code path an attacker would use to take over an account.
- After a failed MFA attempt, offer alternative enrolled methods, log the attempt with user/IP/device context, and alert the user.

## Federation — OAuth 2.0 / OIDC / SAML

Do not invent your own federation protocol. Use a library that implements the spec, then read the spec anyway so you know what the library protects and what it doesn't.

### OAuth 2.0 / OIDC checklist

- Use **Authorization Code + PKCE** for public clients (SPA, mobile, desktop). Do not use Implicit or Resource-Owner-Password-Credentials.
- Validate `state` on every callback; validate `nonce` on ID tokens.
- `redirect_uri` matches exactly — no substring, no prefix, no wildcard. Protect against open redirect in whatever handles the callback.
- Bind tokens to an `audience` and a set of `scopes`; enforce both on the receiver side.
- Prefer sender-constrained tokens (DPoP or mTLS) where the ecosystem supports it.
- Rotate refresh tokens on use; revoke on logout, password change, or risk signal.

### SAML checklist

- TLS 1.2+; sign responses and assertions; encrypt assertions containing anything sensitive.
- Validate `Issuer`, `InResponseTo`, `NotBefore` / `NotOnOrAfter`, `Recipient`, and `Destination` against expected values.
- Verify signatures against a pinned set of trusted keys — not whatever the response says.
- Defend against XML Signature Wrapping: enable strict schema validation; extract assertions by signed-element reference, not by XPath over the whole document.
- Prefer SP-initiated flows; validate `RelayState`; detect replays.

## Tokens — JWT vs opaque

Prefer **opaque tokens** plus a server-side store for anything where revocation matters. "Stateless" is not worth the operational cost of a stolen token that cannot be invalidated.

If you do use JWTs:

- Pin the `alg` server-side — never trust the header. Reject `none`.
- Validate `iss`, `aud`, `exp`, `iat`, and `nbf` on every verification.
- Short lifetimes (5–15 minutes for access tokens). Refresh with rotation.
- Sign with a key in a KMS/HSM; for HMAC tokens use a strong secret stored outside the binary.
- Consider binding a token to client context (a hash of a device identifier in an HttpOnly cookie, for example) so a stolen token does not work on an unrelated client.
- Implement a denylist for logout and critical events, even if that undermines the "stateless" selling point — it's what keeps your users safe.

## Password reset / account recovery

- Return the same response whether or not the account exists. Take the same code path.
- The reset token is a cryptographic secret: ≥ 32 bytes from a CSPRNG, stored as a hash (not plaintext), single-use, short TTL (15–60 minutes).
- The reset link points to an HTTPS URL on a pinned, trusted domain. Set `Referrer-Policy: no-referrer` on the reset UI so the token is not leaked in a Referer header when the user clicks a link on that page.
- After a successful reset:
  - invalidate all existing sessions for the user,
  - require re-authentication,
  - notify the user on every channel you have,
  - do not auto-login.
- Never lock an account because someone *requested* resets for it — that is a DoS vector. Rate limit and alert instead.

## Admin / internal accounts

- Put administrative login on a distinct path (separate subdomain, separate service).
- Stronger factors mandatory (WebAuthn / hardware key, not TOTP).
- Device posture checks, IP allow-lists, and step-up authentication before sensitive operations.
- Distinct session cookies and shorter timeouts.

## Monitoring signals

Log (structured, non-PII where possible):

- login success / failure, with reason code,
- MFA enrollment and each verify attempt,
- password / email changes,
- account lockouts and backoffs,
- token issuance / revocation,
- new-device / new-geo alerts.

Never log: raw passwords, raw MFA codes, raw session IDs, raw tokens, security-question answers.

Detect: credential stuffing (many accounts, few passwords per account, many IPs), impossible travel, brute force on reset tokens.

## Implementation checklist

- Password storage: Argon2id preferred, per-user salt, constant-time verify. Breach-password check on set/change.
- MFA: WebAuthn or hardware tokens for high-risk; TOTP as baseline; SMS only when nothing else works.
- Federation: Authorization Code + PKCE, strict redirect-URI match, audience/scope enforced, refresh rotation.
- Tokens: short-lived, sender-constrained when possible, revocation working, keys in KMS/HSM.
- Reset: single-use hashed tokens, consistent responses, re-auth on reset, sessions rotated.
- Abuse: rate limits on all auth endpoints, uniform error handling, monitoring for anomalies.

## Test plan

- Login: happy path, wrong password, missing user, locked user — all must return the same 401 and similar timing.
- MFA: enroll, verify, recover, fallback — each with negative cases.
- OAuth: PKCE required, `state` validated, `redirect_uri` strict-match, `id_token` signature and `nonce` checked.
- Token: replay after logout must fail; audience mismatch must fail; `alg: none` must fail.
- Reset: consistent response for existent and non-existent users; token single-use; session rotation post-reset.
