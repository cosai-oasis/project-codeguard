---
description: Session management and secure cookies — rotation, fixation, timeouts, theft detection
languages:
  - c
  - go
  - html
  - java
  - javascript
  - php
  - python
  - ruby
  - typescript
alwaysApply: false
rule_id: rule-sessions-cookies
---

# Sessions & Cookies

## Design goals

A session must be unforgeable, stealable only by compromising the transport or the client, automatically invalidated on privilege change, and auditable without leaking sensitive material into logs.

## Session ID properties

- **Source**: a CSPRNG. ≥ 64 bits of entropy is the floor; ≥ 128 bits is a sensible default. 256 bits is cheap to generate and trivially sufficient.
- **Opacity**: the ID encodes no meaning. No user ID, no role, no tenant, no timestamp. Those live in server-side state keyed by the ID.
- **Origin**: only the server mints session IDs. An incoming ID the server never issued must be rejected, not accepted and escalated.
- **Cookie name**: a short, neutral name (`id`, `sid`) is fine; framework defaults (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`) signal the stack to attackers. Either rename or at least do not rely on the name itself for anything.
- **Server-side state**: all session data lives server-side. Never round-trip sensitive attributes through the client. Server-side session stores holding sensitive data are encrypted at rest.

## Cookie flags

For every session cookie:

```
Set-Cookie: id=<opaque>; Secure; HttpOnly; SameSite=Strict; Path=/
```

- **`Secure`** — cookie is never sent over plain HTTP. Combine with HSTS so HTTP is never reached.
- **`HttpOnly`** — cookie is unavailable to JavaScript. Defends the session against any XSS that would otherwise read `document.cookie`.
- **`SameSite=Strict`** — cookie is not sent on cross-site requests, including top-level navigations. Use `Lax` if top-level GET from an outside link must carry the session; `Strict` is preferred for sensitive paths.
- **`Path` / `Domain`** — scope the cookie as narrowly as feasible. Avoid cross-subdomain cookies unless you actually need them.
- **Prefer non-persistent** session cookies (no `Expires` or `Max-Age`) — they die when the browser closes.
- Consider the **`__Host-`** prefix to force `Secure`, `Path=/`, and no `Domain` attribute — a small but real defense against subdomain takeover.

## Session lifecycle

1. **Creation**: only the server creates sessions. Trust nothing from the client about the ID.
2. **Authentication**: rotate the session ID on successful login. Invalidate the pre-auth ID. This is the primary defense against session fixation.
3. **Privilege change**: rotate again on password change, MFA enrollment / removal, role elevation, or any action that expands permissions.
4. **Logout**: the `/logout` handler invalidates the server-side session record *and* clears the cookie on the client. Both steps are required — either alone leaves a hole.
5. **Destruction**: idle timeout and absolute timeout enforced server-side. See below.

If the framework prefers distinct pre-auth and post-auth cookie names, use that pattern; it makes the invalidation step easier to audit.

## Timeouts

| Sensitivity | Idle timeout | Absolute timeout |
|-------------|--------------|------------------|
| High (banking, admin, healthcare) | 2–5 minutes | 4 hours |
| Medium | 15–30 minutes | 4–8 hours |
| Low-risk apps | Up to 1 hour | 12–24 hours |

Both timeouts must be enforced on the server. A client-side timer that tells the user "you've been logged out" without the server discarding the session is a decoration, not a control.

The logout button must be visible on every authenticated page and must work without requiring JavaScript.

## Transport and caching

- HTTPS only for the full session journey. A single HTTP hop leaks the cookie. If the application must support HTTP for some users, it must not authenticate them over HTTP.
- Enable HSTS (`Strict-Transport-Security`) site-wide.
- Pages containing session identifiers in the response body (or sensitive user data) carry `Cache-Control: no-store`. Shared caches are a legitimate concern here.

## Theft detection and response

Session tokens can be exfiltrated through browser vulnerabilities, malicious extensions, or physical access. The server can detect *suspicious* reuse by fingerprinting the environment.

Capture at establishment:

- IP address (consider subnet rather than exact — many legitimate users roam),
- user agent,
- `Accept-Language`,
- available `sec-ch-ua` hints,
- geolocation bucket.

Compare on each request. Tolerate small drift; escalate on big jumps.

| Risk level | Triggers | Response |
|------------|----------|----------|
| Low | UA minor version change | Log, continue |
| Medium | ASN change, UA major change | Challenge (MFA re-verify), rotate session ID |
| High | Country change, concurrent use from distant locations, known-bad ASN | Force re-authentication, rotate session ID, alert user |

Every suspicious event should rotate the session ID; a hijacker with the old ID gets logged out.

## Client storage

Session tokens do **not** go into `localStorage` or `sessionStorage`. Any XSS steals them. Cookies with `HttpOnly` are the only reasonable place for session material.

If the application architecture needs a token accessible to JavaScript (for example, a bearer token for API calls), accept that XSS gets it, and:

- Minimize the token's lifetime (minutes, not days).
- Bind the token to additional client context so a raw steal is not enough.
- Consider isolating the storage in a Web Worker and exposing only a narrow message API to the main thread.

## Multi-cookie scenarios

If the application uses multiple cookies that together represent session state (an access cookie and a CSRF cookie, for instance):

- Verify their relationship to each other on each request; do not trust them independently.
- Do not give them the same name with different paths/domains — cookie jar behavior across browsers is inconsistent.

## Monitoring

- Log session lifecycle events (created, rotated, terminated, detected-drift) with a **salted hash** of the session ID, not the raw ID. You want to correlate across entries without turning the log into a credential dump.
- Dashboards: brute-force on session IDs (high request rates per unique ID), anomalous concurrent use, failed lifecycle events.

## Implementation checklist

1. Session IDs from a CSPRNG, opaque, ≥ 64 bits entropy, server-minted.
2. Cookie flags: `Secure`, `HttpOnly`, `SameSite`, narrow `Path` / `Domain`. `__Host-` prefix where feasible.
3. HTTPS + HSTS everywhere. No mixed content.
4. Rotate session ID on authentication and on privilege change. Invalidate the previous ID.
5. Idle and absolute timeouts enforced server-side. Logout handler invalidates server state and clears cookie.
6. `Cache-Control: no-store` on sensitive responses.
7. Server-side fingerprinting with risk-based responses on drift.
8. Session tokens never in web storage. Framework defaults hardened rather than accepted.
