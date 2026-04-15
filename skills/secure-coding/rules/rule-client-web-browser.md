---
description: Client-side web security — XSS, CSP, CSRF, clickjacking, XS-Leaks, third-party scripts, browser storage
languages:
  - c
  - html
  - javascript
  - php
  - typescript
  - vlang
alwaysApply: false
rule_id: rule-client-web-browser
---

# Client-Side Web Security

## Threat model

Once content is in a browser, the attacker's goal is to execute script in the origin, trick the user into an unintended action, or read data across an origin boundary. Defenses are layered: contextual encoding, Content Security Policy, CSRF tokens, frame controls, XS-Leak mitigations, and careful handling of third-party code.

Fixing XSS first is the most leverage you can apply — most of the other defenses either presume XSS is gone or help mitigate its consequences.

## XSS — encode per context

An input is safe for exactly one rendering context. "HTML-escaped" is not universally safe.

| Context | Correct encoding |
|---------|------------------|
| HTML body | `textContent`, or HTML-escape and insert as HTML |
| HTML attribute (quoted) | Attribute-escape; always quote attributes |
| `href`, `src` | Validate scheme (`https:` only, or explicit allow-list) and URL-encode |
| JavaScript string literal | JSON-encode inside a `<script>` block; **never** build JS from untrusted strings |
| CSS value | Allow-list numeric / color values; never inject raw style text |
| URL path/query | URL-encode each component with the correct encoder |

Patterns to avoid entirely:

- Concatenating untrusted strings into `innerHTML`, `outerHTML`, `document.write`, `Range.createContextualFragment`.
- Passing untrusted input to `eval`, `new Function`, string-form `setTimeout` / `setInterval`, `setImmediate`, `execScript`.
- Setting event-handler attributes (`onclick="..."`) with untrusted values. Use `addEventListener` with a JS function instead.
- Assigning untrusted strings to `location`, `location.href`, `window.name`.

When HTML must be rendered (rich-text user input, rendered Markdown), run it through a vetted sanitizer:

```js
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['p', 'b', 'i', 'ul', 'li', 'a'],
  ALLOWED_ATTR: ['href', 'rel', 'target'],
  ALLOW_DATA_ATTR: false,
});
element.innerHTML = clean;
```

Prefer server-side sanitization when possible — the server is easier to keep consistent across clients.

### Trusted Types

In modern browsers, enforce Trusted Types to make the dangerous sinks refuse strings that have not been typed-checked by an allow-listed policy. This is the single most effective XSS mitigation currently deployable.

```http
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types my-app#default
```

```js
const policy = trustedTypes.createPolicy('my-app', {
  createHTML: input => DOMPurify.sanitize(input),
});
element.innerHTML = policy.createHTML(userHtml);
```

## Content Security Policy

CSP is a backstop for XSS, not a primary defense. Deploy it alongside encoding, not instead of it.

### Guidance

- Prefer **nonce-based** or **hash-based** policies. Host allow-lists (`script-src example.com`) are brittle and routinely bypassed via JSONP endpoints.
- Start in **Report-Only** mode, ship the reporting endpoint, fix what breaks, then enforce.
- Forbid inline script unless nonced; forbid `eval` (`'unsafe-eval'`).
- Set `object-src 'none'` and `base-uri 'self'` — these close off common bypass tricks.
- Set `frame-ancestors` to replace `X-Frame-Options` (see Clickjacking below).

### A reasonable baseline

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM}';
  style-src 'self';
  img-src 'self' data:;
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'self';
  form-action 'self';
  upgrade-insecure-requests;
  require-trusted-types-for 'script';
  report-to csp-reports
```

## CSRF defense

Any state-changing request (POST, PUT, PATCH, DELETE) must be CSRF-protected. For a session-cookie authenticated site:

- Use a framework-provided synchronizer token; reject the request if the token is missing, blank, or doesn't match the session.
- Set session cookies `Secure`, `HttpOnly`, `SameSite=Lax` (default) or `SameSite=Strict` (stricter). The `__Host-` prefix makes the cookie "host-only" and `Secure`-only.
- Validate `Origin` and/or `Referer` on cross-origin mutations. Missing `Origin` on a mutation is itself suspicious.
- GET must never change state. A GET endpoint that mutates is CSRF-able by a simple `<img src>`.

For token-authenticated APIs (the token is in an `Authorization: Bearer` header, not a cookie), CSRF is structurally prevented — a foreign origin cannot set that header cross-site. But: if you read the token from local storage and put it there, see `rule-sessions-cookies.md` on storage risk.

## Clickjacking

- Primary: `Content-Security-Policy: frame-ancestors 'none'` (or a specific list).
- Legacy fallback for older browsers: `X-Frame-Options: DENY` or `SAMEORIGIN`. Browsers that support CSP ignore this header in favor of `frame-ancestors`.
- For sensitive actions that must be framable, add a UX confirmation step that attacker frames cannot easily forge.

## Cross-site leaks (XS-Leaks)

Cross-site leak attacks infer information (logged in? has resource?) from observable side channels: response size, timing, frame count, error behavior, cache hits.

- Set cookies `SameSite=Strict` for actions that should never be triggered from other origins.
- Adopt **Fetch Metadata** request headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`) and reject cross-site requests you do not expect.
- Send **COOP** (`Cross-Origin-Opener-Policy: same-origin`), **COEP** (`Cross-Origin-Embedder-Policy: require-corp`), and **CORP** (`Cross-Origin-Resource-Policy: same-origin`) to isolate browsing contexts.
- Send `Cache-Control: no-store` on sensitive responses, and consider adding a random per-user token to cacheable URLs to prevent cache-probe attacks.

## Third-party JavaScript

Every tag you let onto the page runs in your origin. Minimize and isolate.

- Prefer sandboxed iframes with `sandbox="allow-scripts"` (no `allow-same-origin`) and `postMessage` with explicit-origin checks.
- For scripts served from a CDN, enable **Subresource Integrity**:
  ```html
  <script src="https://cdn.vendor.com/app.js"
          integrity="sha384-abc123..."
          crossorigin="anonymous"></script>
  ```
- Expose a first-party, sanitized data layer to vendor tags rather than letting them query the DOM directly.
- Govern via tag manager rules and vendor contracts; keep libraries patched.

## HTML5 APIs — CORS, WebSockets, storage, postMessage

- **`postMessage`**: always specify an exact target origin (`"*"` is never correct); always validate `event.origin` on the receiving side.
- **CORS**: use a specific origin allow-list, not `*`. CORS is a browser policy for read access — it is **not** an authorization mechanism; do not rely on it to protect state-changing endpoints. Validate preflight requests.
- **WebSockets**: `wss://` only. Check the `Origin` header on upgrade. Authenticate immediately. Cap message size.
- **Web storage** (`localStorage`, `sessionStorage`): do not store session tokens or any other credentials here. Any XSS gets them trivially. Use `HttpOnly` cookies for session material; if you need client-accessible state, keep it non-sensitive or isolate behind a Web Worker.
- **Links**: `target="_blank"` + external host must carry `rel="noopener noreferrer"`.

## HTTP security headers (browser-visible)

In addition to CSP / frame-ancestors:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (preload after it's battle-tested).
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for sensitive paths).
- `Permissions-Policy` with the features you actually use; everything else denied.

## Safe DOM patterns

- Build the DOM with `document.createElement` and set `textContent` / safe attributes — avoid raw HTML insertion.
- Build JSON with `JSON.stringify`, never with string concatenation.
- Prefer `addEventListener` over attribute-based handlers.
- Use strict mode and modules (`<script type="module">`) — both narrow the scope of accidental global leaks relevant to DOM clobbering.

## Implementation checklist

- Every rendering sink has contextual encoding; no `innerHTML` with untrusted data.
- CSP with nonces + Trusted Types enforced; violations flowing to a monitored endpoint.
- CSRF tokens on all state-changing requests (unless authenticated by a non-cookie header); cookies `Secure` + `HttpOnly` + `SameSite`.
- `frame-ancestors` set; `X-Frame-Options` as fallback.
- Fetch Metadata checks on sensitive endpoints; COOP / COEP / CORP as applicable.
- Third-party scripts minimized, sandboxed where possible, SRI-pinned.
- No session material in web storage; `target="_blank"` links carry `rel="noopener noreferrer"`.
- Security headers present and validated by an automated check.

## Test plan

- Static scans for dangerous DOM APIs and missing encoding.
- End-to-end tests that submit CSRF forms without a token and confirm rejection.
- Clickjacking — verify the page refuses to frame in an arbitrary parent.
- CSP report monitoring in staging for a week before enforcing.
- Manual XS-Leak probes (frame count, timing, cache) on sensitive endpoints.
- Open-redirect probes on every endpoint that takes a URL or domain parameter.
