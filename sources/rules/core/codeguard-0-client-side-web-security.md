---
description: Client-side web security (XSS/DOM XSS, CSP, CSRF, clickjacking, XS-Leaks,
  third-party JS)
languages:
- html
- javascript
- php
- typescript
tags:
- web
alwaysApply: false
---

## Client‑side Web Security

Protect browser clients against code injection, request forgery, UI redress, cross‑site leaks, and unsafe third‑party scripts with layered, context‑aware controls.

### XSS Prevention (Context‑Aware)
- HTML context: prefer `textContent`. If HTML is required, sanitize with a vetted library (e.g., DOMPurify) and strict allow‑lists.
- Attribute context: always quote attributes and encode values.
- JavaScript context: do not build JS from untrusted strings; avoid inline event handlers; use `addEventListener`.
- URL context: validate protocol/domain and encode; block `javascript:` and data URLs where inappropriate.
- Redirects/forwards: never use user input directly for destinations; use server-side mapping (ID→URL) or validate against trusted domain allowlists.
- CSS context: allow‑list values; never inject raw style text from users.

Example sanitization:
```javascript
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['b','i','p','a','ul','li'],
  ALLOWED_ATTR: ['href','target','rel'],
  ALLOW_DATA_ATTR: false
});
```

### HTML Sanitizers: Native API and DOMPurify
- Prefer the native HTML Sanitizer API (`Element.setHTML()`, `Document.parseHTML()`) where supported; it always strips XSS‑unsafe elements and attributes, even if a custom config allows them. Browser support varies, so feature‑detect and fall back to DOMPurify.
- Never use `setHTMLUnsafe()` / `parseHTMLUnsafe()` with untrusted input.
- Pin DOMPurify and keep it current; it receives frequent bypass fixes (including mXSS bypasses). Track advisories and update promptly.
- Never re‑parse sanitized output: do not concatenate it into other HTML strings or re‑insert it via `innerHTML` inside `<script>`, `<xmp>`, `<iframe>`, `<noembed>`, `<noframes>`, or `<noscript>` wrappers (mutation XSS).
- Avoid `IN_PLACE` mode combined with hooks that remove nodes; use separate DOMPurify instances per trust boundary instead of reusing one with changing configs.
- When Trusted Types is enforced, request `RETURN_TRUSTED_TYPE: true` so the output is accepted by DOM sinks.

Feature‑detected sanitization:
```javascript
if ('setHTML' in Element.prototype) {
  el.setHTML(userHtml);
} else {
  el.innerHTML = DOMPurify.sanitize(userHtml, { RETURN_TRUSTED_TYPE: true });
}
```

### DOM‑based XSS and Dangerous Sinks
- Prohibit `innerHTML`, `outerHTML`, `document.write` with untrusted data.
- Prohibit `eval`, `new Function`, string‑based `setTimeout/Interval`.
- Validate and encode data before assigning to `location` or event handler properties.
- Use strict mode and explicit variable declarations to prevent global namespace pollution from DOM clobbering.
- Adopt Trusted Types and enforce strict CSP to prevent exploitation of DOM sinks.

Trusted Types + CSP:
```http
Content-Security-Policy: script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script'
```

### Framework Escape Hatches
Frameworks auto‑escape by default; XSS in modern apps usually enters through APIs that bypass that escaping. Treat each of these as a dangerous sink that requires sanitized or trusted input:
- React: `dangerouslySetInnerHTML`; `href`/`src`/`action` props bound to user URLs. React 19+ neutralizes `javascript:` URLs, but React ≤18 does not, and no version blocks `data:` or `vbscript:` URLs or direct `window.location` assignments.
- Vue: `v-html`; dynamic `:href`/`:src` bindings.
- Angular: `[innerHTML]` (sanitized, but avoid for untrusted rich content), and every `DomSanitizer.bypassSecurityTrust*` call.
- Svelte: `{@html ...}`.
- Any framework: refs or direct DOM access (`ref.current.innerHTML`, `this.$el.innerHTML`), server‑side rendered HTML strings, and client‑side template compilation of user input (template injection).
- Validate user‑supplied URLs against an allow‑list of schemes (`https:`, `mailto:`) before binding them to `href`/`src`.

```jsx
// Unsafe: data:/vbscript: URLs pass through (and javascript: on React <=18)
<a href={user.website}>Site</a>

// Safe: allow-list the scheme first
const safeUrl = (u) => {
  try { return ['https:', 'mailto:'].includes(new URL(u).protocol) ? u : '#'; }
  catch { return '#'; }
};
<a href={safeUrl(user.website)}>Site</a>
```

### Client‑side Prototype Pollution
Attacker‑controlled keys (`__proto__`, `constructor`, `prototype`) reaching a deep merge, clone, or set‑by‑path helper can modify `Object.prototype` and alter behavior app‑wide, often chained with a library "gadget" into DOM XSS or authorization bypass. Common sources: URL query strings and fragments (`?__proto__[x]=1`, `#constructor[prototype][x]=1`), parsed JSON, and `postMessage` data.
- Use `Map`/`Set` for untrusted dictionary keys; if an object is required, create it with `Object.create(null)`.
- Never pass untrusted input to recursive merge or set‑by‑path utilities; reject `__proto__`, `constructor`, and `prototype` key segments before writing.
- Validate parsed data against a strict schema (e.g., Zod, ajv with `additionalProperties: false`) so unexpected keys are dropped.
- Note that `Object.assign` and spread treat `__proto__` differently; strip it from untrusted objects before copying.
- Use maintained merge/query‑string libraries patched against prototype pollution; keep them updated.
- Defense in depth: `Object.freeze(Object.prototype)` where compatible with your dependencies.

### Content Security Policy (CSP)
- Prefer nonce‑based or hash‑based CSP over domain allow‑lists.
- Start with Report‑Only mode; collect violations; then enforce.
- Baseline to aim for: `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; form-action 'self'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests`.

### CSRF Defense
- Fix XSS first; then layer CSRF defenses.
- Use framework‑native CSRF protections and synchronizer tokens on all state‑changing requests.
- Cookie settings: `SameSite=Lax` or `Strict`; sessions `Secure` and `HttpOnly`; use `__Host-` prefix when possible.
- Validate Origin/Referer; require custom headers for API mutations in SPA token models.
- Never use GET for state changes; validate tokens on POST/PUT/DELETE/PATCH only. Enforce HTTPS for all token transmission.

### Clickjacking Defense
- Primary: `Content-Security-Policy: frame-ancestors 'none'` or a specific allow‑list.
- Fallback for legacy browsers: `X-Frame-Options: DENY` or `SAMEORIGIN`.
- Consider UX confirmations for sensitive actions when framing is required.

### Cross‑Site Leaks (XS‑Leaks) Controls
- Use `SameSite` cookies appropriately; prefer `Strict` for sensitive actions.
- Adopt Fetch Metadata protections to block suspicious cross‑site requests.
- Isolate browsing contexts: COOP/COEP and CORP where applicable.
- Disable caching and add user‑unique tokens for sensitive responses to prevent cache probing.

### Third‑Party JavaScript
- Minimize and isolate: prefer sandboxed iframes with `sandbox` and postMessage origin checks.
- Use Subresource Integrity (SRI) for external scripts and monitor for changes.
- Provide a first‑party, sanitized data layer; deny direct DOM access from tags where possible.
- Govern via tag manager controls and vendor contracts; keep libraries updated.

SRI example:
```html
<script src="https://cdn.vendor.com/app.js"
  integrity="sha384-..." crossorigin="anonymous"></script>
```

### HTML5, CORS, WebSockets, Storage
- postMessage: always specify exact target origin; verify `event.origin` on receive.
- CORS: avoid `*`; allow‑list origins by exact match (never reflect an unchecked request `Origin` or allow `null`, especially with credentials); validate preflights; do not rely on CORS for authz.
- WebSockets: require `wss://`, origin checks, auth, message size limits, and safe JSON parsing.
- Client storage: never store secrets in `localStorage`/`sessionStorage`; prefer HttpOnly cookies; if unavoidable, isolate via Web Workers (this hides the secret from page scripts but does not stop XSS from using it).
- Links: add `rel="noopener noreferrer"` to external `target=_blank` links.

### Secrets and Source Exposure in Client Bundles
Everything shipped to the browser is public, including minified bundles, source maps, and build‑time environment variables.
- Never embed API secrets, private keys, signing keys, or privileged tokens in frontend code. Proxy privileged calls through a backend that holds the credential.
- Treat client‑exposed env vars as public: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`, `PUBLIC_*` (SvelteKit/Astro). Only put values there that are safe for anyone to read.
- Publishable keys (e.g., Stripe `pk_*`, Firebase web config) are acceptable only when backed by server‑side restrictions (domain/referrer limits, security rules, scoped permissions).
- Do not publish source maps to production, or restrict access to them; they expose original source, comments, and internal endpoints.
- Scan build output for secrets in CI (e.g., gitleaks, trufflehog) and fail the build on findings.

### HTTP Security Headers (Client Impact)
- HSTS: enforce HTTPS everywhere.
- X‑Content‑Type‑Options: `nosniff`.
- Referrer‑Policy and Permissions‑Policy: restrict sensitive signals and capabilities.

### AJAX and Safe DOM APIs
- Avoid dynamic code execution; use function callbacks, not strings.
- Build JSON with `JSON.stringify`; never via string concatenation.
- Prefer creating elements and setting `textContent`/safe attributes over raw HTML insertion.

### Implementation Checklist
- Contextual encoding/sanitization for every sink; no dangerous APIs without guards.
- `setHTML()` used where supported with DOMPurify fallback; DOMPurify pinned to a current, patched version.
- Framework escape hatches (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `{@html}`) reviewed; user URLs scheme‑allow‑listed.
- No untrusted keys reach merge/set‑by‑path helpers; `Map` or `Object.create(null)` for untrusted dictionaries.
- No secrets in client bundles or public env vars; production source maps not publicly served.
- Strict CSP with nonces and Trusted Types; violations monitored.
- CSRF tokens on all state‑changing requests; secure cookie attributes.
- Frame protections set; XS‑Leak mitigations enabled (Fetch Metadata, COOP/COEP/CORP).
- Third‑party JS isolated with SRI and sandbox; vetted data layer only.
- HTML5/CORS/WebSocket usage hardened; no secrets in web storage.
- Security headers enabled and validated.

### Test Plan
- Automated checks for dangerous DOM/API patterns, including framework escape hatches.
- Prototype pollution probes via URL query/fragment (`?__proto__[x]=1`, then check `({}).x`); tools like DOM Invader or ppmap.
- Dependency audit for sanitizer and merge‑utility advisories (DOMPurify, lodash, query‑string parsers).
- Secret scanning of built bundles and verification that source maps are not publicly accessible.
- E2E tests for CSRF and clickjacking; CSP report monitoring.
- Manual probes for XS‑Leaks (frame count, timing, cache) and open redirect behavior.
