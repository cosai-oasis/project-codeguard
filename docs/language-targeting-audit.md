# Language Targeting Audit — Rule `languages:` Corrections

**Issue:** [#121 — Rule `languages:` lists over-target mainstream languages, inflating skill context cost](https://github.com/cosai-oasis/project-codeguard/issues/121)
**Branch:** `fix/rule-language-targeting`
**Date:** 2026-09-03

## Background

CodeGuard's progressive-disclosure routing loads rules for a given language only when that language is detected in the repository. The `languages:` frontmatter list is the trigger: any language appearing there causes the rule to be included in the agent's loaded skill set.

A survey of the tier-0 rules found that `languages:` entries had not been derived from rule body content. Many rules listed languages that appeared nowhere in their prose, guidance, or code examples. The practical consequence was that JavaScript appeared in **18 of 20 rules**, meaning a typical JS project received the full rule corpus (~21,000 tokens) regardless of the specific security concerns in scope.

### Methodology

Each contested entry was evaluated by reading the full rule body and asking:

1. Does the rule contain a code fence in this language?
2. Does the rule prose explicitly address this language, its ecosystem, or its idioms?
3. Would a developer working in this language actually apply guidance from this rule?

Only entries that failed all three tests were removed. No entries were added — additions would require the same content-grounding that was missing from the original lists.

---

## Per-Rule Changes

### 1. `codeguard-0-iac-security.md`

**Covers:** Terraform, CloudFormation, Kubernetes IaC — resource policies, IAM roles, encryption, network exposure.

| | Before | After |
|---|---|---|
| `languages:` | `c, d, hcl, javascript, powershell, ruby, shell, yaml` | `hcl, powershell, shell, yaml` |
| Removed | `c, d, javascript, ruby` | |

**Rationale:**
- `hcl` — Terraform's language; present throughout the rule.
- `yaml` — CloudFormation and Kubernetes manifests are YAML.
- `powershell` / `shell` — referenced for automation scripts alongside IaC.
- `c`, `d`, `javascript`, `ruby` — not mentioned anywhere in the rule body. IaC is a declarative infrastructure concern, not an application-language concern. There are no code fences, ecosystem references, or guidance specific to these languages in the rule.

---

### 2. `codeguard-0-cloud-orchestration-kubernetes.md`

**Covers:** Kubernetes RBAC, network policies, Pod Security Standards, OPA/Kyverno policy-as-code, secrets management — all expressed in YAML manifests.

| | Before | After |
|---|---|---|
| `languages:` | `javascript, yaml` | `yaml` |
| Removed | `javascript` | |

**Rationale:**
- The rule is entirely about Kubernetes configuration in YAML. Every code example is a YAML manifest.
- `javascript` does not appear in the rule body in any form. Policy-as-code tools (OPA/Rego, Kyverno) are not JavaScript.

---

### 3. `codeguard-0-mobile-apps.md`

**Covers:** iOS (Swift/ObjC), Android (Java/Kotlin, XML layouts), React Native (JS), secure storage, certificate pinning, intent security.

| | Before | After |
|---|---|---|
| `languages:` | `java, javascript, kotlin, matlab, perl, swift, xml` | `java, javascript, kotlin, swift, xml` |
| Removed | `matlab, perl` | |

**Rationale:**
- `java`, `kotlin`, `swift`, `javascript`, `xml` — all explicitly addressed in the rule (Android, iOS, React Native).
- `matlab` — never mentioned. MATLAB is a numerical computing environment; it is not used for iOS or Android app development.
- `perl` — never mentioned. Perl is not a mobile development language and has no presence in the rule.

---

### 4. `codeguard-0-client-side-web-security.md`

**Covers:** Browser-side security — XSS, CSP, CSRF, Subresource Integrity, clickjacking, CORS, `postMessage`, cookie flags.

| | Before | After |
|---|---|---|
| `languages:` | `c, html, javascript, php, typescript, vlang` | `html, javascript, php, typescript` |
| Removed | `c, vlang` | |

**Rationale:**
- `html`, `javascript`, `typescript`, `php` — all present in rule code fences and prose.
- `c` — absent from the rule body. Client-side browser security is a web technology domain; C has no role here.
- `vlang` — absent from the rule body. V (Vlang) is a compiled systems language unrelated to browser-side security.

---

### 5. `codeguard-0-additional-cryptography.md`

**Covers:** Symmetric/asymmetric encryption (AES-GCM, RSA, ECC), TLS, HSTS, key management, certificate handling, post-quantum readiness.

| | Before | After |
|---|---|---|
| `languages:` | `c, go, java, javascript, kotlin, matlab, php, python, ruby, swift, typescript, xml, yaml` | `c, go, java, javascript, kotlin, php, python, ruby, swift, typescript` |
| Removed | `matlab, xml, yaml` | |

**Rationale:**
- The retained languages are all mainstream application languages in which cryptographic libraries (OpenSSL, Bouncy Castle, Web Crypto API, etc.) are used. The rule body addresses crypto implementation.
- `matlab` — does not implement TLS, AES-GCM, or production cryptography. MATLAB's crypto capabilities are limited to academic/numerical contexts.
- `xml` / `yaml` — data serialization formats, not programming languages. Crypto is implemented in code, not in XML or YAML structure. XML Signatures (XMLDSig) exist, but the rule body does not address them.

---

### 6. `codeguard-0-authentication-mfa.md`

**Covers:** Argon2/bcrypt password hashing, OAuth 2.0, OIDC, WebAuthn/FIDO2, SAML, TOTP/HOTP, MFA implementation patterns.

| | Before | After |
|---|---|---|
| `languages:` | `c, go, java, javascript, kotlin, matlab, php, python, ruby, swift, typescript` | `c, go, java, javascript, kotlin, php, python, ruby, swift, typescript` |
| Removed | `matlab` | |

**Rationale:**
- All retained languages are used to build authentication systems and have well-established libraries for the protocols covered (passlib, bcrypt.js, spring-security, etc.).
- `matlab` — not used to build production authentication systems. MATLAB has no ecosystem for OAuth2, OIDC, WebAuthn, or SAML.

---

### 7. `codeguard-0-privacy-data-protection.md`

**Covers:** HTTPS enforcement, HSTS, Argon2 for passwords, session cookie security. A high-level policy rule with language-agnostic prose.

| | Before | After |
|---|---|---|
| `languages:` | `javascript, matlab, yaml` | `javascript` |
| Removed | `matlab, yaml` | |

**Rationale:**
- `javascript` — the only language with a code presence in the rule body (cookie `SameSite` attribute example).
- `matlab` — not a web application language; privacy/data protection patterns (HTTPS, session cookies, Argon2) are irrelevant to MATLAB.
- `yaml` — a configuration format, not a language in which privacy controls are implemented. The rule does not discuss YAML-specific configuration for privacy.

---

### 8. `codeguard-0-devops-ci-cd-containers.md`

**Covers:** CI/CD pipeline hardening, Docker/container security, Node.js container patterns, virtual patching, C/C++ toolchain flags.

| | Before | After |
|---|---|---|
| `languages:` | `docker, javascript, powershell, shell, xml, yaml` | `docker, javascript, powershell, shell, yaml` |
| Removed | `xml` | |

**Rationale:**
- `docker` — Dockerfiles throughout the rule.
- `yaml` — CI pipeline definitions (GitHub Actions, etc.) and Kubernetes references.
- `javascript` / `powershell` / `shell` — rule has a dedicated "Node.js in Containers" section and references shell/PowerShell automation.
- `xml` — not referenced in the rule body. While Maven POM files are XML, they are not addressed in this rule. The C/C++ toolchain section discusses compiler flags, not build-system XML.

---

### 9. `codeguard-0-session-management-and-cookies.md`

**Covers:** Session ID generation, cookie security attributes (`Secure`, `HttpOnly`, `SameSite`), session lifecycle, theft detection.

| | Before | After |
|---|---|---|
| `languages:` | `c, go, java, javascript, php, python, ruby, typescript` | `go, java, javascript, php, python, ruby, typescript` |
| Removed | `c, html` | |

**Rationale:**
- The retained languages are all common web application languages with HTTP session frameworks.
- `c` — HTTP session management in C is uncommon and not addressed in the rule body. The rule references web frameworks (Django, Rails, Express, etc.) that have no C ecosystem.
- `html` — HTML is a markup language, not one in which session logic is implemented. The one `Set-Cookie` header example in the rule is a raw HTTP header, not HTML.

---

### 10. `codeguard-0-api-web-services.md`

**Covers:** REST, GraphQL, SOAP/WS security — transport, auth tokens, input validation, SSRF, rate limiting, microservices.

| | Before | After |
|---|---|---|
| `languages:` | `c, go, java, javascript, php, python, ruby, typescript, xml, yaml` | `go, java, javascript, php, python, ruby, typescript, xml` |
| Removed | `c, yaml` | |

**Rationale:**
- `xml` — retained: the rule has a dedicated "SOAP/WS and XML Safety" section covering XSD validation, entity expansion, XML Signatures.
- `c` — absent from the rule body. REST and GraphQL APIs in C are uncommon and not addressed; the rule's framework references (Spring, Django, Node.js, Rails) have no C presence.
- `yaml` — OpenAPI schemas are written in YAML, but the rule refers to "OpenAPI/JSON Schema" for contract validation, not YAML authoring. YAML is a serialization format, not an API implementation language.

---

### 11. `codeguard-0-framework-and-languages.md`

**Covers:** Django/DRF, Laravel, Symfony, Rails, .NET/ASP.NET Core, Java/JAAS, Node.js, PHP — secure-by-default patterns per platform.

| | Before | After |
|---|---|---|
| `languages:` | `c, java, javascript, kotlin, php, python, ruby, typescript, xml, yaml` | `c, java, javascript, kotlin, php, python, ruby, typescript` |
| Removed | `xml, yaml` | |

**Rationale:**
- All retained languages correspond to explicitly named sections (Django → Python, Laravel/Symfony → PHP, Rails → Ruby, .NET → C#/TypeScript, Java/JAAS → Java, Node.js → JavaScript, JAAS → Java, .NET → C).
- `xml` — not a framework or application language. While Spring configuration can use XML, the rule does not address it; the Java/JAAS section focuses on `PreparedStatement`, XSS output encoding, and JAAS `LoginModule` — not XML config.
- `yaml` — Spring Boot YAML configs and similar exist, but the rule body contains no YAML-specific guidance. Application frameworks are implemented in code, not YAML.

---

### 12. `codeguard-0-logging.md`

**Covers:** Structured logging, log sanitization, redaction, integrity, detection/alerting, privacy compliance.

| | Before | After |
|---|---|---|
| `languages:` | `c, javascript, yaml` | `c, javascript` |
| Removed | `yaml` | |

**Rationale:**
- `c` / `javascript` — retained as the only two languages with any footing in the rule. The rule is largely language-agnostic prose, so these are a minimal representative set.
- `yaml` — logging configuration (log4j2.yaml, etc.) is a YAML concern, but the rule addresses *what* and *how* to log (sanitization, redaction, structured fields) — not logger configuration files. Application logging logic is written in code, not YAML.

---

## Summary Table

| Rule | Removed entries | Remaining `languages:` |
|------|-----------------|------------------------|
| `codeguard-0-iac-security` | `c, d, javascript, ruby` | `hcl, powershell, shell, yaml` |
| `codeguard-0-cloud-orchestration-kubernetes` | `javascript` | `yaml` |
| `codeguard-0-mobile-apps` | `matlab, perl` | `java, javascript, kotlin, swift, xml` |
| `codeguard-0-client-side-web-security` | `c, vlang` | `html, javascript, php, typescript` |
| `codeguard-0-additional-cryptography` | `matlab, xml, yaml` | `c, go, java, javascript, kotlin, php, python, ruby, swift, typescript` |
| `codeguard-0-authentication-mfa` | `matlab` | `c, go, java, javascript, kotlin, php, python, ruby, swift, typescript` |
| `codeguard-0-privacy-data-protection` | `matlab, yaml` | `javascript` |
| `codeguard-0-devops-ci-cd-containers` | `xml` | `docker, javascript, powershell, shell, yaml` |
| `codeguard-0-session-management-and-cookies` | `c, html` | `go, java, javascript, php, python, ruby, typescript` |
| `codeguard-0-api-web-services` | `c, yaml` | `go, java, javascript, php, python, ruby, typescript, xml` |
| `codeguard-0-framework-and-languages` | `xml, yaml` | `c, java, javascript, kotlin, php, python, ruby, typescript` |
| `codeguard-0-logging` | `yaml` | `c, javascript` |

**Total entries removed:** 21 across 12 rules.

## Impact

Before these changes, a JavaScript repository triggered **18 of 20** core rules. After, it triggers **16**. The two rules no longer triggered for JavaScript are:

- `codeguard-0-iac-security` (Terraform/CloudFormation — JS removed)
- `codeguard-0-cloud-orchestration-kubernetes` (K8s YAML only — JS removed)

More significant reductions apply to languages that were only spuriously included. A repository detected as pure HCL (Terraform) now loads 1 rule instead of potentially many. A MATLAB repository no longer loads cryptography, authentication, or privacy rules.

The remaining JavaScript count (16 rules) reflects genuine applicability — JavaScript spans browser security, Node.js APIs, mobile (React Native), frameworks, session management, and more. A follow-on issue should evaluate whether the `javascript` entries that remain are individually justified.
