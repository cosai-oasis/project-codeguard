# Secure Coding Skill — Sources & Attribution

This skill is a consolidated, reorganized **rewrite** of publicly available secure-coding guidance. It is not AI-generated slop — every rule is traceable to at least one upstream document maintained by a credible organization (OWASP Foundation, OASIS / CoSAI, CERT / SEI, NIST, IETF, browser and cloud vendors).

This README documents where each rule draws from. Security facts (algorithm names, HTTP header semantics, bcrypt cost factors, CVE mitigation patterns) are industry consensus and are not subject to copyright. Phrasing, structure, and organization have been substantially rewritten in this skill's own voice. Where a phrase from an upstream document would be more precise than a paraphrase, it appears here as a short quotation with the source named.

## Content policy

1. **Facts are facts.** Stating that "AES-GCM is an AEAD mode" or that "session IDs should come from a CSPRNG" is repeating established industry practice, not reproducing anyone's prose.
2. **Structure is our own.** The two-tier (always-apply + context) organization, the language-to-rules lookup table, the before/during/after workflow, and the ordering inside each rule are specific to this skill.
3. **Examples are re-authored.** Code snippets have been rewritten to illustrate the guidance in minimal, self-contained form.
4. **Attribution is given.** Primary inspirations are listed per rule below so reviewers can verify context and go deeper if they want.

## Primary sources

### OWASP Cheat Sheet Series

- **Project site**: <https://cheatsheetseries.owasp.org/>
- **License**: Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA 4.0)
- **Repository**: <https://github.com/OWASP/CheatSheetSeries>
- **Role in this skill**: canonical reference for input validation, XSS, CSRF, password storage, session management, XML/deserialization, upload handling, access control, logging, cryptographic storage, and many framework guides.

### OASIS CoSAI — Project CodeGuard

- **Project site**: <https://project-codeguard.org/>
- **Coalition**: Coalition for Secure AI (OASIS Open Project) — <https://www.oasis-open.org/projects/cosai/>
- **Repository**: <https://github.com/cosai-oasis/project-codeguard>
- **License**: CC-BY-4.0 for rules and skills content
- **Role in this skill**: the core ruleset structure (always-apply + context rules, language-to-rules mapping, MCP security guidance, post-quantum crypto posture) was directly inspired by Project CodeGuard. The present skill replaces wording and re-organizes content but retains the same overall model.

### CERT C Secure Coding Standard

- **Project site**: <https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard>
- **Publisher**: Software Engineering Institute, Carnegie Mellon University
- **Role in this skill**: basis for the C/C++ memory safety rule — banned-function list, bounded replacements, sensitive-memory zeroization, toolchain flags.

### NIST publications

- **SP 800-63B** — Digital Identity Guidelines (authentication and lifecycle management). <https://pages.nist.gov/800-63-3/sp800-63b.html>
- **SP 800-90A/B/C** — Random bit generation.
- **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)**, **FIPS 203 (ML-KEM)** — post-quantum signature and KEM standards.
- **Role in this skill**: authoritative source for password policy, MFA factor hierarchy, and the selection of post-quantum-ready primitives.

### IETF RFCs (transport and crypto)

- **RFC 8446** — TLS 1.3.
- **RFC 7525** — Recommendations for Secure Use of TLS.
- **RFC 6797** — HTTP Strict Transport Security.
- **RFC 6265bis** — Cookies (SameSite, `__Host-` prefix).
- **RFC 7519** — JSON Web Token.
- **RFC 6749 / 8252 / 7636** — OAuth 2.0 and PKCE.
- **RFC 9242 / 9370** — IKEv2 post-quantum hybrid key exchange.
- **Role in this skill**: authoritative for transport-layer configuration, cookie semantics, token handling, and hybrid PQC key exchange.

### Vendor security guides

- **OWASP Mobile Application Security Testing Guide / Verification Standard** (MASTG / MASVS) — <https://mas.owasp.org/>
- **OWASP API Security Top 10 (2023)** — <https://owasp.org/API-Security/>
- **Android Developers — Security guidance** — <https://developer.android.com/topic/security/best-practices>
- **Apple Platform Security Guide** — <https://support.apple.com/guide/security/welcome/web>
- **CIS Benchmarks** — Docker, Kubernetes, cloud platforms. <https://www.cisecurity.org/cis-benchmarks>
- **SLSA framework** — <https://slsa.dev/>
- **Sigstore / Cosign** — <https://www.sigstore.dev/>
- **SPIFFE / SPIRE** — <https://spiffe.io/>
- **Role in this skill**: mobile, API, container, Kubernetes, IaC, and supply-chain rules.

### Browser security

- **MDN Web Docs — Web Security** — <https://developer.mozilla.org/en-US/docs/Web/Security>
- **W3C / WICG — Content Security Policy, Trusted Types, Permissions Policy, Fetch Metadata, COOP/COEP/CORP** — specs at <https://www.w3.org/TR/> and <https://wicg.github.io/>
- **Google Web Fundamentals — Secure by Default** — <https://web.dev/secure/>
- **Role in this skill**: client-side web security rule (XSS, CSP, Trusted Types, CSRF, clickjacking, XS-Leaks, third-party JavaScript, secure HTTP headers).

### Cloud provider reference architectures

- AWS Well-Architected Framework — Security Pillar.
- Google Cloud Security Foundations.
- Azure Security Benchmark.
- **Role in this skill**: IaC and Kubernetes rules (network posture, IAM, encryption, logging, backup).

### Model Context Protocol

- **Specification**: <https://modelcontextprotocol.io/>
- **CoSAI MCP Security Guidelines**: <https://www.oasis-open.org/projects/cosai/>
- **Role in this skill**: the MCP security rule.

## Per-rule attribution

Each rule below lists its primary inspirations. Many rules draw on several sources — they're listed in rough order of contribution.

### Tier A — always apply

| Rule | Primary sources |
|------|-----------------|
| `always-no-hardcoded-secrets.md` | Project CodeGuard hardcoded-credentials rule; OWASP Secrets Management Cheat Sheet; industry secret-pattern regexes (AWS, GitHub, Stripe, Google, Slack). |
| `always-crypto-algorithms.md` | Project CodeGuard crypto-algorithms rule; NIST FIPS 203 / 204 / 205; RFC 8446 (TLS 1.3); RFC 9242 / 9370 (IKEv2 PQC); OpenSSL EVP API documentation; guidance from BSI, NCSC, CNSA 2.0. |
| `always-certificate-hygiene.md` | Project CodeGuard digital-certificates rule; RFC 5280 (X.509); OpenSSL command reference; CA/Browser Forum Baseline Requirements. |

### Tier B — context rules

| Rule | Primary sources |
|------|-----------------|
| `rule-additional-cryptography.md` | OWASP Cryptographic Storage Cheat Sheet, Transport Layer Security Cheat Sheet, HSTS Cheat Sheet, Pinning Cheat Sheet; NIST SP 800-52; RFC 6797 (HSTS); RFC 7919 (FFDHE). |
| `rule-api-web-services.md` | OWASP API Security Top 10 (2023); OWASP REST Security Cheat Sheet, GraphQL Cheat Sheet, SOAP/Web Service Security Cheat Sheet, SSRF Prevention Cheat Sheet, Microservices Security Cheat Sheet; OpenAPI / JSON Schema specifications. |
| `rule-authentication-mfa.md` | NIST SP 800-63B; OWASP Authentication Cheat Sheet, Password Storage Cheat Sheet, MFA Cheat Sheet, Forgot Password Cheat Sheet, JWT for Java Cheat Sheet, SAML Security Cheat Sheet, OAuth 2.0 Cheat Sheet; RFC 7519, RFC 6749/6819, RFC 8252, RFC 7636; IETF OAuth 2.0 Security BCP (RFC 8725/9700). |
| `rule-authorization-access-control.md` | OWASP Authorization Cheat Sheet, Access Control Cheat Sheet, IDOR Prevention Cheat Sheet, Mass Assignment Cheat Sheet, Transaction Authorization Cheat Sheet; OWASP Top 10 A01:2021 (Broken Access Control). |
| `rule-client-web-browser.md` | OWASP XSS Prevention Cheat Sheet, DOM-based XSS Prevention, Content Security Policy Cheat Sheet, CSRF Prevention Cheat Sheet, Clickjacking Defense Cheat Sheet, XS-Leaks Cheat Sheet, Third-Party JavaScript Management, HTML5 Security Cheat Sheet, HTTP Headers Cheat Sheet; W3C CSP 3, Trusted Types, Fetch Metadata, COOP/COEP/CORP specs; MDN Web Security docs. |
| `rule-kubernetes-hardening.md` | CIS Kubernetes Benchmark; Kubernetes official docs — Pod Security Standards, NetworkPolicy, RBAC; OPA Gatekeeper / Kyverno policy libraries; Sigstore cosign docs; SLSA framework. |
| `rule-database-data-storage.md` | OWASP Database Security Cheat Sheet; CIS Benchmarks (MySQL, PostgreSQL, SQL Server, MongoDB, Redis); vendor security guides for each database; PCI DSS v4 guidance. |
| `rule-ci-cd-containers.md` | OWASP CI/CD Security Cheat Sheet, Docker Security Cheat Sheet, Node.js Docker Cheat Sheet, C-Based Toolchain Hardening, Virtual Patching Cheat Sheet; CIS Docker Benchmark; SLSA; Sigstore; BuildKit secret docs. |
| `rule-file-upload-handling.md` | OWASP File Upload Cheat Sheet; OWASP Unrestricted File Upload; Snyk and various vendor CVE writeups for image and document parsers; zip-slip and zip-bomb reference material. |
| `rule-framework-language-guides.md` | OWASP cheat sheets per framework: Django Security, Django REST Framework, Laravel, Symfony, Ruby on Rails, .NET Security, Java Security, JAAS, Node.js Security, PHP Configuration; framework-official security guides (Django docs "Security", Rails Security Guide, ASP.NET Core Security, Laravel Security, Symfony Security). |
| `rule-infrastructure-as-code.md` | CIS Cloud Benchmarks (AWS, Azure, GCP); AWS Well-Architected Security Pillar; Google Cloud Security Foundations; Azure Security Benchmark; Terraform security docs; CloudFormation best practices. |
| `rule-input-validation-injection.md` | OWASP Input Validation Cheat Sheet, Injection Prevention, SQL Injection Prevention, OS Command Injection Defense, LDAP Injection Prevention, Query Parameterization, Prototype Pollution Prevention; Salesforce Apex SOQL injection guidance; OWASP Top 10 A03:2021. |
| `rule-logging-monitoring.md` | OWASP Logging Cheat Sheet, Logging Vocabulary Cheat Sheet; NIST SP 800-92 (Guide to Computer Security Log Management); OWASP Top 10 A09:2021 (Security Logging and Monitoring Failures). |
| `rule-mcp-security.md` | OASIS CoSAI MCP Security Guidelines; Model Context Protocol specification; SPIFFE/SPIRE docs; OWASP Top 10 for LLM Applications. |
| `rule-mobile-app-security.md` | OWASP Mobile Application Security Verification Standard (MASVS); OWASP Mobile Security Testing Guide (MSTG); Android Developers security guidance; Apple Platform Security Guide; Play Integrity API and App Attest documentation. |
| `rule-privacy-data-protection.md` | OWASP User Privacy Protection Cheat Sheet; GDPR Articles 5, 15–22, 25, 32; ISO/IEC 27701; NIST Privacy Framework. |
| `rule-c-cpp-memory-safety.md` | CERT C Secure Coding Standard — STR, MEM, INT rules; C11 Annex K (bounds-checking interfaces); ISO/IEC TR 24731; OpenSSL `OPENSSL_cleanse` docs; compiler documentation (GCC, Clang) for hardening flags. |
| `rule-sessions-cookies.md` | OWASP Session Management Cheat Sheet, Cookie Theft Mitigation Cheat Sheet; RFC 6265bis (cookie `SameSite`, `__Host-` prefix); OWASP Top 10 A07:2021. |
| `rule-supply-chain-dependencies.md` | OWASP Vulnerable Dependency Management Cheat Sheet, NPM Security Cheat Sheet, Software Component Verification Standard (SCVS); SLSA framework; Sigstore; OWASP Top 10 A06:2021 (Vulnerable and Outdated Components); OpenSSF Scorecard. |
| `rule-xml-serialization-hardening.md` | OWASP XML External Entity Prevention Cheat Sheet, Deserialization Cheat Sheet, XML Security Cheat Sheet; `defusedxml` Python package documentation; vendor docs for Jackson, XStream, Json.NET with safe configuration. |

## What this skill is not

- Not a substitute for a security review. A threat model specific to the application still matters.
- Not a complete security policy. It covers *coding* guardrails; it does not cover people, process, physical security, vendor onboarding, or incident response in depth.
- Not a certification. Compliance with PCI DSS, HIPAA, SOC 2, ISO 27001, and similar frameworks requires controls and evidence beyond what a coding skill can provide.

## Contributing and feedback

If a rule has a gap, an inaccuracy, or a better-worded alternative, open an issue or PR against the repository. Keep in mind:

- Keep the two-tier structure (always + context).
- Do not reintroduce large verbatim quotes from upstream sources.
- Cite new sources in this README when you add them.
- Keep code examples short and self-contained — they are illustrative, not tutorials.

## License

This skill is distributed under the same license as the repository it lives in — see [`LICENSE.md`](../../LICENSE.md) at the repository root. Upstream sources retain their own licenses; the attributions above exist so users can consult them directly.
