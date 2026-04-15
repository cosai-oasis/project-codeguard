---
name: secure-coding
description: Secure-by-default coding guardrails for AI coding agents. Load this skill when generating, editing, or reviewing code so that common vulnerability classes (injection, weak crypto, auth/authz gaps, hardcoded secrets, unsafe deserialization, etc.) are prevented rather than patched later.
version: "1.0"
scope: "software security for AI-assisted code generation and review"
---

# Secure Coding Skill

AI coding agents move fast, and by default they optimize for "code that works on the happy path." This skill rebalances that default by injecting security checkpoints the agent consults **before** writing code, **while** writing it, and **after** it is written.

The ruleset is a consolidated, reorganized rewrite of publicly available secure-coding guidance (OWASP Cheat Sheet Series, CERT C, platform hardening guides, and the CoSAI Project CodeGuard ruleset). Sources are listed in [README.md](README.md). Content has been substantially rewritten; the underlying security facts themselves are industry consensus and uncopyrightable.

---

## When the agent should load this skill

Load it whenever code is about to be written, modified, or reviewed — and especially in the following situations:

- A new feature, endpoint, handler, or form is being added
- Existing code is being refactored or extended in a security-sensitive area
- Any of these show up in the task: authentication, session handling, cryptography, file upload, database access, IPC/RPC, serialization, XML/YAML/JSON parsing, command execution, template rendering, inter-service calls
- The task touches infrastructure-as-code, containers, CI/CD, or cluster configuration
- Secrets, credentials, tokens, or keys appear in scope
- Code review is explicitly requested

If none of the above apply and the change is cosmetic (e.g., formatting, renaming a private variable, adjusting a log string with no user data), the skill can be skipped — but when in doubt, load it.

---

## How to use this skill

The ruleset has two tiers.

### Tier A — Always apply

Three rules are unconditional. They must be consulted on **every** code operation regardless of language or feature area:

- [`always-no-hardcoded-secrets.md`](rules/always-no-hardcoded-secrets.md) — secrets, keys, tokens, and credentials must never appear in source
- [`always-crypto-algorithms.md`](rules/always-crypto-algorithms.md) — what cryptography is allowed, what is banned, post-quantum posture
- [`always-certificate-hygiene.md`](rules/always-certificate-hygiene.md) — inspecting and validating X.509 certificates encountered in code

### Tier B — Context rules (language × domain)

The remaining 20 rules are loaded based on the language of the file being edited and the security domain the task touches. Use this lookup table:

| Language | Rules to load |
|----------|---------------|
| **apex** | input-validation-injection |
| **c** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, database-data-storage, file-upload-handling, framework-language-guides, infrastructure-as-code, input-validation-injection, logging-monitoring, c-cpp-memory-safety, sessions-cookies, xml-serialization-hardening |
| **cpp** | c-cpp-memory-safety |
| **d** | infrastructure-as-code |
| **docker** | ci-cd-containers, supply-chain-dependencies |
| **go** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, input-validation-injection, mcp-security, sessions-cookies, xml-serialization-hardening |
| **html** | client-web-browser, input-validation-injection, sessions-cookies |
| **java** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, framework-language-guides, input-validation-injection, mcp-security, mobile-app-security, sessions-cookies, xml-serialization-hardening |
| **javascript** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, kubernetes-hardening, database-data-storage, ci-cd-containers, file-upload-handling, framework-language-guides, infrastructure-as-code, input-validation-injection, logging-monitoring, mcp-security, mobile-app-security, privacy-data-protection, sessions-cookies, supply-chain-dependencies |
| **kotlin** | additional-cryptography, authentication-mfa, framework-language-guides, mobile-app-security |
| **matlab** | additional-cryptography, authentication-mfa, mobile-app-security, privacy-data-protection |
| **perl** | mobile-app-security |
| **php** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, file-upload-handling, framework-language-guides, input-validation-injection, sessions-cookies, xml-serialization-hardening |
| **powershell** | ci-cd-containers, infrastructure-as-code, input-validation-injection |
| **python** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, framework-language-guides, input-validation-injection, mcp-security, sessions-cookies, xml-serialization-hardening |
| **ruby** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, framework-language-guides, infrastructure-as-code, input-validation-injection, sessions-cookies, xml-serialization-hardening |
| **rust** | mcp-security |
| **shell** | ci-cd-containers, infrastructure-as-code, input-validation-injection |
| **sql** | database-data-storage, input-validation-injection |
| **swift** | additional-cryptography, authentication-mfa, mobile-app-security |
| **typescript** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, file-upload-handling, framework-language-guides, input-validation-injection, mcp-security, sessions-cookies |
| **vlang** | client-web-browser |
| **xml** | additional-cryptography, api-web-services, ci-cd-containers, framework-language-guides, mobile-app-security, xml-serialization-hardening |
| **yaml** | additional-cryptography, api-web-services, authorization-access-control, kubernetes-hardening, database-data-storage, ci-cd-containers, framework-language-guides, infrastructure-as-code, logging-monitoring, privacy-data-protection, supply-chain-dependencies |

Rule filenames above refer to files in `rules/` and are prefixed `rule-` in the actual filesystem (for example `rule-input-validation-injection.md`).

If the language is not listed, fall back to the closest paradigm (interpreted web → javascript; compiled systems → c/go; statically-typed JVM → java) and still apply all three Tier A rules.

---

## Workflow: before, during, after

### Before writing

Ask three questions, in order:

1. **Credentials?** If the feature touches secrets/keys/tokens in any way, open `always-no-hardcoded-secrets.md` first — it changes *where* the data must live.
2. **Language(s)?** Use the table above to select Tier B rules.
3. **Security domain(s)?** Map the task to domains (injection, auth, crypto, upload, parsing, IaC, …) and load those rules even if the table already implicitly covers them. Loading extras is cheaper than missing a checklist.

At the end of step 3 the agent should have a concrete list of rule files to keep in working context.

### While writing

- Default to the secure pattern shown in each applicable rule, not the pattern that comes to mind first.
- When the secure path and the "clean" path disagree, pick the secure path and leave a one-line comment explaining the choice. Future reviewers (human or AI) need to see the intent.
- Do not silently downgrade a security property to make a test pass. If a rule's guidance blocks the task, stop and flag it instead.

### After writing

Walk the implementation checklist inside each loaded rule. For each item, answer one of:
- **Applied** — and briefly note where (file/function).
- **Not applicable** — with a one-sentence reason.
- **Deferred** — with an explicit follow-up note; do not mark the task complete on a deferred security item without the user's acknowledgment.

When the agent produces its final summary, it should name which rules were applied and call out any security-relevant features it added (parameterized queries, CSRF tokens, bcrypt hashing, etc.) so reviewers can audit the choices quickly.

---

## Proactive posture

Avoidance is not enough — the agent should **actively choose** secure patterns even when the user did not ask:

- Parameterized queries are the default, not "added later."
- User input is validated at the trust boundary (schema / allow-list / size / type), not just trusted and used.
- Least-privilege is chosen over convenience — narrow IAM roles, scoped tokens, single-purpose service accounts.
- Modern, authenticated cryptography (AES-GCM / ChaCha20-Poly1305 / Ed25519 / X25519) is the default; legacy algorithms appear only with an explicit migration reason.
- Defense in depth: a control is not "enough" because another layer also has it. CSP plus encoding, input validation plus parameterization, authz checks at gateway and service, etc.

---

## Rule index

All rules live in [`rules/`](rules/). Quick index:

**Tier A — always apply:**
- [always-no-hardcoded-secrets.md](rules/always-no-hardcoded-secrets.md)
- [always-crypto-algorithms.md](rules/always-crypto-algorithms.md)
- [always-certificate-hygiene.md](rules/always-certificate-hygiene.md)

**Tier B — context:**
- [rule-additional-cryptography.md](rules/rule-additional-cryptography.md)
- [rule-api-web-services.md](rules/rule-api-web-services.md)
- [rule-authentication-mfa.md](rules/rule-authentication-mfa.md)
- [rule-authorization-access-control.md](rules/rule-authorization-access-control.md)
- [rule-client-web-browser.md](rules/rule-client-web-browser.md)
- [rule-kubernetes-hardening.md](rules/rule-kubernetes-hardening.md)
- [rule-database-data-storage.md](rules/rule-database-data-storage.md)
- [rule-ci-cd-containers.md](rules/rule-ci-cd-containers.md)
- [rule-file-upload-handling.md](rules/rule-file-upload-handling.md)
- [rule-framework-language-guides.md](rules/rule-framework-language-guides.md)
- [rule-infrastructure-as-code.md](rules/rule-infrastructure-as-code.md)
- [rule-input-validation-injection.md](rules/rule-input-validation-injection.md)
- [rule-logging-monitoring.md](rules/rule-logging-monitoring.md)
- [rule-mcp-security.md](rules/rule-mcp-security.md)
- [rule-mobile-app-security.md](rules/rule-mobile-app-security.md)
- [rule-privacy-data-protection.md](rules/rule-privacy-data-protection.md)
- [rule-c-cpp-memory-safety.md](rules/rule-c-cpp-memory-safety.md)
- [rule-sessions-cookies.md](rules/rule-sessions-cookies.md)
- [rule-supply-chain-dependencies.md](rules/rule-supply-chain-dependencies.md)
- [rule-xml-serialization-hardening.md](rules/rule-xml-serialization-hardening.md)

See [README.md](README.md) for sources and attribution.
