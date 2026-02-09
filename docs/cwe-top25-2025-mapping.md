# CWE Top 25 (2025) Mapping to Project CodeGuard Rules

This document maps the [2025 MITRE CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html) to existing Project CodeGuard rules. It identifies which CWEs are covered, which rules address them, and where gaps exist that require new rules.

The CWE Top 25 is published annually by MITRE based on real-world CVE and exploitation data. This mapping helps assess CodeGuard's coverage against the most prevalent vulnerability classes and prioritize new rule development.

## Coverage Summary

- **Fully covered**: 16 of 25 CWEs have direct, explicit rule coverage
- **Partially covered**: 8 of 25 CWEs are addressed by related rules but lack dedicated or complete guidance
- **Gap identified**: 1 CWE (CWE-770) has no existing rule coverage

## Mapping Table

Each row maps a CWE from the 2025 Top 25 to the CodeGuard rules that address it. The "Coverage" column uses:

- **Full** - The CWE is directly and explicitly addressed by one or more rules
- **Partial** - The CWE is addressed indirectly or only for specific languages
- **Gap** - No existing rule covers this CWE

### Core Rules

| Rank | CWE ID | CWE Name | CodeGuard Core Rule(s) | Coverage | Notes |
|------|--------|----------|----------------------|----------|-------|
| 1 | CWE-79 | Cross-site Scripting (XSS) | `codeguard-0-client-side-web-security` | Full | Covers context-aware XSS prevention (HTML, attribute, JS, URL, CSS contexts), DOM-based XSS, dangerous sinks, and CSP deployment |
| 2 | CWE-89 | SQL Injection | `codeguard-0-input-validation-injection` | Full | Covers prepared statements, parameterized queries, bind variables, stored procedure safety, and ORM-level protections |
| 3 | CWE-352 | Cross-Site Request Forgery (CSRF) | `codeguard-0-client-side-web-security` | Full | Covers synchronizer tokens, SameSite cookies, origin/referer validation, and framework-specific CSRF protections |
| 4 | CWE-862 | Missing Authorization | `codeguard-0-authorization-access-control` | Full | Covers deny-by-default, per-request authorization checks, RBAC/ABAC/ReBAC, and centralized authorization middleware |
| 5 | CWE-787 | Out-of-bounds Write | `codeguard-0-safe-c-functions` | Partial | Addresses buffer overflows through safe function replacements (`snprintf`, `strncpy`, bounds checking). C/C++ only; no coverage for memory-unsafe patterns in other languages |
| 6 | CWE-22 | Path Traversal | `codeguard-0-file-handling-and-uploads` | Full | Covers path canonicalization, directory traversal prevention, sandboxed storage, and server-generated filenames |
| 7 | CWE-416 | Use After Free | `codeguard-0-safe-c-functions` | Partial | Addresses memory safety practices for C/C++. Does not cover use-after-free patterns in languages with manual memory management beyond C/C++ |
| 8 | CWE-125 | Out-of-bounds Read | `codeguard-0-safe-c-functions` | Partial | Covered through bounds-checked function alternatives and buffer size validation. C/C++ only |
| 9 | CWE-78 | OS Command Injection | `codeguard-0-input-validation-injection` | Full | Covers OS command injection defense with parameterized APIs, input sanitization, and avoidance of shell invocation |
| 10 | CWE-94 | Code Injection | `codeguard-0-input-validation-injection` | Partial | Addresses injection broadly but does not provide standalone guidance for `eval()`/`exec()`, template injection, or dynamic code generation patterns |
| 11 | CWE-120 | Classic Buffer Overflow | `codeguard-0-safe-c-functions` | Partial | Covers safe alternatives to `strcpy`, `sprintf`, `gets`, and other unbounded copy functions. New to Top 25 in 2025 |
| 12 | CWE-434 | Unrestricted Upload of File with Dangerous Type | `codeguard-0-file-handling-and-uploads` | Full | Covers extension validation, content-type verification, magic number checks, storage isolation, and malware scanning |
| 13 | CWE-476 | NULL Pointer Dereference | `codeguard-0-safe-c-functions` | Partial | Implicit in C/C++ safe coding practices. No explicit guidance for null safety patterns in Java, Go, Kotlin, or Rust |
| 14 | CWE-121 | Stack-based Buffer Overflow | `codeguard-0-safe-c-functions` | Partial | Covered through safe function alternatives and stack protection guidance. New to Top 25 in 2025 |
| 15 | CWE-502 | Deserialization of Untrusted Data | `codeguard-0-xml-and-serialization` | Full | Covers unsafe native deserialization, type-safe alternatives, allowlisting, and platform-specific hardening (Java, Python, PHP, Ruby) |
| 16 | CWE-122 | Heap-based Buffer Overflow | `codeguard-0-safe-c-functions` | Partial | Addressed through dynamic allocation safety and bounds checking. New to Top 25 in 2025 |
| 17 | CWE-863 | Incorrect Authorization | `codeguard-0-authorization-access-control` | Full | Covers IDOR prevention, mass assignment protection, resource-level permission validation, and least-privilege enforcement |
| 18 | CWE-20 | Improper Input Validation | `codeguard-0-input-validation-injection` | Full | Covers syntactic and semantic validation, allowlists, canonicalization, Unicode normalization, and ReDoS prevention |
| 19 | CWE-284 | Improper Access Control | `codeguard-0-authorization-access-control` | Full | Covered through centralized authorization, middleware enforcement, and per-request access checks. New to Top 25 in 2025 |
| 20 | CWE-200 | Exposure of Sensitive Information | `codeguard-0-privacy-data-protection`, `codeguard-1-hardcoded-credentials` | Full | Covers data minimization, encryption at rest/transit, credential protection, and error message sanitization |
| 21 | CWE-306 | Missing Authentication for Critical Function | `codeguard-0-authentication-mfa` | Full | Covers authentication requirements, MFA enforcement, OAuth/OIDC flows, and session binding |
| 22 | CWE-918 | Server-Side Request Forgery (SSRF) | `codeguard-0-api-web-services` | Full | Covers SSRF controls including URL allowlists, protocol restrictions, and internal network access prevention |
| 23 | CWE-77 | Command Injection | `codeguard-0-input-validation-injection` | Full | Addressed alongside OS command injection (CWE-78) with parameterized command APIs and shell avoidance |
| 24 | CWE-639 | Authorization Bypass via User-Controlled Key | `codeguard-0-authorization-access-control` | Full | Directly addressed through IDOR prevention guidance: user-scoped queries, server-side lookups, non-enumerable identifiers. New to Top 25 in 2025 |
| 25 | CWE-770 | Allocation of Resources Without Limits or Throttling | None | **Gap** | No existing rule covers rate limiting, resource quotas, memory bounds, connection pool limits, or DoS prevention through resource management. New to Top 25 in 2025 |

### OWASP Supplementary Rules

Several OWASP rules provide additional depth for CWEs already covered by core rules:

| CWE ID | OWASP Rule(s) | Additional Coverage |
|--------|--------------|-------------------|
| CWE-79 | `codeguard-0-cross-site-scripting-prevention`, `codeguard-0-dom-based-xss-prevention`, `codeguard-0-xss-filter-evasion`, `codeguard-0-content-security-policy` | Framework-specific XSS guidance, CSP deployment details, filter evasion patterns |
| CWE-89 | `codeguard-0-sql-injection-prevention`, `codeguard-0-query-parameterization` | Database-specific parameterization, ORM safety patterns |
| CWE-352 | `codeguard-0-cross-site-request-forgery-prevention` | Framework-specific CSRF token implementation |
| CWE-862/863 | `codeguard-0-authorization`, `codeguard-0-authorization-testing-automation` | Authorization testing automation, policy verification |
| CWE-22 | `codeguard-0-input-validation` | Broader input validation including path components |
| CWE-78/77 | `codeguard-0-os-command-injection-defense`, `codeguard-0-injection-prevention` | Dedicated command injection cheat sheet content |
| CWE-434 | `codeguard-0-file-upload` | Extended file upload validation patterns |
| CWE-502 | `codeguard-0-deserialization` | Language-specific deserialization hardening |
| CWE-120/121/122 | `codeguard-0-cw-memory-string-usage-guidelines`, `codeguard-0-c-based-toolchain-hardening` | Compiler flags, ASLR, stack canaries, toolchain hardening |
| CWE-918 | `codeguard-0-server-side-request-forgery-prevention` | Dedicated SSRF prevention patterns |
| CWE-639 | `codeguard-0-insecure-direct-object-reference-prevention` | IDOR-specific testing and prevention patterns |
| CWE-200 | `codeguard-0-error-handling` | Secure error handling to prevent information disclosure |

## Gap Analysis

### CWE-770: Allocation of Resources Without Limits or Throttling (Gap)

This CWE is new to the 2025 Top 25 and has no coverage in any existing CodeGuard rule. It covers:

- Rate limiting for API endpoints and authentication attempts
- Memory allocation bounds and maximum payload sizes
- Connection pool limits and timeout enforcement
- Thread/process pool sizing and queue depth limits
- File descriptor and disk space quotas
- Recursive computation depth limits
- Denial-of-service prevention through resource management

**Recommendation**: Create a new core rule `codeguard-0-resource-limits-dos-prevention.md` to address this gap.

### Partial Coverage Areas

The following CWEs have partial coverage that could be strengthened:

**CWE-94 (Code Injection)**: The existing injection rule treats code injection as part of a broader injection category. Standalone guidance for `eval()`/`exec()` avoidance, template injection (Jinja2, Twig, ERB, Handlebars), and dynamic code generation would improve coverage.

**CWE-476 (NULL Pointer Dereference)**: Current coverage is limited to C/C++ through safe function alternatives. Explicit guidance for null safety patterns in Java (Optional), Kotlin (null safety), Go (nil checks), Rust (Option/Result), and TypeScript (strict null checks) would expand coverage across the language ecosystem.

**Memory Safety CWEs (CWE-120, 121, 122, 125, 416, 787)**: All six memory safety CWEs in the Top 25 are handled by `codeguard-0-safe-c-functions.md`, which is specific to C/C++. For languages with manual or semi-manual memory management, additional guidance may be warranted. The OWASP `codeguard-0-c-based-toolchain-hardening` rule provides compiler-level mitigations but is also C/C++ specific.

## 2025 Top 25 Changes

Six CWEs are new to the 2025 list compared to 2024:

| CWE ID | CWE Name | CodeGuard Status |
|--------|----------|-----------------|
| CWE-120 | Classic Buffer Overflow | Partial (via safe-c-functions) |
| CWE-121 | Stack-based Buffer Overflow | Partial (via safe-c-functions) |
| CWE-122 | Heap-based Buffer Overflow | Partial (via safe-c-functions) |
| CWE-284 | Improper Access Control | Full (via authorization-access-control) |
| CWE-639 | Authorization Bypass via User-Controlled Key | Full (via authorization-access-control) |
| CWE-770 | Allocation of Resources Without Limits | **Gap** |

## References

- [2025 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [CWE Top 25 Methodology](https://cwe.mitre.org/top25/archive/2025/2025_methodology.html)
- [Project CodeGuard Core Rules](https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core)
