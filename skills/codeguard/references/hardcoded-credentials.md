---
description: No Hardcoded Credentials
alwaysApply: true
tags:
- secrets
---

rule_id: codeguard-1-hardcoded-credentials

## Hardcoded Credentials

Never store secrets, passwords, API keys, tokens, or any other credentials directly in source code. Treat the codebase as public and untrusted: any credential that appears in source code is compromised and must be revoked and rotated at its provider (removing it from the code or history is not enough), then handled through secure alternatives.

### Values That Must Never Be Hardcoded
- Database passwords, user passwords, admin passwords.
- API keys, secret keys, access tokens, refresh tokens.
- Private keys and signing keys (public certificates are not secrets; see [digital-certificates](digital-certificates.md)).
- Connection strings containing credentials.
- OAuth client secrets, webhook secrets.
- Any other credentials that could be used to access external services.
- Default or fallback secret values in code (e.g., `os.getenv("API_KEY", "dev-key")`). Instead, have the application fail at startup if a required secret is not provided.

### Recognition Patterns
- AWS credentials: `AKIA`, `ASIA`, `ABIA`, `ACCA` (an access key ID is usable only with its secret key, and for `ASIA` the session token). Other IAM prefixes such as `AIDA`, `AROA`, `AGPA` are identifiers, not credentials; don't publish them, but they need no rotation.
- Stripe keys: secret keys start with `sk_` (e.g., `sk_live_`, `sk_test_`) and restricted keys with `rk_`. Publishable keys (`pk_live_`, `pk_test_`) are designed to be public and are not secrets.
- Google API keys: start with `AIza` followed by 35 characters.
- GitHub tokens: start with `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`.
- JWTs: three base64 sections separated by dots, starting with `eyJ`.
- Private key blocks: any text between `-----BEGIN` and `-----END PRIVATE KEY-----`.
- Connection strings: URLs with credentials like `mongodb://user:pass@host`.

### Warning Signs
- Variable names containing `password`, `secret`, `key`, `token`, or `auth`.
- Long random-looking strings whose purpose is unclear.
- Base64-encoded strings near authentication code.
- Any string that grants access to external services.

### Reporting
- Always explain how this rule was applied and why it was applied.

### Implementation Checklist
- No passwords, API keys, secret or private keys, tokens, fallback secret defaults, or credential-bearing connection strings in source code.
- Code checked against the recognition patterns and warning signs above.
- Any credential found in source treated as compromised: revoked and rotated, then moved to a secure alternative.
- Every finding explains how and why the rule was applied.
