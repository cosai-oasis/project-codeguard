---
description: No secrets, keys, or credentials in source code — ever
alwaysApply: true
rule_id: always-no-hardcoded-secrets
---

# No Hardcoded Secrets

## Rule

A credential that lives inside source code is compromised the moment that source is committed, copied, shared with an AI agent, printed in a stack trace, or mirrored to a backup. Treat the repository as if it will eventually become public — because in practice many repositories do, by accident or by policy change.

This rule is unconditional: **do not place the following in source files, sample configs, test fixtures, docstrings, or comments.**

## What counts as a secret

Categories that are always off-limits in source:

- Passwords of any kind — service accounts, DB users, admin accounts, test accounts that point at real systems
- API keys, bearer tokens, personal access tokens, OAuth client secrets, webhook signing secrets
- Private keys (RSA/EC/Ed25519), TLS server keys, SSH private keys, code-signing keys
- Connection strings that embed credentials (`postgres://user:pw@host/db`, `mongodb://...`, `amqps://...`)
- Session cookie values, JWTs, refresh tokens — even expired ones
- Cloud access keys and session tokens (AWS, GCP, Azure, Cloudflare, …)
- Shared HMAC or symmetric encryption keys

A test-only credential pointing at a *shared* test environment is still a real credential. Local-only credentials for an isolated dev container or a disposable ephemeral DB are acceptable only when the string has no value outside that sandbox.

## Shapes to recognize

When reading or generating code, treat these patterns as red flags and pause:

| Pattern | Example prefix |
|---------|----------------|
| AWS access key | `AKIA…`, `ASIA…`, `AROA…`, `AIDA…`, `AGPA…` |
| GitHub token | `ghp_…`, `gho_…`, `ghs_…`, `ghu_…`, `ghr_…` |
| Stripe key | `sk_live_…`, `sk_test_…`, `pk_live_…`, `pk_test_…` |
| Google API key | `AIza…` (35 chars after prefix) |
| Slack token | `xoxb-…`, `xoxp-…`, `xoxa-…` |
| JWT | three base64url segments separated by `.` (often starts `eyJ…`) |
| PEM-encoded key | block starting with `-----BEGIN ... PRIVATE KEY-----` |
| Embedded URL credentials | `proto://username:password@host` |

Also be suspicious of:

- Any variable named `PASSWORD`, `SECRET`, `API_KEY`, `TOKEN`, `AUTH`, `PRIV_KEY`, `CREDS` whose value is a literal string
- Long opaque base64 or hex strings near authentication code
- Default fallbacks like `os.getenv("DB_PASS", "hunter2")` — the fallback is still source-code-resident

## What to do instead

1. Read the value from environment at runtime, with no in-code default. If the variable is missing, fail loudly during startup.
2. Pull from a secret manager (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler, 1Password Connect, …). Rotate through the manager, not through a deploy.
3. For developer workstations, use a local `.env` that is `.gitignore`-d, plus a committed `.env.example` with placeholder values.
4. In CI, inject via repo/organization secrets; never echo them to logs; mask in output.
5. When a secret must be present at build time (e.g., container registry auth), use BuildKit secrets or the platform's equivalent — not `ARG` / `ENV`, which persist in layers.

## If a secret slipped in

Rotate first, then remove. Deleting the file in a later commit does **not** remove the secret from git history. The correct sequence is:

1. Revoke the credential at the issuer (AWS console, GitHub settings, etc.).
2. Generate a replacement and wire it in via the mechanisms above.
3. Rewrite history (`git filter-repo` or BFG) if the repo is shared and the value must truly disappear, then force-push after coordinating with collaborators.
4. Audit access logs for the revoked credential for the window it was exposed.

Rotation is not optional — assume any exposed credential has been scraped within minutes.

## When applying this rule

The agent must call out, in its response, every place a secret could have landed in code and confirm it was externalized. This is not a ritual — a single missed case defeats the rule entirely.
