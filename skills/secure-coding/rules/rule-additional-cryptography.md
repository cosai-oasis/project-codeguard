---
description: Applied cryptography beyond algorithm choice — TLS configuration, HSTS, key management, certificate pinning, data at rest
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
  - xml
  - yaml
alwaysApply: false
rule_id: rule-additional-cryptography
---

# Applied Cryptography — TLS, Keys, Data at Rest

This rule covers the *application* of cryptographic primitives. For the selection of the primitives themselves (AES-GCM vs. ChaCha20, Ed25519 vs. ECDSA, Argon2id parameters, etc.), see `always-crypto-algorithms.md`.

## Data at rest

- Encrypt sensitive data. The bar is lower than people remember — "sensitive" includes anything that could identify a user, expose a business relationship, or help a subsequent attack.
- Minimize what is stored. The strongest encryption is not storing the value.
- Prefer **tokenization** for identifiers you do not need to compute over — card numbers, bank accounts, identifiers that will only ever be compared for equality.
- Use **authenticated encryption** (AES-GCM or ChaCha20-Poly1305). Unauthenticated modes let an attacker flip bits in ciphertext without detection.
- **IV / nonce management**: unique per message; never reuse. For AES-GCM, use a 96-bit random nonce, or a counter if you can guarantee no reuse across processes. A single AES-GCM nonce reuse under the same key is catastrophic — it reveals the XOR of two plaintexts *and* lets an attacker forge ciphertexts.
- **Salts** are unique per record and stored alongside the ciphertext. They do not need to be secret, but they must not be reused.

### Backups

- Backups are encrypted with a key that is distinct from the production key. A compromise of the live service should not also decrypt every historical snapshot.
- Restore paths are tested — an unverified restore is not a backup.
- Retention and access are policy-bound; audit the access logs on restore events.

## Key management

- Generate keys inside a **validated module** — HSM, KMS, or a platform secure enclave. If the key is generated in application code, it is generated with whatever entropy that process happens to have.
- Never derive a long-lived key from a password as the sole source of entropy.
- Separate keys by purpose: encryption, signing, wrapping, authentication. A compromise of one should not compromise another.
- **Envelope encryption**: data is encrypted with a data-encryption key (DEK); the DEK is encrypted by a key-encryption key (KEK) living in the KMS. The cipher data + wrapped DEK sit together; the KEK is used only to unwrap.
- **Rotation** on schedule *and* on any compromise signal. The system must support rotation without an outage — plan the migration path before you need it.
- Access to keys is audited. Who unwrapped what, when, from where.

## TLS configuration

### Protocol versions

- Enforce TLS 1.3. Allow TLS 1.2 only when a specific legacy client requires it, and document the exception.
- Disable TLS 1.0, TLS 1.1, and all SSL versions. These are off by default in modern servers; verify the configuration.
- Enable `TLS_FALLBACK_SCSV` to prevent downgrade attacks in mixed-client fleets.

### Cipher suites

- Prefer AEAD suites: TLS 1.3 mandates them; TLS 1.2 configurations should include `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`, `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`, and equivalents.
- Disable NULL, EXPORT, anonymous, RC4, 3DES, and SEED cipher suites.
- Disable TLS compression — CRIME attack.

### Key exchange groups

- Prefer `x25519`, then `secp256r1` (P-256). Add `secp384r1` only if policy requires it.
- If FFDHE is permitted, use the RFC 7919 named groups (`ffdhe2048` minimum).
- See `always-crypto-algorithms.md` for hybrid post-quantum groups.

### Certificates

- Key size: RSA ≥ 2048 (3072 preferred), or EC on P-256 / P-384. See `always-certificate-hygiene.md` for inspection.
- Signature: SHA-256 or stronger.
- Exact `CN` / `SAN` matching the hostnames in use; avoid wildcard certs covering unrelated hosts.
- OCSP stapling enabled to avoid the performance and privacy cost of client-side OCSP.
- Lifecycle — rotate with overlap, monitor expiry, have a rollback.

### Application layer

- HTTPS site-wide. Redirect HTTP to HTTPS.
- No mixed content — a single HTTP subresource on an HTTPS page downgrades the entire origin.
- All cookies carry the `Secure` attribute.

## HSTS

`Strict-Transport-Security` tells browsers to refuse HTTP for the host (and optionally all subhosts) for the policy's lifetime.

Phased rollout:

1. **Test**: `max-age=86400` (1 day), with `includeSubDomains` if the subdomains are genuinely HTTPS-only. Monitor.
2. **Production**: `max-age=31536000` (1 year) minimum. Add `includeSubDomains` once every subdomain serves HTTPS correctly.
3. **Preload**: submit to the HSTS preload list once the policy has been live in production without issue for several months. Understand that preload is effectively permanent — removal takes weeks to propagate.

Do not send HSTS over HTTP; it is ignored and indicates confusion.

## Certificate pinning

Pin with care. It is a foot-gun.

- Do **not** use HPKP (deprecated; browsers removed it).
- Pinning makes sense for **controlled** clients — mobile apps, kiosks, embedded clients — where the vendor owns both ends and can push an update.
- Pin the **SPKI** (Subject Public Key Info), not the whole certificate. Include at least one backup pin — ideally for a key held offline for exactly this purpose.
- Plan the update channel. A pinned app whose pins rotate out of sync with the server is a bricked app.
- Never allow user bypass ("click here to trust this certificate anyway"). The whole point of pinning is that such a prompt must not exist.
- Test rotation and failure paths — often. A pinning bug only surfaces when the certificate rotates.

## Randomness

Use the platform CSPRNG wrapper (see `always-crypto-algorithms.md`). Do not seed CSPRNGs manually in application code — modern platforms do it correctly already.

## Implementation checklist

- AEAD everywhere; vetted libraries only; no hand-rolled crypto.
- Keys generated and stored in KMS/HSM; separated by purpose; rotation mechanism proven in staging.
- TLS configuration: 1.3 + 1.2 (limited), AEAD-only, compression off, OCSP stapling on.
- HSTS deployed per phase plan; mixed content eliminated.
- Certificate pinning only where it fits the client model, always with backup pins and a rotation plan.
- Backups encrypted with a distinct key; restore tested.

## Test plan

- Run an automated TLS scanner (SSL Labs, testssl.sh) — aim for A or A+ in production.
- Code review crypto API usage; unit tests for envelope encryption round-trips and key rotation.
- Pinning simulations exercising rotation and failure handling when pinning is deployed.
- Periodic backup restore drills.
