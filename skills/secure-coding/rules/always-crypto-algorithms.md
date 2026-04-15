---
description: Allowed, deprecated, and banned cryptographic algorithms — plus post-quantum posture
alwaysApply: true
rule_id: always-crypto-algorithms
---

# Cryptographic Algorithms — What to Use, What to Retire

## Rule

Choose cryptographic primitives from the "allowed" column below. Never generate new code on primitives from the "banned" column. Do not introduce primitives from the "deprecated" column into new designs; migrate them when you touch them.

This applies to every language and every layer — application crypto, transport, key exchange, signatures, password hashing (covered more fully in `rule-authentication-mfa.md`).

## Banned — broken, do not use

These are cryptographically broken or structurally unsafe. Refuse to generate code that uses them.

| Category | Banned primitives | Why |
|----------|-------------------|-----|
| Hash | MD2, MD4, MD5, SHA-0 | Practical collisions or preimage attacks exist |
| Symmetric | DES, 3DES, RC2, RC4, Blowfish | Key size too small, known biases, or better replacements exist |
| Key exchange | Static RSA, anonymous Diffie-Hellman | No forward secrecy, or no authentication at all |
| Classical | Vigenère, ROT-N, XOR-with-fixed-key, "home-made" schemes | Not cryptography |

## Deprecated — migrate, don't extend

Weak enough that they should not appear in anything being actively developed, but still exist in production and may need to be tolerated briefly during migration.

- **SHA-1** (collision resistance broken) — replace with SHA-256 or better
- **AES-ECB** — leaks structure of plaintext; use AEAD instead
- **AES-CBC** without encrypt-then-MAC — malleable; use AEAD
- **RSA with PKCS#1 v1.5 padding** for signatures or encryption — use PSS / OAEP, or migrate to EC
- **Ephemeral DH with small or shared primes** — use ECDHE or FFDHE with RFC 7919 groups

## Allowed — modern, post-quantum-aware defaults

### Symmetric encryption
- **AES-GCM** (256-bit key preferred — Grover's algorithm halves the effective key size against a quantum attacker)
- **ChaCha20-Poly1305** when AES-NI is unavailable or on mobile

Both are AEAD. Unauthenticated modes (CTR, CBC, OFB) are not an option for new code.

### Hashing
- **SHA-256**, **SHA-384**, **SHA-512**, **SHA-3** family for generic hashing and integrity
- **BLAKE2** / **BLAKE3** where standardized support permits
- Password hashing uses **Argon2id / scrypt / bcrypt / PBKDF2** — see `rule-authentication-mfa.md` for parameters

### Asymmetric — signatures
- **Ed25519** or **ECDSA on P-256** as the default for new signatures
- **RSA-2048+** with **PSS** padding when ECC cannot be used
- **ML-DSA** (FIPS 204, formerly Dilithium) — only with hardware-backed key storage (HSM / TPM / Secure Enclave). Do **not** enable ML-DSA with software-only keys.

### Asymmetric — key exchange / KEM
- **X25519** or **ECDH on P-256 / P-384** for classical
- **Hybrid PQC** when both peers support it — preferred combinations:
  - `X25519MLKEM768` (X25519 + ML-KEM-768)
  - `SecP256r1MLKEM768` (P-256 + ML-KEM-768)
  - `SecP384r1MLKEM1024` for higher-assurance contexts
- **ML-KEM-768** standalone is acceptable; avoid ML-KEM-512 unless the risk is explicitly accepted
- Use vendor-documented group identifiers from RFC 9242 / RFC 9370. Remove any legacy draft-Kyber groups.

### Random numbers
Use the platform CSPRNG. Never use a general-purpose PRNG for security:

| Language | Use | Do not use |
|----------|-----|------------|
| Python | `secrets`, `os.urandom` | `random` |
| Java | `SecureRandom` | `Random`, `Math.random()` |
| Node.js | `crypto.randomBytes`, `crypto.randomUUID` | `Math.random()` |
| Go | `crypto/rand` | `math/rand` |
| C | `getrandom(2)`, OpenSSL `RAND_bytes` | `rand()`, `/dev/random` direct reads (blocks) |
| Browser | `crypto.getRandomValues`, `crypto.randomUUID` | `Math.random()` |

## Transport protocols

- **TLS**: enforce 1.3; allow 1.2 only with a documented legacy reason; disable 1.0, 1.1, and all SSL versions.
- **IKEv2 / IPsec**: ESP with AEAD (AES-256-GCM), PFS via ECDHE, hybrid PQC per RFC 9242 / 9370 when supported. Ensure re-keys preserve the hybrid group.
- **SSH**: only vendor-supported hybrid/PQC KEX (for example `sntrup761x25519-sha512`).

## Key management — non-negotiable rules

- Generate keys with a CSPRNG, inside an HSM or KMS whenever feasible.
- Never derive a long-lived key from a user password as the sole source of entropy. Use a password-derivation function with a random salt; keep the derived key scoped narrowly.
- Separate keys by purpose — one key per use case (encryption, signing, wrapping). A compromised signing key should not also decrypt data at rest.
- Rotate on schedule and on compromise. Wrap data-encryption keys (DEKs) with a key-encryption key (KEK) and store the two separately.
- Never hardcode keys. Never place them in plain environment variables in production — use KMS / Vault / HSM.
- Log the fact of key access, not the key material. Audit trails for key use are required.

## Deprecated C / OpenSSL primitives

When touching C code that uses OpenSSL, migrate to the EVP high-level API:

- `AES_encrypt / AES_decrypt` → `EVP_EncryptInit_ex` + `EVP_EncryptUpdate` + `EVP_EncryptFinal_ex` with `EVP_aes_256_gcm()`
- `RSA_new / RSA_free / RSA_get0_*` → `EVP_PKEY_new / EVP_PKEY_free / EVP_PKEY_up_ref`
- `SHA1_Init` etc. → `EVP_DigestInit_ex` with `EVP_sha256()` or stronger
- Legacy `HMAC(..., SHA1, ...)` → `EVP_Q_MAC` (one-shot) or `EVP_MAC` (streaming) with SHA-256 or stronger

Example of the secure AES-256-GCM path in C:

```c
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) { /* error */ }

if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) { /* error */ }

int written = 0, total = 0;
if (EVP_EncryptUpdate(ctx, ciphertext, &written, plaintext, plaintext_len) != 1) { /* error */ }
total = written;

if (EVP_EncryptFinal_ex(ctx, ciphertext + written, &written) != 1) { /* error */ }
total += written;

/* Retrieve the authentication tag */
unsigned char tag[16];
EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag);

EVP_CIPHER_CTX_free(ctx);
```

## Cryptographic agility

- Make the algorithm choice configurable rather than hardcoded. When a primitive needs to be retired, you should be able to flip a flag instead of rewriting call sites.
- Instrument negotiated groups, handshake sizes, and failure causes — you will need this telemetry the day a migration becomes urgent.
- Do not invent your own protocol, mode, or padding. If you are combining primitives, you are writing a protocol. Use a vetted library (libsodium, Tink, BoringSSL, the language's standard library) instead.

## When applying this rule

Name the chosen primitive in the response and, when the choice was non-trivial (post-quantum posture, FIPS constraints, interop with legacy), briefly explain the trade-off.
