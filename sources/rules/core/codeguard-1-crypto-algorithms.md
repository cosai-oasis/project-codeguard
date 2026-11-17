---
description: Cryptographic Security Guidelines & Post-Quantum Readiness
languages: []
alwaysApply: true
---

## Cryptographic Algorithms & Post-Quantum Readiness

Use only modern, secure algorithms through high-level APIs, migrate away from broken and deprecated primitives, and prepare for quantum threats with AES-256 and hybrid post-quantum key exchange.

### Banned Algorithms
- Never generate or use code with these algorithms; they are cryptographically broken and vulnerable to collision or man-in-the-middle attacks.
- Hash: `MD2`, `MD4`, `MD5`, `SHA-0`.
- Symmetric: `RC2`, `RC4`, `Blowfish`, `DES`, `3DES`.
- Key exchange: Static RSA, Anonymous Diffie-Hellman.
- Classical: `Vigenère`.

### Deprecated Algorithms
- These have known weaknesses or are considered obsolete. Avoid them in new designs and prioritize migration.
- Hash: `SHA-1`.
- Symmetric: `AES-CBC`, `AES-ECB`.
- Signature: RSA with `PKCS#1 v1.5` padding in new designs (prefer RSA-PSS, ECDSA, or EdDSA); existing uses such as X.509 `sha256WithRSAEncryption` and JWT `RS256` remain acceptable.
- Key exchange: DHE with primes under 2048 bits or custom (non-RFC 7919) groups, and FFDHE in (D)TLS 1.2.

### Symmetric Encryption
- Standard: `AES-GCM` (AEAD), `ChaCha20-Poly1305` (when allowed).
- Prefer AES-256 keys (or stronger) for post-quantum readiness; they resist quantum attacks (Grover's algorithm).
- Avoid custom crypto and unauthenticated modes.
- Never reuse a nonce/IV with the same key; for AES-GCM and ChaCha20-Poly1305, use a unique 96-bit nonce per message (random, or a counter that never repeats), store it with the ciphertext, and rotate the key well before 2^32 random-nonce encryptions (NIST SP 800-38D).
- Compare MACs, tokens, and other secret values with a constant-time function (e.g., `hmac.compare_digest`, `crypto.timingSafeEqual`), never `==`.

### Key Exchange (KEM)
- Standard: ECDHE (`X25519` or `secp256r1`).
- Use hybrid key exchange (classical + PQC) when supported:
  - Preferred: `X25519MLKEM768` (X25519 + ML-KEM-768).
  - Alternative: `SecP256r1MLKEM768` (P-256 + ML-KEM-768).
  - High assurance: `SecP384r1MLKEM1024` (P-384 + ML-KEM-1024).
- Pure PQC: ML-KEM-768 (baseline) or ML-KEM-1024. Avoid ML-KEM-512 unless explicitly risk-accepted.
- Use the standard group names and code points from the IANA TLS Supported Groups registry, as documented by your TLS library.
- Remove legacy/draft "Hybrid-Kyber" groups (e.g., `X25519Kyber`) and draft or hardcoded OIDs.

### Signatures & Certificates
- Standard: ECDSA (`P-256`).
- Continue using ECDSA (`P-256`) for mTLS and code signing until ML-DSA is supported by your PKI, protocols, and verifiers.
- Protect long-lived signing keys in an HSM, TPM, or KMS where available, whatever the algorithm.

### Protocol Versions
- (D)TLS: prefer (D)TLS 1.3; allow (D)TLS 1.2 only where required, with ECDHE and AEAD suites. Prohibit TLS 1.0/1.1 and SSL.
- IPsec: enforce IKEv2 only.
  - Use ESP with AEAD (AES-256-GCM).
  - Require PFS via ECDHE.
  - Implement RFC 9242 and RFC 9370 for hybrid PQC (ML-KEM + ECDHE).
  - Ensure re-keys (`CREATE_CHILD_SA`) maintain hybrid algorithms.
- SSH: enable only vendor-supported PQC/hybrid KEX (e.g., `sntrup761x25519`).

### Key Management and Crypto Agility
- Expose algorithm choices in config/policy to allow agility without code changes.
- Use KMS/HSM for key storage.
- Generate keys with a CSPRNG.
- Separate encryption keys from signature keys.
- Rotate keys per policy.
- Never hardcode keys, secrets, or experimental OIDs.
- Capture negotiated groups, handshake sizes, and failure causes to monitor PQC adoption.

### Deprecated OpenSSL APIs
- Never use these deprecated functions; use the replacement EVP high-level APIs.

#### Symmetric Encryption (AES)
- Deprecated: `AES_encrypt()`, `AES_decrypt()`.
- Replacement:

```c
EVP_EncryptInit_ex()   // Use EVP_aes_256_gcm() for PQC readiness
EVP_EncryptUpdate()
EVP_EncryptFinal_ex()
```

#### RSA/PKEY Operations
- Deprecated: `RSA_new()`, `RSA_free()`, `RSA_get0_n()`.
- Replacement:

```c
EVP_PKEY_new()
EVP_PKEY_up_ref()
EVP_PKEY_free()
```

#### Hash & MAC Functions
- Deprecated: `SHA1_Init()`; the `HMAC_CTX`-based functions (`HMAC_CTX_new()`, `HMAC_Init_ex()`, `HMAC_Update()`, `HMAC_Final()`). One-shot `HMAC()` is not deprecated.
- Replacement:

```c
EVP_DigestInit_ex()    // Use SHA-256 or stronger
EVP_Q_mac()            // For one-shot MAC
```

### Additional Requirements
- Avoid HMAC with SHA-1 in new designs; use HMAC with SHA-256 or stronger:

```c
// Secure replacement for HMAC-SHA1
if (EVP_Q_mac(NULL, "HMAC", NULL, "SHA256", NULL, key, key_len, data, data_len, out, out_size, &out_len) == NULL) handle_error();
```

### Secure Implementation Pattern
AES-256-GCM encryption with EVP, error handling on every call, and the authentication tag retrieved:

```c
// Secure AES-256-GCM encryption (PQC-ready symmetric strength)
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) handle_error();

// Use AES-256-GCM
if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
    handle_error();

int len, ciphertext_len;
if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    handle_error();
ciphertext_len = len;

if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    handle_error();
ciphertext_len += len;

// Retrieve the tag; store it with the unique IV and ciphertext
if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    handle_error();

EVP_CIPHER_CTX_free(ctx);
```

- On decryption, set the received tag with `EVP_CTRL_GCM_SET_TAG` before `EVP_DecryptFinal_ex()` and discard the plaintext unless it returns 1.

### Implementation Checklist
- No banned algorithms; deprecated algorithms kept out of new designs and scheduled for migration.
- Symmetric encryption uses AES-GCM (AES-256 preferred) or ChaCha20-Poly1305; no custom or unauthenticated modes.
- Key exchange uses ECDHE, with hybrid ML-KEM groups where supported; no draft Kyber groups or hardcoded OIDs.
- (D)TLS 1.3 preferred (1.2 only where required), IKEv2 only, and vendor-supported PQC/hybrid SSH KEX.
- Keys generated with a CSPRNG, stored in KMS/HSM, separated by purpose, rotated, and never hardcoded.
- C code uses EVP high-level APIs with every return value checked; HMAC uses SHA-256 or stronger.
- Algorithm choices configurable; negotiated groups and handshake failures monitored.
