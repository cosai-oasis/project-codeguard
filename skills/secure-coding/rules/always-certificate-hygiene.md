---
description: Spot, parse, and validate X.509 certificates found in code
alwaysApply: true
rule_id: always-certificate-hygiene
---

# Certificate Hygiene

## Rule

Whenever the agent encounters certificate data — embedded in source, loaded from a file, or produced by a call — it must (1) recognize that the data is a certificate, (2) verify the four core security properties listed below, and (3) surface any finding with clear severity and a concrete remediation.

"Verify" means: if the certificate content is available in context, parse it and report. If it is only referenced by file path or loaded at runtime, produce a short runbook the human reviewer can run to verify, plus a warning if anything in the code path skips validation.

## How to recognize certificate data

### PEM strings in source

Look for multi-line string literals (or constants / templates) containing:

```
-----BEGIN CERTIFICATE-----
<base64 blob>
-----END CERTIFICATE-----
```

Related blocks to also watch: `-----BEGIN RSA PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`, `-----BEGIN PRIVATE KEY-----` — these are private keys and fall under `always-no-hardcoded-secrets.md`.

### File loads

File extensions commonly used: `.pem`, `.crt`, `.cer`, `.der`, `.p7b`, `.p12` / `.pfx`. Treat any read of these paths as a certificate event.

### Library calls

Any of the following are signals that certificate handling is happening:

- OpenSSL: `PEM_read_X509`, `d2i_X509`, `SSL_CTX_use_certificate_file`
- Python: `cryptography.x509.load_pem_x509_certificate`, `ssl.SSLContext.load_cert_chain`
- Java: `CertificateFactory.getInstance("X.509")`, `KeyStore.load`
- Go: `tls.LoadX509KeyPair`, `x509.ParseCertificate`
- Node.js: `crypto.createCredentials`, `tls.createSecureContext` with `cert:` / `key:`
- .NET: `X509Certificate2`, `X509Store`

## The four checks

If the certificate contents are available, produce the findings below. If they are not, recommend the inspection command:

```
openssl x509 -in <path_or_stream> -noout -text
```

(or the platform equivalent) and list the four checks for the reviewer to run.

### Check 1 — Validity window

Pull `notBefore` and `notAfter`. Compare to current time.

- **Critical — expired**: `notAfter` is in the past.
  > *"The certificate expired on YYYY-MM-DD. TLS clients will reject the connection. Replace the certificate before deployment."*
- **Warning — not yet valid**: `notBefore` is in the future.
  > *"The certificate's validity begins on YYYY-MM-DD. It will not be accepted until then."*
- **Informational — expiring soon**: less than 30 days remaining.
  > *"The certificate expires on YYYY-MM-DD (N days). Plan a rotation."*

### Check 2 — Public key strength

Inspect algorithm and modulus size.

- **High**: RSA modulus < 2048 bits.
- **High**: EC key on a curve smaller than P-256 (`secp192r1`, `P-192`, `P-224`).
- **Acceptable**: RSA ≥ 2048 (≥ 3072 preferred for new issuance), or EC on P-256 / P-384 / Ed25519.

Report:
> *"The certificate's public key is {Algorithm}-{Size}. New certificates should use RSA ≥ 2048 or ECDSA on P-256 or higher. Re-issue before deployment."*

### Check 3 — Signature algorithm

Look at the `signatureAlgorithm` field.

- **High** if the algorithm is MD5- or SHA-1-based (`md5WithRSAEncryption`, `sha1WithRSAEncryption`).
- Acceptable: SHA-256 / SHA-384 / SHA-512 families.

Report:
> *"The certificate is signed with {Algorithm}, which is not collision-resistant. Re-issue with a SHA-2 family signature (e.g., sha256WithRSAEncryption)."*

### Check 4 — Self-signed / issuer

Compare `Issuer` and `Subject`.

- **Informational**: identical fields — the certificate is self-signed.

Self-signed is not inherently insecure, but it requires explicit trust configuration on every client. Report:
> *"This certificate is self-signed (Issuer = Subject). Acceptable only when the trust path is explicitly managed — internal services, development environments, private CAs. Do not use on Internet-facing endpoints."*

## Additional defense — also flag

- **Private key next to the certificate in the repo.** Even if the certificate is fine, a committed private key is a critical finding. Route through `always-no-hardcoded-secrets.md`.
- **`verify=False`, `InsecureSkipVerify=true`, `rejectUnauthorized: false`, `NSURLSessionDelegate` that accepts any cert.** Any code that disables verification must be treated as a critical finding, because all of the above checks become irrelevant at runtime.
- **Pinning code that accepts any backup.** If pinning is implemented, at least one backup pin is needed; zero backups means a rotation bricks clients.

## Worked examples

### Example A — hardcoded certificate

```python
# Certificate for legacy_service
LEGACY_CERT = """
-----BEGIN CERTIFICATE-----
MIIC...
-----END CERTIFICATE-----
"""
```

Report:

> **Security review required.** A certificate is hardcoded in `LEGACY_CERT`.
>
> Run `openssl x509 -in - -noout -text` on the decoded content and verify:
> - Validity: `notAfter` not in the past and `notBefore` not in the future
> - Key strength: RSA ≥ 2048 or ECDSA ≥ P-256
> - Signature: SHA-2 family (not MD5 / SHA-1)
> - Issuer vs subject: document if self-signed; accept only for internal/dev use
>
> **Separately**: hardcoded certificates cannot be rotated without a code change. Prefer loading from an external file, config-mounted secret, or certificate store.

### Example B — loaded from disk, verification disabled

```go
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
// ...
client := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}}
```

Report:

> **Critical.** `InsecureSkipVerify: true` disables certificate verification entirely. Every connection is vulnerable to MITM. Remove this flag; if you are hitting a self-signed internal service, add that CA to the RootCAs pool instead.
>
> Secondary: certificate loaded from `server.crt`. Run the four checks above on that file before deployment.

## When applying this rule

In the response, either:
- state that no certificate data was present, **or**
- enumerate each certificate / file and the outcome of each of the four checks (or a request for the reviewer to run them).
