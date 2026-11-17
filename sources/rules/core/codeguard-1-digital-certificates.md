---
description: Certificate Best Practices
languages: []
tags:
- secrets
alwaysApply: true
---

## Digital Certificates

Identify X.509 certificates embedded in code or loaded from files, flag them for verification of expiration, key strength, signature algorithm, and issuer, and report every concern with a clear explanation and recommended action.

### Identifying Certificate Data
- PEM-encoded strings: multi-line string literals or constants that begin with `-----BEGIN CERTIFICATE-----` and end with `-----END CERTIFICATE-----`.
- File operations: reads of files with common certificate extensions such as `.pem`, `.crt`, `.cer`, and `.der`.
- Library calls: functions that load or parse certificates, such as OpenSSL's `PEM_read_X509`, Python's `cryptography.x509.load_pem_x509_certificate`, or Java's `CertificateFactory`.

### Verification
- Flag every identified certificate for verification; each of the checks below must pass before the certificate meets security requirements.
- Recommend inspecting the certificate with the command below, which shows expiration dates, key algorithm and size, signature algorithm, and issuer/subject information.

```bash
openssl x509 -text -noout -in <certificate_file>
```

### Expiration Status
- Expired (`notAfter` date in the past): CRITICAL VULNERABILITY. Report: `This certificate expired on [YYYY-MM-DD]. It is no longer valid and will be rejected by clients, causing connection failures. It must be renewed and replaced immediately.`
- Not yet valid (`notBefore` date in the future): Warning. Report: `This certificate is not yet valid. Its validity period begins on [YYYY-MM-DD].`

### Public Key Strength
- Weak keys: RSA keys with a modulus smaller than 2048 bits; Elliptic Curve (EC) keys using curves with less than a 256-bit prime modulus (e.g., `secp192r1`, `P-192`, `P-224`).
- Severity: High-Priority Warning.
- Report: `The certificate's public key is cryptographically weak ([Algorithm], [Key Size]). Keys of this strength are vulnerable to factorization or discrete logarithm attacks. The certificate should be re-issued using at least an RSA 2048-bit key or an ECDSA key on a P-256 (or higher) curve.`

### Signature Algorithm
- Insecure algorithms: any signature algorithm using MD5 or SHA-1 (e.g., `md5WithRSAEncryption`, `sha1WithRSAEncryption`) on leaf or intermediate certificates. The self-signature on a root trust anchor is not validated, so it need not be flagged.
- Severity: High-Priority Warning.
- Report: `The certificate is signed with the insecure algorithm '[Algorithm]'. This makes it vulnerable to collision attacks, potentially allowing for certificate forgery. It must be re-issued using a signature based on the SHA-2 family (e.g., sha256WithRSAEncryption).`

### Self-Signed Certificates
- Condition: the certificate's `Issuer` and `Subject` fields are identical and its signature verifies with its own public key (identical names alone mean self-issued, e.g., a CA key-rollover certificate, not self-signed).
- Severity: Informational.
- Report: `This is a self-signed certificate. Ensure this is intentional and only used for development, testing, or internal services where trust is explicitly configured. Self-signed certificates should never be used for public-facing production systems as they will not be trusted by browsers or standard clients.`

### Reporting Examples
- Keep feedback direct and easy to understand.
- Always explain how these checks were applied and why they were applied.

Hardcoded certificate:
```python
# Certificate for connecting to legacy_service
LEGACY_CERT = """
-----BEGIN CERTIFICATE-----
MIIC... (certificate data) ...
-----END CERTIFICATE-----
"""
```

> Security Review Required: A certificate is hardcoded in the `LEGACY_CERT` variable. Unverified certificates may contain critical vulnerabilities.
>
> - Concern: Hardcoded certificates cannot be easily rotated and may contain security issues that are not immediately visible in the code.
> - Required Verification: This certificate must be verified for:
>   - Expiration: Certificate must not be expired or not yet valid
>   - Key Strength: RSA keys must be at least 2048-bit; EC keys must use P-256 or higher curve
>   - Signature Algorithm: Must use SHA-2 family (not MD5 or SHA-1)
>   - Self-Signed: If self-signed, must only be used for development, testing, or internal services
> - Action: Verify this certificate meets the above requirements before deployment. Consider loading certificates from external files or a certificate store for easier rotation.

Certificate loaded from file:
```go
// Load the server certificate from disk
cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
```

> Security Review Required: Certificate loaded from `server.crt`. Unverified certificates may contain critical vulnerabilities.
>
> - Required Verification: Ensure this certificate meets security requirements:
>   - Expiration: Certificate must not be expired or not yet valid
>   - Key Strength: RSA keys must be at least 2048-bit; EC keys must use P-256 or higher curve
>   - Signature Algorithm: Must use SHA-2 family (not MD5 or SHA-1)
>   - Self-Signed: If self-signed, must only be used for development, testing, or internal services
> - Action: Verify this certificate meets the above requirements before deployment.

### Implementation Checklist
- Every certificate embedded in code or loaded from disk is identified and flagged for verification.
- Certificate is within its validity period: not expired and not before its `notBefore` date.
- Public key is RSA 2048-bit or larger, or EC on P-256 or a stronger curve.
- Signature uses the SHA-2 family; no MD5 or SHA-1.
- Self-signed certificates are limited to development, testing, or internal services with explicitly configured trust.
- Certificates are loaded from external files or a certificate store rather than hardcoded, so they can be rotated.
- Every report states the severity, the reason, and the required action.
