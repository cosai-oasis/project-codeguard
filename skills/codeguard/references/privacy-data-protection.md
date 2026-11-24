---
description: Privacy & data protection (minimization, classification, encryption, rights, transparency)
languages:
- javascript
alwaysApply: false
tags:
- privacy
---

rule_id: codeguard-0-privacy-data-protection

## Privacy & Data Protection

Implement strong cryptography, enforce HTTPS with HSTS, limit any certificate pinning to controlled clients, and provide user privacy features to protect data and anonymity.

### Cryptography and Transport
- Use strong, up-to-date cryptographic algorithms for data in transit and at rest.
- Enforce HTTPS exclusively and implement HTTP Strict Transport Security (HSTS).
- Don't pin certificates by default; outages from certificate changes usually outweigh the benefit. Pin only in a native client you ship and control end to end, where you can update pins safely; use backup pins (see [additional-cryptography](additional-cryptography.md)).

### Minimizing Exposure
- Minimize IP address leakage by blocking third-party external content loading where feasible.

### Transparency and Auditing
- Maintain transparency by informing users about privacy limitations and data handling policies.
- Implement privacy-focused audit trails and access logging.

### Authentication and Sessions
- Return "Invalid username or password" to prevent account enumeration.
- Securely hash passwords with established libraries: preferably Argon2id, with unique salts per user (bcrypt for legacy systems only; see [authentication-mfa](authentication-mfa.md)).
- Store sessions server-side with cryptographically random IDs.

### Implementation Checklist
- Strong algorithms protect data in transit and at rest; HTTPS only, with HSTS; any certificate pinning limited to controlled clients.
- Third-party content loading blocked or minimized to limit IP address leakage.
- Users informed of privacy limitations and data handling; privacy-focused audit trails and access logs in place.
- Generic login errors; Argon2id (preferred; bcrypt for legacy only) with per-user salts; server-side sessions with random IDs.
