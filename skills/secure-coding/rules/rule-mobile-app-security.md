---
description: Mobile application security (iOS and Android) — storage, transport, code integrity, biometrics, permissions
languages:
  - java
  - javascript
  - kotlin
  - matlab
  - perl
  - swift
  - xml
alwaysApply: false
rule_id: rule-mobile-app-security
---

# Mobile Application Security

The mobile device is a hostile environment. The user may be adversarial (researchers, competitors, users poking at their own device), the OS may be compromised (rooted / jailbroken), and the network in between is frequently untrusted.

## Architecture principles

- **Server-side for security decisions.** Never trust the client for authentication, authorization, pricing, inventory, or anything the business cares about. The client displays; the server decides.
- **Least privilege** at every layer — permissions requested, capabilities declared, entitlements granted.
- **Defense in depth** — assume each layer will be defeated.
- **Trusted libraries only** — mobile SDKs have a long history of carrying surprises. Vet before integrating; monitor after.
- **Secure update path** — the app must be updatable, and a forced-update mechanism should exist for security-critical patches.

## Authentication and authorization

- Authentication flows use standard protocols — OAuth 2.0 with PKCE, OIDC. See `rule-authentication-mfa.md`.
- No password storage on device. Use revocable access tokens with short lifetimes and refresh rotation.
- Credentials never hardcoded in the app binary (see `always-no-hardcoded-secrets.md`). App Transport-layer identity is the exception — a service API key scoped narrowly and wrapped in platform secure storage is acceptable; a broad credential is not.
- Every request to the backend is authenticated; authorization is checked server-side on every request.
- Session timeout + remote logout. Step-up authentication for sensitive operations.
- **Biometrics** — use the platform API (Face ID / Touch ID on iOS, `BiometricPrompt` on Android). Fall back to device passcode, not to a PIN you invented. Biometric gating protects a server-issued token; it is not authentication to the server.
- Avoid 4-digit PINs; require passphrase complexity where a PIN is allowed.

## Data storage on device

- Store only what the app needs. Everything else stays server-side.
- Sensitive data goes into platform secure storage:
  - iOS: **Keychain** (with appropriate accessibility class — `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` is usually right) and **Secure Enclave** for key operations.
  - Android: **Keystore**, ideally hardware-backed (TEE or StrongBox). For data-at-rest beyond keys, `EncryptedSharedPreferences` / `EncryptedFile`.
- Never store credentials or tokens in:
  - `UserDefaults` / `NSUserDefaults` (iOS) — not encrypted.
  - `SharedPreferences` (Android) — world-readable on rooted devices.
  - Application log files.
  - Unencrypted SQLite databases.
- Private files belong on internal storage only; external storage is world-readable on many Android versions.
- Disable automatic backup for files containing secrets — `android:allowBackup="false"` with an explicit backup rules file, or iOS data-protection class `kCFURLIsExcludedFromBackupKey`.
- Disable snapshot caching when sensitive UI is visible (iOS: blur / blank on `applicationWillResignActive`; Android: `FLAG_SECURE` on sensitive activities).
- Cache policies: do not cache response bodies containing credentials. `Cache-Control: no-store` on the server side plus `URLCache` / OkHttp cache tuning on the client.

## PII minimization

- Collect only the fields needed for the feature.
- Purge on a schedule — chat messages expire, search history rotates.
- Inform the user and honor export / delete requests.

## Network

Assume the network is hostile.

- HTTPS only, with certificate validation enabled (never `allowsInsecureHTTPLoads`, never `trust-all` custom trust managers).
- Strong cipher suites; TLS 1.2 minimum, 1.3 preferred.
- Certificate issued by a CA the OS trusts; for enterprise certificates, configure trust explicitly via Network Security Config (Android) or App Transport Security (iOS).
- Consider **certificate pinning** for high-value apps — see `rule-additional-cryptography.md`. Plan the rotation channel before deploying.
- Additional encryption on sensitive payloads even over TLS when the data is very sensitive — a compromised CA should not be able to read everything.
- Do not rely on SMS for security-critical delivery. SMS is trivially intercepted on modern networks.

## Code integrity and anti-tampering

- **Release builds**:
  - Debuggable off. No verbose logging of user data.
  - Code obfuscation (ProGuard / R8 on Android, LLVM bitcode obfuscation plus appropriate SwiftShield-style measures on iOS). Obfuscation is delay, not prevention — but the delay matters.
  - Strip symbols.
- **Runtime integrity** (for apps where the threat model calls for it):
  - Detect debugger attachment.
  - Detect code injection / method hooking (Frida / Cydia Substrate indicators).
  - Detect emulators and rooted / jailbroken devices. Accept that detection is a cat-and-mouse game; degrade gracefully rather than crashing.
  - Verify the app signature at runtime.
- Use the platform's integrity-attestation API:
  - Android: **Play Integrity API**.
  - iOS: **App Attest** and **DeviceCheck**.

These produce signed tokens the server can verify before granting sensitive operations.

## Platform specifics

### Android

- Use `EncryptedSharedPreferences` / `EncryptedFile` (AndroidX Security). Back keys with `AndroidKeyStore`, ideally `StrongBox`.
- `android:exported="false"` on activities, services, providers, and receivers by default. Only export what must be exported, and then protect with permissions or signature checks.
- Intents carrying sensitive data use explicit component names, not implicit intents.
- Disable backup for sensitive files (`android:allowBackup="false"` + `fullBackupContent`).
- Network Security Config explicitly lists the domains and trust anchors the app uses.

### iOS

- Store sensitive items in Keychain with the strictest accessibility class that still works.
- Secure Enclave for asymmetric keys the app uses for device binding.
- Disable Siri intents that expose sensitive information, or set `requiresUserAuthentication = true` on them.
- Widgets and Live Activities that show sensitive data mask it on the lock screen.
- Deep links validated — a malicious URL scheme invocation must not auto-navigate into sensitive flows.
- Avoid storing sensitive data in `Info.plist` or any other plist.

## Input / output at the UI layer

- Validate and sanitize input on both sides — the client for UX, the server for security.
- Mask sensitive fields (password, PIN, OTP) to prevent shoulder-surfing. Disable clipboard on truly sensitive fields.
- Security events visible to the user — "new device login", "password change", "email change" — arrive through an independent channel.

## Testing and monitoring

- Penetration testing that includes cryptographic review and a jailbroken / rooted device.
- Automated security tests in CI — verify cert pinning is on, verify integrity checks are present, verify the app refuses to run on debuggable builds in production.
- Real-time monitoring of backend signals that indicate client compromise (unusual session patterns, integrity attestation failures, CI-signed vs. attacker-signed binaries).
- Incident response plan covers lost devices, credential compromise, and app-store impostors.

## Summary

Much of mobile security is careful platform usage — Keychain/Keystore, App Transport Security, the integrity APIs, hardware-backed keys. Most of the failures in the field come from shortcuts: a token in `UserDefaults`, a custom TLS trust manager that accepts any cert, a root-detection that was disabled for debugging and never re-enabled. Enumerate those shortcuts during review and do not ship them.
