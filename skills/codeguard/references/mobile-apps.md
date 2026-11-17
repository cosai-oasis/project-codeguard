---
description: 'Mobile app security (iOS/Android): storage, transport, code integrity, biometrics, permissions'
languages:
- java
- javascript
- kotlin
- swift
- xml
alwaysApply: false
---

rule_id: codeguard-0-mobile-apps

## Mobile Application Security

Write iOS, Android, and cross‑platform (React Native, Flutter) code that keeps secrets in hardware‑backed storage, treats every IPC entry point and WebView as untrusted input, and never relies on the client for security decisions.

### Ground Rules
- The app binary is public. Anything shipped in it (strings, resources, JS bundles, `.env` values, `Info.plist`, `BuildConfig`) can be extracted. Never embed API secrets, private keys, or privileged tokens; proxy privileged calls through a backend that holds the credential.
- Every security decision (authorization, entitlement, price, feature unlock) is enforced server‑side. Client checks exist only for UX.
- Root/jailbreak detection, obfuscation, and anti‑hooking are bypassable speed bumps. Never gate security on them; use server‑verified attestation (Play Integrity, App Attest) instead.

### Secrets and Key Storage
- Store tokens in the iOS Keychain, or on Android encrypted under a non‑exportable Keystore key (ciphertext in app‑private storage). Never store plaintext tokens or keys in `SharedPreferences`, `NSUserDefaults`, plist files, SQLite, files, or `AsyncStorage`.
- Prefer generating non‑exportable keys inside the Keystore/Secure Enclave and encrypting data with them over storing raw secrets.
- Android: use AES‑256‑GCM keys from `AndroidKeyStore`; request StrongBox with `setIsStrongBoxBacked(true)` and fall back on `StrongBoxUnavailableException`. `androidx.security:security-crypto` (`EncryptedSharedPreferences`) is deprecated; use Keystore directly or Tink with a Keystore‑wrapped key.
- iOS: use the most restrictive Keychain accessibility that works: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` or `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`. Never `kSecAttrAccessibleAlways*`. Use `ThisDeviceOnly` so items never migrate to another device (backups containing them restore only to the same device).
- iOS Secure Enclave supports only specific key types (P‑256 via `kSecAttrTokenIDSecureEnclave` or CryptoKit `SecureEnclave.P256`, plus post-quantum ML-KEM and ML-DSA types where the OS supports them); use them for signing, key agreement, or key encapsulation.
- Store refresh tokens, never passwords. Clear tokens and Keychain/Keystore entries on logout (Keychain items survive app uninstall on iOS; clear them on first launch after reinstall).

Android Keystore key bound to strong biometrics:
```kotlin
val spec = KeyGenParameterSpec.Builder(
    "token_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setKeySize(256)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .setInvalidatedByBiometricEnrollment(true)
    .build()
KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
    .apply { init(spec) }
    .generateKey()
```

iOS Keychain item bound to the current biometric set:
```swift
let access = SecAccessControlCreateWithFlags(
    nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil)!
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: "com.example.auth",
    kSecAttrAccount as String: "refresh_token",
    kSecValueData as String: tokenData,
    kSecAttrAccessControl as String: access
]
let status = SecItemAdd(query as CFDictionary, nil)
guard status == errSecSuccess else { throw KeychainError(status) }
```

### Biometrics and Local Authentication
- Never treat a biometric success callback as proof of identity on its own; it can be hooked. Bind biometrics to a key operation:
  - Android: pass a `BiometricPrompt.CryptoObject` wrapping a `Cipher`/`Signature` from an auth‑bound Keystore key, and use `result.cryptoObject` in `onAuthenticationSucceeded`.
  - iOS: protect the Keychain item with `SecAccessControl` (`.biometryCurrentSet`); reading it triggers biometrics. Do not rely on `LAContext.evaluatePolicy` alone.
- Use `BIOMETRIC_STRONG` (Class 3) for anything that unlocks credentials; `BIOMETRIC_WEAK` is not bound to keys.
- Invalidate keys when biometric enrollment changes (`setInvalidatedByBiometricEnrollment(true)`, `.biometryCurrentSet`).
- For high‑value actions, have the server issue a challenge that the app signs with a biometric‑bound key.

### Authentication Flows
- Use OAuth 2.0 / OIDC authorization code flow with PKCE (`S256`) via the system browser: AppAuth, Android Custom Tabs, or iOS `ASWebAuthenticationSession` (RFC 8252). Never collect third‑party credentials in a WebView.
- Use claimed HTTPS redirect URIs (App Links / Universal Links) rather than custom schemes, which other apps can register.
- Validate `state` and `nonce` on every redirect. Do not embed a client secret; mobile apps are public clients.
- Keep access tokens short‑lived; send them only in the `Authorization` header, never in URLs.

### Network Communication
- HTTPS only. Do not add cleartext exceptions: no `android:usesCleartextTraffic="true"` or `cleartextTrafficPermitted="true"`, and no `NSAllowsArbitraryLoads` in App Transport Security. Scope any unavoidable exception to a single domain.
- Never disable certificate validation: no trust‑all `X509TrustManager`, no `HostnameVerifier` returning `true`, no `WebViewClient.onReceivedSslError` calling `handler.proceed()`, no `URLSessionDelegate` that accepts a challenge without `SecTrustEvaluateWithError`.
- Do not trust user‑installed CAs in release builds; restrict `<certificates src="user"/>` to `<debug-overrides>`.
- If you pin, pin SPKI SHA‑256 hashes declaratively, include at least one backup pin, and set an expiration so a key rotation can't brick the app.

Android `res/xml/network_security_config.xml`:
```xml
<network-security-config>
  <base-config cleartextTrafficPermitted="false">
    <trust-anchors><certificates src="system"/></trust-anchors>
  </base-config>
  <domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-06-01">
      <pin digest="SHA-256">PRIMARY_SPKI_SHA256_BASE64=</pin>
      <pin digest="SHA-256">BACKUP_SPKI_SHA256_BASE64=</pin>
    </pin-set>
  </domain-config>
</network-security-config>
```

iOS `Info.plist` pinning (iOS 14+):
```xml
<key>NSAppTransportSecurity</key>
<dict>
  <key>NSPinnedDomains</key>
  <dict>
    <key>api.example.com</key>
    <dict>
      <key>NSIncludesSubdomains</key><true/>
      <key>NSPinnedCAIdentities</key>
      <array>
        <dict><key>SPKI-SHA256-BASE64</key><string>PRIMARY_SPKI_SHA256_BASE64=</string></dict>
        <dict><key>SPKI-SHA256-BASE64</key><string>BACKUP_SPKI_SHA256_BASE64=</string></dict>
      </array>
    </dict>
  </dict>
</dict>
```

### Local Data at Rest and Leakage
- Write sensitive files to app‑private storage only: Android `Context.filesDir`/`noBackupFilesDir`, never external/shared storage or `MediaStore`; iOS app container with `FileProtectionType.complete` (`.completeUnlessOpen` for files written in the background).
- Exclude sensitive data from backups: Android `android:allowBackup="false"` or explicit `android:dataExtractionRules` (API 31+) and `android:fullBackupContent` excludes; iOS `ThisDeviceOnly` Keychain classes (restorable only to the same device) and `isExcludedFromBackup` for files.
- Encrypt local databases holding sensitive data (e.g., SQLCipher) with a Keystore/Keychain‑protected key.
- Use parameterized queries in SQLite, Room, and Core Data (`NSPredicate(format:)` with arguments); never build SQL or predicates by string concatenation.
- Logging: never log tokens, PII, or request/response bodies. Strip `Log.d`/`Log.v` from release with R8 `-assumenosideeffects`; on iOS use `Logger`/`os_log` and keep dynamic values `privacy: .private`; avoid `print`/`NSLog` with sensitive data. Disable verbose HTTP logging interceptors in release.
- Screens: set `WindowManager.LayoutParams.FLAG_SECURE` on screens showing secrets; on iOS cover sensitive views in `sceneWillResignActive` so the app‑switcher snapshot doesn't capture them.
- Keyboards: use `inputType="textPassword"`/`textNoSuggestions` and `isSecureTextEntry`, and disable autocorrect on sensitive fields so input isn't cached.
- Clipboard: avoid copying secrets. If required, mark sensitive (Android 13+ `ClipDescription.EXTRA_IS_SENSITIVE`) or set `UIPasteboard` items with `.localOnly` and a short `.expirationDate`.
- Release builds: `android:debuggable` false, R8 minification on; iOS release config without `get-task-allow`.

### Android Components and IPC
- Set `android:exported` explicitly on every component. Export only what must be called by other apps, and protect exported components with a `signature`‑level custom permission when callers are your own apps.
- Treat every incoming `Intent`, extra, and `Uri` as untrusted input; validate types and ranges.
- Never launch an `Intent` taken from another app's extras (intent redirection). Build a new explicit `Intent` from validated fields instead.
- Use explicit intents for in‑app communication and for anything carrying sensitive data. Do not send sensitive data in implicit broadcasts; use in‑process mechanisms (e.g., Kotlin `Flow`) or restrict the receiver with `setPackage`.
- `PendingIntent`: always use `FLAG_IMMUTABLE` unless mutability is required, and always wrap an explicit `Intent`.
- Share files via `FileProvider` with `content://` URIs and per‑URI grants (`FLAG_GRANT_READ_URI_PERMISSION`); never `file://` URIs or world‑readable files.
- Content providers: set `exported="false"` unless needed, use parameterized selection arguments, and canonicalize paths in `openFile` to block traversal (`..`).
- Register runtime `BroadcastReceiver`s with `RECEIVER_NOT_EXPORTED` (API 33+) unless other apps must send to them.
- App Links: use `android:autoVerify="true"` with a published `assetlinks.json`; still validate every parameter.
- Request only the permissions you use; prefer scoped alternatives (Photo Picker, `ACTION_OPEN_DOCUMENT`) over broad storage permissions.

```kotlin
val intent = Intent(context, ReplyReceiver::class.java)
val pending = PendingIntent.getBroadcast(
    context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
```

### iOS Entry Points
- Prefer Universal Links over custom URL schemes. Treat every URL in `application(_:open:options:)` and `scene(_:openURLContexts:)` as untrusted: validate host, path, and parameters, and require user confirmation or re‑authentication before state‑changing actions.
- App Intents / Shortcuts / Siri: set `authenticationPolicy` to `.requiresAuthentication` or `.requiresLocalDeviceAuthentication` for sensitive intents (legacy SiriKit: list sensitive intents under `IntentsRestrictedWhileLocked` in the extension's `Info.plist`).
- Widgets and Live Activities: apply `.privacySensitive()` so content is redacted on the lock screen.
- App extensions and App Groups: share only what extensions need; shared containers and shared Keychain access groups widen exposure.
- Request permission usage strings only for capabilities you use, and request at time of use.

### WebViews
- Load only trusted, HTTPS content. Do not load arbitrary URLs from deep links or intents into a WebView without allow‑listing the host.
- Android:
  - Leave `javaScriptEnabled` off unless required.
  - Set `allowFileAccess = false` and `allowContentAccess = false`; never enable `setAllowFileAccessFromFileURLs` or `setAllowUniversalAccessFromFileURLs`. Serve bundled content with `WebViewAssetLoader` over `https://appassets.androidplatform.net`.
  - `addJavascriptInterface` exposes methods to every frame loaded in the WebView. Use it only with trusted content, or prefer `WebViewCompat.addWebMessageListener` with an explicit allowed‑origin set.
  - Allow‑list navigation in `shouldOverrideUrlLoading`.
- iOS:
  - Use `WKWebView` (`UIWebView` is removed).
  - In `WKScriptMessageHandler`, check `message.frameInfo.isMainFrame` and `securityOrigin` before acting; validate message bodies.
  - Disable JavaScript per navigation with `WKWebpagePreferences.allowsContentJavaScript = false` when not needed; use `limitsNavigationsToAppBoundDomains` with `WKAppBoundDomains`.

```kotlin
webView.settings.apply {
    javaScriptEnabled = false
    allowFileAccess = false
    allowContentAccess = false
}
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
        val uri = request.url
        return !(uri.scheme == "https" && uri.host in ALLOWED_HOSTS)
    }
}
```

### App and Device Integrity
- Use Play Integrity API (Android) or App Attest / `DCAppAttestService` (iOS). Bind each request to a server‑issued nonce and verify the verdict or assertion on your server; never decide on the device.
- Treat integrity signals as risk inputs (step‑up auth, rate limits), not as the only control.
- Root/jailbreak, debugger, and hook detection are optional hardening layers; do not ship secrets that depend on them staying intact.

### Cross‑Platform (React Native, Flutter)
- `AsyncStorage`, MMKV without encryption, and Flutter `shared_preferences` are plaintext. Store secrets with Keychain/Keystore‑backed libraries (`react-native-keychain`, `expo-secure-store`, `flutter_secure_storage`).
- JS bundles and Dart snapshots are extractable; Hermes bytecode and Dart obfuscation are not secrecy. `EXPO_PUBLIC_*` and `react-native-config` values ship in the app.
- Enable code signing for over‑the‑air updates (EAS Update, CodePush alternatives) so the app only runs bundles you signed.
- Disable the RN dev menu / Flutter debug mode in release; native platform rules above still apply to the generated Android and iOS projects.

### Implementation Checklist
- No secrets, private keys, or privileged tokens in the binary, bundle, resources, or public env vars.
- Tokens in the iOS Keychain with restrictive accessibility, or encrypted under a non‑exportable Android Keystore key; biometrics bound to key operations.
- OAuth via system browser with PKCE and claimed HTTPS redirects; no client secret in the app.
- No cleartext traffic, no disabled TLS validation, no user CAs in release; pins (if used) have backups and expiration.
- Sensitive files in app‑private storage, excluded from backups; no sensitive data in logs, snapshots, clipboard, or keyboard cache.
- Every Android component has explicit `exported`; incoming intents validated; `PendingIntent` immutable; files shared via `FileProvider`.
- Deep links, Universal Links, App Intents, and widgets validated or protected.
- WebViews restricted: JS, file access, and JS bridges minimized; navigation allow‑listed.
- Integrity attestation verified server‑side with a nonce.
- Release builds non‑debuggable with R8 minification and debug logging stripped.

### Test Plan
- Lint and static checks: Android Lint security checks (`ExportedReceiver`, `SetJavaScriptEnabled`, `TrustAllX509TrustManager`, `UnsafeIntentLaunch`), SwiftLint/Semgrep rules for `NSAllowsArbitraryLoads`, `print` of sensitive values, and insecure Keychain classes; MobSF scan of the built APK/IPA.
- Secret scanning of release artifacts (unzipped APK/AAB/IPA and JS bundles) with gitleaks or trufflehog; fail the build on findings.
- Unit tests asserting Keystore/Keychain key attributes (auth‑bound, non‑exportable) and that logout clears stored credentials.
- Manifest/plist assertions in CI: `exported` set everywhere, `allowBackup`/`dataExtractionRules` as intended, no cleartext or ATS exceptions.
- Instrumented tests that send malformed intents and deep links to exported entry points and confirm they are rejected.
- Verify TLS pinning and validation by proxying release builds through an intercepting proxy with a user‑installed CA; connections must fail.
