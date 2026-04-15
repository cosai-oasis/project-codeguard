# Скилл безопасной разработки — источники и атрибуция

## Основные источники

### OWASP Cheat Sheet Series

- **Сайт проекта**: <https://cheatsheetseries.owasp.org/>
- **Лицензия**: Creative Commons Attribution-ShareAlike 4.0 International (CC-BY-SA 4.0)
- **Репозиторий**: <https://github.com/OWASP/CheatSheetSeries>
- **Роль в скилле**: канонический референс по валидации ввода, XSS, CSRF, хранению паролей, работе с сессиями, XML/десериализации, загрузке файлов, контролю доступа, логированию, криптографическому хранению и множеству фреймворк-ориентированных гайдов.

### OASIS CoSAI — Project CodeGuard

- **Сайт проекта**: <https://project-codeguard.org/>
- **Коалиция**: Coalition for Secure AI (OASIS Open Project) — <https://www.oasis-open.org/projects/cosai/>
- **Репозиторий**: <https://github.com/cosai-oasis/project-codeguard>
- **Лицензия**: CC-BY-4.0 для правил и контента скилов
- **Роль в скилле**: сама структура набора правил (always-apply + context, таблица язык → правила, MCP-руководство, пост-квантовая криптопозиция) вдохновлена Project CodeGuard напрямую. Текущий скилл меняет формулировки и перестраивает содержимое, но сохраняет общую модель.

### CERT C Secure Coding Standard

- **Сайт проекта**: <https://wiki.sei.cmu.edu/confluence/display/c/SEI+CERT+C+Coding+Standard>
- **Издатель**: Software Engineering Institute, Carnegie Mellon University
- **Роль в скилле**: основа правила по memory safety для C/C++ — список запрещённых функций, ограниченные по размеру замены, затирание чувствительной памяти, флаги тулчейна.

### Публикации NIST

- **SP 800-63B** — Digital Identity Guidelines (аутентификация и жизненный цикл). <https://pages.nist.gov/800-63-3/sp800-63b.html>
- **SP 800-90A/B/C** — генерация случайных битов.
- **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)**, **FIPS 203 (ML-KEM)** — пост-квантовые стандарты подписей и KEM.
- **Роль в скилле**: авторитетный источник по парольной политике, иерархии MFA-факторов и выбору пост-квантовых примитивов.

### IETF RFC (транспорт и криптография)

- **RFC 8446** — TLS 1.3.
- **RFC 7525** — Recommendations for Secure Use of TLS.
- **RFC 6797** — HTTP Strict Transport Security.
- **RFC 6265bis** — Cookies (SameSite, `__Host-`-префикс).
- **RFC 7519** — JSON Web Token.
- **RFC 6749 / 8252 / 7636** — OAuth 2.0 и PKCE.
- **RFC 9242 / 9370** — пост-квантовый гибридный обмен ключами в IKEv2.
- **Роль в скилле**: авторитетные источники для конфигурации транспортного уровня, семантики cookie, обращения с токенами и гибридного PQC-обмена.

### Вендорские гайды безопасности

- **OWASP Mobile Application Security Testing Guide / Verification Standard** (MASTG / MASVS) — <https://mas.owasp.org/>
- **OWASP API Security Top 10 (2023)** — <https://owasp.org/API-Security/>
- **Android Developers — Security guidance** — <https://developer.android.com/topic/security/best-practices>
- **Apple Platform Security Guide** — <https://support.apple.com/guide/security/welcome/web>
- **CIS Benchmarks** — Docker, Kubernetes, облачные платформы. <https://www.cisecurity.org/cis-benchmarks>
- **SLSA framework** — <https://slsa.dev/>
- **Sigstore / Cosign** — <https://www.sigstore.dev/>
- **SPIFFE / SPIRE** — <https://spiffe.io/>
- **Роль в скилле**: правила по мобильным приложениям, API, контейнерам, Kubernetes, IaC и цепочке поставок.

### Браузерная безопасность

- **MDN Web Docs — Web Security** — <https://developer.mozilla.org/en-US/docs/Web/Security>
- **W3C / WICG — Content Security Policy, Trusted Types, Permissions Policy, Fetch Metadata, COOP/COEP/CORP** — спецификации на <https://www.w3.org/TR/> и <https://wicg.github.io/>
- **Google Web Fundamentals — Secure by Default** — <https://web.dev/secure/>
- **Роль в скилле**: правило клиентской веб-безопасности (XSS, CSP, Trusted Types, CSRF, clickjacking, XS-Leaks, сторонний JavaScript, защитные HTTP-заголовки).

### Референс-архитектуры облачных провайдеров

- AWS Well-Architected Framework — Security Pillar.
- Google Cloud Security Foundations.
- Azure Security Benchmark.
- **Роль в скилле**: правила IaC и Kubernetes (сетевая конфигурация, IAM, шифрование, логирование, бэкапы).

### Model Context Protocol

- **Спецификация**: <https://modelcontextprotocol.io/>
- **CoSAI MCP Security Guidelines**: <https://www.oasis-open.org/projects/cosai/>
- **Роль в скилле**: правило по безопасности MCP.

## Атрибуция по правилам

Каждое правило ниже перечисляет свои основные источники. Многие правила опираются на несколько — они приведены в приблизительном порядке вклада.

### Уровень A — применять всегда

| Правило | Основные источники |
|---------|--------------------|
| `always-no-hardcoded-secrets.md` | Правило hardcoded-credentials из Project CodeGuard; OWASP Secrets Management Cheat Sheet; индустриальные regex-паттерны секретов (AWS, GitHub, Stripe, Google, Slack). |
| `always-crypto-algorithms.md` | Правило crypto-algorithms из Project CodeGuard; NIST FIPS 203 / 204 / 205; RFC 8446 (TLS 1.3); RFC 9242 / 9370 (IKEv2 PQC); документация OpenSSL EVP API; рекомендации BSI, NCSC, CNSA 2.0. |
| `always-certificate-hygiene.md` | Правило digital-certificates из Project CodeGuard; RFC 5280 (X.509); справочник команд OpenSSL; CA/Browser Forum Baseline Requirements. |

### Уровень B — контекстные правила

| Правило | Основные источники |
|---------|--------------------|
| `rule-additional-cryptography.md` | OWASP Cryptographic Storage Cheat Sheet, Transport Layer Security Cheat Sheet, HSTS Cheat Sheet, Pinning Cheat Sheet; NIST SP 800-52; RFC 6797 (HSTS); RFC 7919 (FFDHE). |
| `rule-api-web-services.md` | OWASP API Security Top 10 (2023); OWASP REST Security Cheat Sheet, GraphQL Cheat Sheet, SOAP/Web Service Security Cheat Sheet, SSRF Prevention Cheat Sheet, Microservices Security Cheat Sheet; спецификации OpenAPI / JSON Schema. |
| `rule-authentication-mfa.md` | NIST SP 800-63B; OWASP Authentication Cheat Sheet, Password Storage Cheat Sheet, MFA Cheat Sheet, Forgot Password Cheat Sheet, JWT for Java Cheat Sheet, SAML Security Cheat Sheet, OAuth 2.0 Cheat Sheet; RFC 7519, RFC 6749/6819, RFC 8252, RFC 7636; IETF OAuth 2.0 Security BCP (RFC 8725/9700). |
| `rule-authorization-access-control.md` | OWASP Authorization Cheat Sheet, Access Control Cheat Sheet, IDOR Prevention Cheat Sheet, Mass Assignment Cheat Sheet, Transaction Authorization Cheat Sheet; OWASP Top 10 A01:2021 (Broken Access Control). |
| `rule-client-web-browser.md` | OWASP XSS Prevention Cheat Sheet, DOM-based XSS Prevention, Content Security Policy Cheat Sheet, CSRF Prevention Cheat Sheet, Clickjacking Defense Cheat Sheet, XS-Leaks Cheat Sheet, Third-Party JavaScript Management, HTML5 Security Cheat Sheet, HTTP Headers Cheat Sheet; спецификации W3C CSP 3, Trusted Types, Fetch Metadata, COOP/COEP/CORP; MDN Web Security. |
| `rule-kubernetes-hardening.md` | CIS Kubernetes Benchmark; официальная документация Kubernetes — Pod Security Standards, NetworkPolicy, RBAC; policy-библиотеки OPA Gatekeeper / Kyverno; документация Sigstore cosign; SLSA framework. |
| `rule-database-data-storage.md` | OWASP Database Security Cheat Sheet; CIS Benchmarks (MySQL, PostgreSQL, SQL Server, MongoDB, Redis); вендорские гайды по каждой СУБД; PCI DSS v4. |
| `rule-ci-cd-containers.md` | OWASP CI/CD Security Cheat Sheet, Docker Security Cheat Sheet, Node.js Docker Cheat Sheet, C-Based Toolchain Hardening, Virtual Patching Cheat Sheet; CIS Docker Benchmark; SLSA; Sigstore; документация BuildKit по секретам. |
| `rule-file-upload-handling.md` | OWASP File Upload Cheat Sheet; OWASP Unrestricted File Upload; Snyk и вендорские разборы CVE для парсеров изображений и документов; справочные материалы про zip-slip и zip-bomb. |
| `rule-framework-language-guides.md` | OWASP-чит-шиты по фреймворкам: Django Security, Django REST Framework, Laravel, Symfony, Ruby on Rails, .NET Security, Java Security, JAAS, Node.js Security, PHP Configuration; официальные гайды фреймворков (раздел «Security» в Django, Rails Security Guide, ASP.NET Core Security, Laravel Security, Symfony Security). |
| `rule-infrastructure-as-code.md` | CIS Cloud Benchmarks (AWS, Azure, GCP); AWS Well-Architected Security Pillar; Google Cloud Security Foundations; Azure Security Benchmark; Terraform security docs; CloudFormation best practices. |
| `rule-input-validation-injection.md` | OWASP Input Validation Cheat Sheet, Injection Prevention, SQL Injection Prevention, OS Command Injection Defense, LDAP Injection Prevention, Query Parameterization, Prototype Pollution Prevention; Salesforce Apex SOQL injection guidance; OWASP Top 10 A03:2021. |
| `rule-logging-monitoring.md` | OWASP Logging Cheat Sheet, Logging Vocabulary Cheat Sheet; NIST SP 800-92 (Guide to Computer Security Log Management); OWASP Top 10 A09:2021 (Security Logging and Monitoring Failures). |
| `rule-mcp-security.md` | OASIS CoSAI MCP Security Guidelines; спецификация Model Context Protocol; документация SPIFFE/SPIRE; OWASP Top 10 for LLM Applications. |
| `rule-mobile-app-security.md` | OWASP Mobile Application Security Verification Standard (MASVS); OWASP Mobile Security Testing Guide (MSTG); Android Developers security guidance; Apple Platform Security Guide; документация Play Integrity API и App Attest. |
| `rule-privacy-data-protection.md` | OWASP User Privacy Protection Cheat Sheet; GDPR статьи 5, 15–22, 25, 32; ISO/IEC 27701; NIST Privacy Framework. |
| `rule-c-cpp-memory-safety.md` | CERT C Secure Coding Standard — правила STR, MEM, INT; C11 Annex K (bounds-checking interfaces); ISO/IEC TR 24731; документация OpenSSL `OPENSSL_cleanse`; документация компиляторов (GCC, Clang) по hardening-флагам. |
| `rule-sessions-cookies.md` | OWASP Session Management Cheat Sheet, Cookie Theft Mitigation Cheat Sheet; RFC 6265bis (`SameSite`, `__Host-`-префикс); OWASP Top 10 A07:2021. |
| `rule-supply-chain-dependencies.md` | OWASP Vulnerable Dependency Management Cheat Sheet, NPM Security Cheat Sheet, Software Component Verification Standard (SCVS); SLSA framework; Sigstore; OWASP Top 10 A06:2021 (Vulnerable and Outdated Components); OpenSSF Scorecard. |
| `rule-xml-serialization-hardening.md` | OWASP XML External Entity Prevention Cheat Sheet, Deserialization Cheat Sheet, XML Security Cheat Sheet; документация пакета `defusedxml`; вендорские доки для Jackson, XStream, Json.NET с безопасной конфигурацией. |
