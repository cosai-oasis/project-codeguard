---
description: Per-framework / per-language secure-by-default guidance — Django, DRF, Laravel, Symfony, Rails, .NET, Java, Node.js, PHP
languages:
  - c
  - java
  - javascript
  - kotlin
  - php
  - python
  - ruby
  - typescript
  - xml
  - yaml
alwaysApply: false
rule_id: rule-framework-language-guides
---

# Framework & Language Guides

Each mainstream web framework ships a pile of security features that only protect you when they are on and used correctly. This rule is a short, per-framework list of what to enable, what to avoid, and where the common pitfalls are. It complements, not replaces, the cross-cutting rules (injection, auth, sessions, etc.).

---

## Django

- `DEBUG = False` in production. `DEBUG = True` is effectively remote information disclosure.
- Keep Django and all installed apps patched. Subscribe to `django-announce`.
- Middleware: `SecurityMiddleware`, `XFrameOptionsMiddleware`, `CsrfViewMiddleware`. Do not disable them per endpoint unless you know why.
- Force HTTPS: `SECURE_SSL_REDIRECT = True`. Configure HSTS via `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_HSTS_PRELOAD`. Roll out HSTS in phases (see `rule-additional-cryptography.md`).
- Cookies: `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`.
- CSRF: `{% csrf_token %}` in every `<form>`; `X-CSRFToken` header from JS (the Django docs show the right pattern).
- XSS: Django templates auto-escape by default. Do **not** use `{% autoescape off %}` on user-controlled output. For JS context, use `json_script` rather than building JSON by hand.
- Authentication: `django.contrib.auth` with `AUTH_PASSWORD_VALIDATORS` enabled. Prefer `argon2-cffi` as the password hasher.
- Secrets: `SECRET_KEY` comes from the environment / secret manager, not source. Use `get_random_secret_key()` when generating.

## Django REST Framework (DRF)

- Set `DEFAULT_AUTHENTICATION_CLASSES` and **restrictive** `DEFAULT_PERMISSION_CLASSES`. `AllowAny` must never be the project-level default; endpoints that are truly public opt in.
- Always call `self.check_object_permissions(request, obj)` on views that return or modify a single object — DRF does not call it for you on retrieve/update paths you override.
- Serializers: list `fields = [...]` explicitly. `fields = '__all__'` invites the next migration to silently expose a field.
- Throttling (`DEFAULT_THROTTLE_CLASSES`) — or do it at the gateway.
- Disable HTTP methods the view does not need (override `http_method_names`).
- Never use raw SQL in `extra()` with user input. Use the ORM; if you must, parameterize.

## Laravel

- `APP_DEBUG=false` in production; no `storage/logs/*.log` readable from the web.
- `php artisan key:generate` for `APP_KEY`; never commit the value.
- Filesystem permissions for `storage/` and `bootstrap/cache/` — writable by the web user only.
- Sessions/cookies: `EncryptCookies` middleware on; `config/session.php` → `'secure' => true`, `'http_only' => true`, `'same_site' => 'lax'` (or `'strict'`), `'lifetime'` tuned short.
- Mass assignment: use `$request->validated()` from a FormRequest, or `$request->only([...])`. Never `$request->all()` directly into `update()`.
- SQLi: Eloquent and the query builder parameterize. Do not build queries with `DB::raw($userInput)` or concatenate into `whereRaw`.
- XSS: `{{ $value }}` in Blade is escaped. Use `{!! !!}` only with fully-trusted content.
- File uploads: validation rules `file`, `mimes:...`, `max:...`; resolve filename with `basename()`; store outside `public/`.
- CSRF: `VerifyCsrfToken` middleware on; `@csrf` in Blade forms. API routes authenticated by header-bearing tokens bypass CSRF naturally.

## Symfony

- XSS: Twig `{{ var }}` is auto-escaped. `|raw` only when the source is trusted.
- CSRF: Forms component adds tokens by default. For ad-hoc forms, `csrf_token(id)` and `isCsrfTokenValid(id, token)`.
- SQLi: Doctrine parameterized queries; never `->where("name = $userInput")`.
- Command execution: prefer the Filesystem and Process components. `Process` with an array of arguments (not a string) keeps the shell out.
- Uploads: `#[Assert\File(...)]` for validation; store outside `public/`; unique random filenames.
- Directory traversal: validate paths with `realpath` and compare to an allowed root; or use `basename` for user-supplied filenames.
- Security component: firewalls and providers configured explicitly; cookies `secure`, `httponly`, `samesite`.

## Ruby on Rails

- Avoid the classic shell-execution family entirely when user input is in scope:

  ```ruby
  eval(...); system(...); exec(...); spawn(...); `backticks`
  Process.spawn(...); Process.exec(...)
  IO.popen(...); IO.read("| ..."); IO.readlines("| ...")
  open("| ...")
  ```

  All of these become command injection if `userInput` is concatenated in.
- SQLi: ActiveRecord parameterizes. Never `where("name = '#{params[:name]}'")`. Use `where(name: params[:name])` or `where("name = ?", params[:name])`. For `LIKE`, wrap the user fragment with `ActiveRecord::Base.sanitize_sql_like`.
- XSS: ERB auto-escapes. Do not call `.html_safe` on user data. If you need to allow specific HTML, use `sanitize(html, tags: [...], attributes: [...])`.
- Sessions: for sensitive apps, use `ActiveRecord` or Redis store, not the cookie store. `config.force_ssl = true` in production.
- Authentication: Devise or other vetted library. Do not roll your own.
- CSRF: `protect_from_forgery with: :exception` in `ApplicationController`. Do not disable for convenience.
- Redirects: validate the target against an allow-list; never `redirect_to params[:url]` directly.
- CORS: `rack-cors` configured with a specific origin list; never `origins '*'` for authenticated endpoints.

## .NET (ASP.NET Core)

- Keep the SDK, runtime, and NuGet packages patched. `dotnet list package --vulnerable --include-transitive` in CI.
- Authorization: `[Authorize]` with explicit policies; write server-side checks even when the UI enforces the same rule. Cover IDOR by resolving resources through user-scoped queries.
- Authentication / sessions: ASP.NET Identity where applicable; lockout configured; cookies `HttpOnly` + `Secure`; short timeouts.
- Cryptography: AES-GCM for data at rest; PBKDF2 with ≥ 600 000 iterations or the platform-provided Argon2 binding for passwords; DPAPI for local secret storage on Windows. TLS 1.2 minimum, 1.3 preferred.
- Injection: `SqlParameter` or EF Core parameters on every query; allow-list validation on anything that becomes part of a path or identifier.
- Config: `UseHttpsRedirection()`; strip server headers (`AddServerHeader = false`); CSP, HSTS, `X-Content-Type-Options: nosniff` via middleware (or in response headers directly).
- CSRF: anti-forgery tokens with `[ValidateAntiForgeryToken]` on state-changing actions; AJAX sends `RequestVerificationToken`.
- Deserialization: never `BinaryFormatter`. `System.Text.Json` for new code; `DataContractSerializer` when XML is needed.

## Java / JAAS

- SQL / JPA: `PreparedStatement` / `@NamedQuery` with bind parameters. Do not concatenate.
- XSS: sanitize on output with a known library (OWASP Java Encoder, OWASP Java HTML Sanitizer). Validate on input with allow-lists.
- Logging: parameterized logging (`log.info("user {} logged in", user)`) — not string concatenation with user data (log injection).
- Crypto: AES-GCM with a random 12-byte nonce; never hardcode keys; KMS / HSM for key material.
- JAAS: `LoginModule` implementing `initialize/login/commit/abort/logout`. Keep credential material out of shared logger scopes. Segregate public and private credentials on the `Subject`.
- XXE / deserialization: see `rule-xml-serialization-hardening.md`.

## Node.js

- Request size limits (`body-parser` / `express` `limit` option) — reject oversized bodies early.
- Validate and sanitize input; encode output per context.
- Never pass user input into `eval`, `Function`, `child_process.exec`. For subprocesses, `child_process.execFile` / `spawn` with an argument array and `{ shell: false }`.
- Use `helmet` for baseline HTTP headers; `hpp` for HTTP Parameter Pollution; `express-rate-limit` or a gateway for rate limiting.
- Cookies: `secure`, `httpOnly`, `sameSite` set correctly. `NODE_ENV=production` so frameworks drop verbose defaults.
- `npm ci`, `npm audit`, Snyk or equivalent. `rule-supply-chain-dependencies.md` applies.
- ReDoS — test user-facing regexes for catastrophic backtracking. `safe-regex` as a linter.

## PHP

- `php.ini` hardening in production:
  - `expose_php = Off`
  - `display_errors = Off`, `log_errors = On`
  - `allow_url_fopen = Off`, `allow_url_include = Off`
  - `open_basedir = /var/www/app`
  - `disable_functions = exec,passthru,shell_exec,system,proc_open,popen`
  - `session.cookie_secure = 1`, `session.cookie_httponly = 1`, `session.cookie_samesite = Strict`
  - `session.use_strict_mode = 1`, `session.use_only_cookies = 1`
- Upload limits: `upload_max_filesize`, `post_max_size`, `max_file_uploads`, `max_input_time`, `memory_limit`, `max_execution_time` — all set to modest values.
- Consider Snuffleupagus or similar hardening extensions.
- PDO with prepared statements; never `mysqli_query($conn, "SELECT ... '$user'")`.
- `htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')` when echoing variables into HTML.

---

## Cross-cutting implementation checklist

- Each framework's CSRF / XSS / session protections are **on** and used for every request.
- Parameterization is standard across every data-access path.
- No `exec`-family functions receive untrusted input. If a subprocess is needed, structured execution + allow-listed command.
- HTTPS + HSTS everywhere; secure cookie flags set.
- Secrets come from environment / vault, never from source.
- Redirect targets validated against allow-lists.
- Dependencies kept current; SCA and SAST in CI.
- Debug features off in production.

When the chosen framework differs from everything above, the principle is: find what the maintainers consider the "secure default", turn on every switch that implements it, and document anything you turn off.
