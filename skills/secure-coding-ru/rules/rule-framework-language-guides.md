---
description: Per-framework / per-language secure-by-default руководство — Django, DRF, Laravel, Symfony, Rails, .NET, Java, Node.js, PHP
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

# Руководство по фреймворкам и языкам

Каждый массовый веб-фреймворк привозит кучу security-фич, которые защищают, только когда они включены и используются правильно. Это правило — короткий список по каждому фреймворку: что включить, чего избегать, где типовые ловушки. Оно дополняет, а не заменяет кросс-правила (инъекции, auth, сессии и т. п.).

---

## Django

- `DEBUG = False` в продакшене. `DEBUG = True` — это фактически удалённое disclosure.
- Держите Django и все установленные app-ы пропатченными. Подписывайтесь на `django-announce`.
- Middleware: `SecurityMiddleware`, `XFrameOptionsMiddleware`, `CsrfViewMiddleware`. Не отключайте их поэндпоинтно без понимания причины.
- Принудительный HTTPS: `SECURE_SSL_REDIRECT = True`. HSTS через `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`, `SECURE_HSTS_PRELOAD`. Катите HSTS фазами (см. `rule-additional-cryptography.md`).
- Cookie: `SESSION_COOKIE_SECURE = True`, `CSRF_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = 'Lax'`.
- CSRF: `{% csrf_token %}` в каждом `<form>`; заголовок `X-CSRFToken` из JS (Django-доки показывают правильный паттерн).
- XSS: Django-шаблоны автоэкранируют по умолчанию. **Не** используйте `{% autoescape off %}` на user-контролируемом выводе. Для JS-контекста — `json_script`, а не ручная сборка JSON.
- Аутентификация: `django.contrib.auth` с включёнными `AUTH_PASSWORD_VALIDATORS`. Предпочтительный хэшер паролей — `argon2-cffi`.
- Секреты: `SECRET_KEY` — из окружения / secret-менеджера, не из исходников. Генерируйте через `get_random_secret_key()`.

## Django REST Framework (DRF)

- Ставьте `DEFAULT_AUTHENTICATION_CLASSES` и **ограничивающий** `DEFAULT_PERMISSION_CLASSES`. `AllowAny` никогда не должен быть project-default; по-настоящему публичные эндпоинты opt-in.
- Всегда вызывайте `self.check_object_permissions(request, obj)` на view, возвращающих или модифицирующих один объект — DRF не делает это за вас, если вы переопределили retrieve/update.
- Serializer-ы: `fields = [...]` явно. `fields = '__all__'` приглашает следующую миграцию молча раскрыть поле.
- Throttling (`DEFAULT_THROTTLE_CLASSES`) — либо делайте это на шлюзе.
- Отключайте HTTP-методы, не нужные вью (переопределяйте `http_method_names`).
- Не используйте сырой SQL в `extra()` с пользовательским вводом. Используйте ORM; если уж — параметризуйте.

## Laravel

- `APP_DEBUG=false` в продакшене; никаких читаемых из веба `storage/logs/*.log`.
- `php artisan key:generate` для `APP_KEY`; никогда не коммитить значение.
- Права ФС на `storage/` и `bootstrap/cache/` — пишет только веб-пользователь.
- Сессии/cookie: middleware `EncryptCookies` включён; `config/session.php` → `'secure' => true`, `'http_only' => true`, `'same_site' => 'lax'` (или `'strict'`), `'lifetime'` — короткий.
- Mass assignment: `$request->validated()` из FormRequest или `$request->only([...])`. Никогда `$request->all()` напрямую в `update()`.
- SQLi: Eloquent и query-builder параметризуют. Не собирайте запросы `DB::raw($userInput)` и не конкатенируйте в `whereRaw`.
- XSS: `{{ $value }}` в Blade экранирован. `{!! !!}` — только полностью доверенный контент.
- Загрузка файлов: правила `file`, `mimes:...`, `max:...`; имя файла резолвьте через `basename()`; храните вне `public/`.
- CSRF: middleware `VerifyCsrfToken` включён; `@csrf` в Blade-формах. API-маршруты, аутентифицирующие заголовком-токеном, обходят CSRF естественно.

## Symfony

- XSS: `{{ var }}` в Twig автоэкранирован. `|raw` — только если источник доверенный.
- CSRF: Forms-компонент добавляет токены по умолчанию. Для ad-hoc форм — `csrf_token(id)` и `isCsrfTokenValid(id, token)`.
- SQLi: параметризованные запросы Doctrine; никогда `->where("name = $userInput")`.
- Команды: предпочитайте Filesystem и Process. `Process` с массивом аргументов (не строкой) держит шелл вне.
- Загрузки: `#[Assert\File(...)]` для валидации; храните вне `public/`; уникальные случайные имена.
- Directory traversal: валидируйте пути через `realpath` и сравнивайте с разрешённым корнем; либо `basename` для пользовательских имён.
- Security-компонент: firewalls и provider-ы настроены явно; cookie `secure`, `httponly`, `samesite`.

## Ruby on Rails

- Полностью избегайте классического шелл-семейства, когда в игре пользовательский ввод:

  ```ruby
  eval(...); system(...); exec(...); spawn(...); `backticks`
  Process.spawn(...); Process.exec(...)
  IO.popen(...); IO.read("| ..."); IO.readlines("| ...")
  open("| ...")
  ```

  Всё это становится command-injection, если `userInput` подклеили.
- SQLi: ActiveRecord параметризует. Никогда `where("name = '#{params[:name]}'")`. Используйте `where(name: params[:name])` или `where("name = ?", params[:name])`. Для `LIKE` оборачивайте пользовательский фрагмент в `ActiveRecord::Base.sanitize_sql_like`.
- XSS: ERB автоэкранирует. Не вызывайте `.html_safe` на пользовательских данных. Нужен определённый HTML — `sanitize(html, tags: [...], attributes: [...])`.
- Сессии: для чувствительных приложений — `ActiveRecord` или Redis-store, не cookie-store. `config.force_ssl = true` в продакшене.
- Аутентификация: Devise или другая проверенная библиотека. Не пишите своё.
- CSRF: `protect_from_forgery with: :exception` в `ApplicationController`. Не отключайте «для удобства».
- Редиректы: валидируйте цель по allow-list; никогда `redirect_to params[:url]` напрямую.
- CORS: `rack-cors` с конкретным списком origin; никогда `origins '*'` для аутентифицируемых эндпоинтов.

## .NET (ASP.NET Core)

- Держите SDK, runtime и NuGet-пакеты пропатченными. `dotnet list package --vulnerable --include-transitive` в CI.
- Авторизация: `[Authorize]` с явными policy; пишите серверную проверку, даже если UI enforce-ит то же правило. IDOR закрывайте резолвом ресурсов через user-scoped-запросы.
- Аутентификация / сессии: ASP.NET Identity там, где применимо; настроен lockout; cookie `HttpOnly` + `Secure`; короткие таймауты.
- Криптография: AES-GCM для данных at rest; PBKDF2 c ≥ 600 000 итераций или платформенная Argon2-биндинг для паролей; DPAPI для локальных секретов на Windows. TLS минимум 1.2, предпочтительно 1.3.
- Инъекции: `SqlParameter` или параметры EF Core на каждом запросе; allow-list-валидация для всего, что становится частью пути или идентификатора.
- Конфиг: `UseHttpsRedirection()`; срезайте server-заголовки (`AddServerHeader = false`); CSP, HSTS, `X-Content-Type-Options: nosniff` через middleware (или прямо заголовками ответа).
- CSRF: anti-forgery-токены с `[ValidateAntiForgeryToken]` на state-changing-экшнах; AJAX шлёт `RequestVerificationToken`.
- Десериализация: никаких `BinaryFormatter`. Новый код — `System.Text.Json`; когда нужен XML — `DataContractSerializer`.

## Java / JAAS

- SQL / JPA: `PreparedStatement` / `@NamedQuery` с bind-параметрами. Не конкатенируйте.
- XSS: экранируйте на выходе известной библиотекой (OWASP Java Encoder, OWASP Java HTML Sanitizer). На входе — allow-list-валидация.
- Логирование: параметризованное (`log.info("user {} logged in", user)`) — не конкатенация с пользовательскими данными (log-injection).
- Криптография: AES-GCM со случайным 12-байтным nonce; никаких хардкод-ключей; KMS / HSM для материала ключа.
- JAAS: `LoginModule`, реализующий `initialize/login/commit/abort/logout`. Материал кредов держите вне общих логгеров. Публичные и приватные креды сегрегируйте на `Subject`.
- XXE / десериализация: см. `rule-xml-serialization-hardening.md`.

## Node.js

- Лимиты размера запроса (`body-parser` / опция `limit` у `express`) — отсекайте oversize-тела рано.
- Валидируйте и санитизируйте ввод; экранируйте вывод по контексту.
- Никогда не передавайте пользовательский ввод в `eval`, `Function`, `child_process.exec`. Для subprocess-ов — `child_process.execFile` / `spawn` с массивом аргументов и `{ shell: false }`.
- Используйте `helmet` для базовых HTTP-заголовков; `hpp` для HTTP Parameter Pollution; `express-rate-limit` или шлюз для rate-limit.
- Cookie: `secure`, `httpOnly`, `sameSite` корректно. `NODE_ENV=production`, чтобы фреймворки сбросили verbose-дефолты.
- `npm ci`, `npm audit`, Snyk или аналог. Применимо `rule-supply-chain-dependencies.md`.
- ReDoS — тестируйте user-facing regex на катастрофический backtracking. `safe-regex` как линтер.

## PHP

- Упрочнение `php.ini` в продакшене:
  - `expose_php = Off`
  - `display_errors = Off`, `log_errors = On`
  - `allow_url_fopen = Off`, `allow_url_include = Off`
  - `open_basedir = /var/www/app`
  - `disable_functions = exec,passthru,shell_exec,system,proc_open,popen`
  - `session.cookie_secure = 1`, `session.cookie_httponly = 1`, `session.cookie_samesite = Strict`
  - `session.use_strict_mode = 1`, `session.use_only_cookies = 1`
- Лимиты аплоада: `upload_max_filesize`, `post_max_size`, `max_file_uploads`, `max_input_time`, `memory_limit`, `max_execution_time` — все на скромные значения.
- Рассмотрите Snuffleupagus или аналог для hardening.
- PDO с prepared statement; никогда `mysqli_query($conn, "SELECT ... '$user'")`.
- `htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')` при выводе переменных в HTML.

---

## Кросс-чек-лист реализации

- CSRF / XSS / session-защиты каждого фреймворка **включены** и используются на каждом запросе.
- Параметризация — стандарт по всем data-access путям.
- Ни одна `exec`-семейная функция не принимает недоверенный ввод. Нужен subprocess — структурированный запуск + allow-list-команда.
- HTTPS + HSTS везде; флаги безопасности cookie выставлены.
- Секреты — из окружения / vault, никогда из исходников.
- Редирект-цели валидированы по allow-list.
- Зависимости свежие; SCA и SAST в CI.
- Debug-фичи отключены в продакшене.

Когда выбранный фреймворк не похож ни на один выше, принцип тот же: ищите «secure default» по мнению мейнтейнеров, включайте каждый переключатель, который его реализует, документируйте всё, что выключаете.
