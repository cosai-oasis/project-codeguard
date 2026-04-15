---
description: Клиентская веб-безопасность — XSS, CSP, CSRF, clickjacking, XS-Leaks, сторонние скрипты, браузерное хранилище
languages:
  - c
  - html
  - javascript
  - php
  - typescript
  - vlang
alwaysApply: false
rule_id: rule-client-web-browser
---

# Клиентская веб-безопасность

## Модель угроз

Когда контент оказался в браузере, цели атакующего: исполнить скрипт в источнике, заставить пользователя сделать незапланированное действие либо прочитать данные через границу источника. Защита слоится: контекстное экранирование, Content Security Policy, CSRF-токены, контроль фреймов, митигации XS-Leak и аккуратная работа со сторонним кодом.

Починить XSS первым — самый высокий леверидж: большинство остальных защит либо предполагают, что XSS ушёл, либо смягчают его последствия.

## XSS — экранируйте по контексту

Ввод безопасен ровно в одном контексте рендеринга. «HTML-escaped» универсально безопасным не бывает.

| Контекст | Корректное экранирование |
|----------|--------------------------|
| HTML body | `textContent` или HTML-escape и вставка как HTML |
| HTML-атрибут (в кавычках) | Attribute-escape; всегда кавычьте атрибуты |
| `href`, `src` | Валидируйте схему (только `https:` или явный allow-list) и URL-энкодьте |
| JS-строковый литерал | JSON-энкод внутри `<script>`; **никогда** не собирайте JS из недоверенных строк |
| CSS-значение | Allow-list числовых/цветовых значений; никогда не вставляйте сырой style |
| URL path/query | URL-энкод каждый компонент правильным энкодером |

Паттерны, которых избегайте полностью:

- Конкатенация недоверенных строк в `innerHTML`, `outerHTML`, `document.write`, `Range.createContextualFragment`.
- Передача недоверенного ввода в `eval`, `new Function`, строковую форму `setTimeout` / `setInterval`, `setImmediate`, `execScript`.
- Задание event-handler атрибутов (`onclick="..."`) недоверенными значениями. Используйте `addEventListener` с JS-функцией.
- Присваивание недоверенных строк в `location`, `location.href`, `window.name`.

Когда HTML всё-таки нужно рендерить (rich-text ввод, рендер Markdown), прогоняйте через проверенный санитайзер:

```js
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['p', 'b', 'i', 'ul', 'li', 'a'],
  ALLOWED_ATTR: ['href', 'rel', 'target'],
  ALLOW_DATA_ATTR: false,
});
element.innerHTML = clean;
```

Предпочитайте серверную санитизацию — серверу проще оставаться консистентным между клиентами.

### Trusted Types

В современных браузерах включайте Trusted Types, чтобы опасные sink-и отказывались принимать строки, не типизированные allow-list-policy. Это самое эффективное из сегодня деплоимых средств против XSS.

```http
Content-Security-Policy: require-trusted-types-for 'script'; trusted-types my-app#default
```

```js
const policy = trustedTypes.createPolicy('my-app', {
  createHTML: input => DOMPurify.sanitize(input),
});
element.innerHTML = policy.createHTML(userHtml);
```

## Content Security Policy

CSP — страховочный слой против XSS, а не основной защитник. Разворачивайте параллельно с экранированием, а не вместо него.

### Рекомендации

- Предпочитайте **nonce-based** или **hash-based** политики. Host allow-list (`script-src example.com`) хрупок и регулярно обходится через JSONP-эндпоинты.
- Начните с **Report-Only**, запустите endpoint отчётов, поправьте что ломается, затем включайте enforcement.
- Запрещайте inline-скрипты, если они не с nonce; запрещайте `eval` (`'unsafe-eval'`).
- Ставьте `object-src 'none'` и `base-uri 'self'` — это закрывает типовые трюки обхода.
- Проставьте `frame-ancestors` — он заменяет `X-Frame-Options` (см. Clickjacking ниже).

### Разумная база

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{RANDOM}';
  style-src 'self';
  img-src 'self' data:;
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'self';
  form-action 'self';
  upgrade-insecure-requests;
  require-trusted-types-for 'script';
  report-to csp-reports
```

## Защита от CSRF

Любой state-changing запрос (POST, PUT, PATCH, DELETE) должен быть защищён от CSRF. Для сайта с cookie-сессией:

- Используйте synchronizer-token из фреймворка; отклоняйте запрос, если токен отсутствует, пустой или не совпадает с сессионным.
- Ставьте сессионные cookie `Secure`, `HttpOnly`, `SameSite=Lax` (дефолт) или `SameSite=Strict` (строже). Префикс `__Host-` делает cookie «host-only» и только `Secure`.
- Валидируйте `Origin` и/или `Referer` на кросс-ориджинных мутациях. Отсутствие `Origin` на мутации — уже подозрительно.
- GET никогда не должен менять состояние. GET-эндпоинт, меняющий данные, атакуется простым `<img src>`.

Для API с токен-аутентификацией (токен в заголовке `Authorization: Bearer`, не в cookie) CSRF структурно невозможен — чужой источник не может задать этот заголовок. Но: если вы читаете токен из localStorage и туда его кладёте — см. `rule-sessions-cookies.md` про риски хранилища.

## Clickjacking

- Основное: `Content-Security-Policy: frame-ancestors 'none'` (или конкретный список).
- Легаси-фолбэк для старых браузеров: `X-Frame-Options: DENY` или `SAMEORIGIN`. Браузеры, поддерживающие CSP, игнорируют этот заголовок в пользу `frame-ancestors`.
- Для чувствительных действий, которые должны быть фреймабельны, добавляйте UX-подтверждение, которое атакующий frame-ом легко не подделает.

## Кросс-сайт-утечки (XS-Leaks)

Атаки XS-Leak выводят информацию (залогинен? есть ли ресурс?) из наблюдаемых побочных каналов: размер ответа, тайминг, количество фреймов, поведение ошибок, кэш-хиты.

- Ставьте cookie `SameSite=Strict` для действий, которые никогда не должны запускаться с других источников.
- Используйте заголовки запроса **Fetch Metadata** (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`) и отклоняйте неожиданные кросс-сайт запросы.
- Отправляйте **COOP** (`Cross-Origin-Opener-Policy: same-origin`), **COEP** (`Cross-Origin-Embedder-Policy: require-corp`) и **CORP** (`Cross-Origin-Resource-Policy: same-origin`) для изоляции браузинг-контекстов.
- На чувствительных ответах — `Cache-Control: no-store`; рассмотрите добавление случайного per-user токена в кэшируемые URL, чтобы исключить cache-probe-атаки.

## Сторонний JavaScript

Каждый тег, который вы впустили на страницу, работает в вашем origin-е. Минимизируйте и изолируйте.

- Предпочитайте sandbox-iframe с `sandbox="allow-scripts"` (без `allow-same-origin`) и `postMessage` с явной проверкой origin.
- Для скриптов с CDN — **Subresource Integrity**:
  ```html
  <script src="https://cdn.vendor.com/app.js"
          integrity="sha384-abc123..."
          crossorigin="anonymous"></script>
  ```
- Выставляйте вендорским тегам первопартийный, санитизированный data-layer, а не позволяйте им самостоятельно читать DOM.
- Управляйте через правила tag-manager и вендорские контракты; держите библиотеки пропатченными.

## HTML5 API — CORS, WebSocket, хранилище, postMessage

- **`postMessage`**: всегда указывайте точный target origin (`"*"` никогда не корректен); на приёме всегда валидируйте `event.origin`.
- **CORS**: конкретный allow-list origin, не `*`. CORS — это политика чтения в браузере, **не** механизм авторизации; не полагайтесь на него для защиты state-changing эндпоинтов. Валидируйте preflight.
- **WebSocket**: только `wss://`. Проверяйте `Origin` при upgrade. Аутентифицируйте сразу. Ставьте лимит на размер сообщения.
- **Web storage** (`localStorage`, `sessionStorage`): не храните здесь session-токены и любые другие креды. XSS тривиально их вытянет. Материал сессии кладите в `HttpOnly`-cookie; если нужно клиент-доступное состояние — пусть будет нечувствительное или изолируйте за Web Worker.
- **Ссылки**: `target="_blank"` + внешний хост должен нести `rel="noopener noreferrer"`.

## HTTP-заголовки безопасности (видимые браузеру)

В дополнение к CSP / frame-ancestors:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (preload после обкатки).
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: strict-origin-when-cross-origin` (или `no-referrer` для чувствительных путей).
- `Permissions-Policy` с теми фичами, что вы реально используете; всё остальное — denied.

## Безопасные паттерны работы с DOM

- Стройте DOM через `document.createElement` и ставьте `textContent` / безопасные атрибуты — избегайте вставки сырого HTML.
- Собирайте JSON через `JSON.stringify`, никогда конкатенацией.
- Предпочитайте `addEventListener` атрибут-хендлерам.
- Используйте strict-mode и модули (`<script type="module">`) — оба сужают случайные глобальные утечки, релевантные DOM clobbering.

## Чек-лист реализации

- У каждого sink-а рендера есть контекстное экранирование; никаких `innerHTML` с недоверенными данными.
- CSP с nonce + Trusted Types включены; нарушения идут в мониторящийся endpoint.
- CSRF-токены на всех state-changing запросах (кроме аутентификации заголовком, не cookie); cookie — `Secure` + `HttpOnly` + `SameSite`.
- Задан `frame-ancestors`; `X-Frame-Options` — как фолбэк.
- Проверки Fetch Metadata на чувствительных эндпоинтах; COOP / COEP / CORP где применимо.
- Сторонние скрипты минимизированы, по возможности в sandbox-е, с SRI.
- В web-хранилище нет session-материала; `target="_blank"` несёт `rel="noopener noreferrer"`.
- Заголовки безопасности присутствуют и проверяются автоматическим чекером.

## План тестирования

- Статические сканы на опасные DOM-API и отсутствие экранирования.
- E2E-тесты, отправляющие CSRF-формы без токена и проверяющие отказ.
- Clickjacking — страница отказывается встраиваться в произвольного родителя.
- Мониторинг CSP-отчётов в staging неделю до включения enforcement.
- Ручные XS-Leak-пробинги (количество фреймов, тайминг, кэш) на чувствительных эндпоинтах.
- Open-redirect-зонды на каждом эндпоинте, принимающем URL или доменный параметр.
