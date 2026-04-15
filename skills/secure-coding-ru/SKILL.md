---
name: secure-coding-ru
description: Правила безопасной по умолчанию разработки для ИИ-агентов. Загружайте этот скилл при генерации, правке или ревью кода — чтобы типовые классы уязвимостей (инъекции, слабая криптография, пробелы в аутентификации и авторизации, захардкоженные секреты, небезопасная десериализация и т. п.) предотвращались заранее, а не лечились постфактум.
version: "1.0"
scope: "безопасность ПО при ИИ-ассистированной генерации и ревью кода"
---

## Когда агенту загружать этот скилл

Загружайте всегда, когда код собираются писать, править или ревьюить — и особенно в следующих ситуациях:

- Добавляется новая фича, эндпоинт, обработчик или форма
- Существующий код рефакторится или расширяется в зоне, чувствительной к безопасности
- В задаче всплывает что-либо из: аутентификация, работа с сессиями, криптография, загрузка файлов, доступ к БД, IPC/RPC, сериализация, разбор XML/YAML/JSON, исполнение команд, рендер шаблонов, межсервисные вызовы
- Задача касается infrastructure-as-code, контейнеров, CI/CD или конфигурации кластера
- В области задачи появляются секреты, учётные данные, токены или ключи
- Явно запрошено ревью кода

Если ничего из вышеперечисленного не применимо и правка косметическая (например, форматирование, переименование приватной переменной, подкрутка строки лога без пользовательских данных), скилл можно не загружать — но при сомнении загружайте.

---

## Как пользоваться скиллом

Набор правил разбит на два уровня.

### Уровень A — применять всегда

Три правила безусловны. С ними нужно свериться на **каждой** операции с кодом, независимо от языка и предметной области:

- [`always-no-hardcoded-secrets.md`](rules/always-no-hardcoded-secrets.md) — секреты, ключи, токены и учётные данные не должны попадать в исходники
- [`always-crypto-algorithms.md`](rules/always-crypto-algorithms.md) — какая криптография разрешена, какая запрещена, позиция по пост-квантовой устойчивости
- [`always-certificate-hygiene.md`](rules/always-certificate-hygiene.md) — инспекция и валидация X.509-сертификатов, встречающихся в коде

### Уровень B — контекстные правила (язык × домен)

Оставшиеся 20 правил загружаются исходя из языка редактируемого файла и предметной области безопасности, которой касается задача. Пользуйтесь таблицей:

| Язык | Какие правила загружать |
|------|-------------------------|
| **apex** | input-validation-injection |
| **c** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, database-data-storage, file-upload-handling, framework-language-guides, infrastructure-as-code, input-validation-injection, logging-monitoring, c-cpp-memory-safety, sessions-cookies, xml-serialization-hardening |
| **cpp** | c-cpp-memory-safety |
| **d** | infrastructure-as-code |
| **docker** | ci-cd-containers, supply-chain-dependencies |
| **go** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, input-validation-injection, mcp-security, sessions-cookies, xml-serialization-hardening |
| **html** | client-web-browser, input-validation-injection, sessions-cookies |
| **java** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, framework-language-guides, input-validation-injection, mcp-security, mobile-app-security, sessions-cookies, xml-serialization-hardening |
| **javascript** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, kubernetes-hardening, database-data-storage, ci-cd-containers, file-upload-handling, framework-language-guides, infrastructure-as-code, input-validation-injection, logging-monitoring, mcp-security, mobile-app-security, privacy-data-protection, sessions-cookies, supply-chain-dependencies |
| **kotlin** | additional-cryptography, authentication-mfa, framework-language-guides, mobile-app-security |
| **matlab** | additional-cryptography, authentication-mfa, mobile-app-security, privacy-data-protection |
| **perl** | mobile-app-security |
| **php** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, file-upload-handling, framework-language-guides, input-validation-injection, sessions-cookies, xml-serialization-hardening |
| **powershell** | ci-cd-containers, infrastructure-as-code, input-validation-injection |
| **python** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, framework-language-guides, input-validation-injection, mcp-security, sessions-cookies, xml-serialization-hardening |
| **ruby** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, file-upload-handling, framework-language-guides, infrastructure-as-code, input-validation-injection, sessions-cookies, xml-serialization-hardening |
| **rust** | mcp-security |
| **shell** | ci-cd-containers, infrastructure-as-code, input-validation-injection |
| **sql** | database-data-storage, input-validation-injection |
| **swift** | additional-cryptography, authentication-mfa, mobile-app-security |
| **typescript** | additional-cryptography, api-web-services, authentication-mfa, authorization-access-control, client-web-browser, file-upload-handling, framework-language-guides, input-validation-injection, mcp-security, sessions-cookies |
| **vlang** | client-web-browser |
| **xml** | additional-cryptography, api-web-services, ci-cd-containers, framework-language-guides, mobile-app-security, xml-serialization-hardening |
| **yaml** | additional-cryptography, api-web-services, authorization-access-control, kubernetes-hardening, database-data-storage, ci-cd-containers, framework-language-guides, infrastructure-as-code, logging-monitoring, privacy-data-protection, supply-chain-dependencies |

Имена правил выше — это файлы в каталоге `rules/`, в реальной ФС они имеют префикс `rule-` (например, `rule-input-validation-injection.md`).

Если язык не указан в таблице — опускайтесь к ближайшей парадигме (интерпретируемый веб → javascript; компилируемый системный → c/go; статически типизированный JVM → java) и обязательно применяйте все три правила уровня A.

---

## Порядок действий: до, во время, после

### Перед написанием кода

Задайте три вопроса, строго в этом порядке:

1. **Учётные данные?** Если фича как-либо касается секретов/ключей/токенов, сначала открывайте `always-no-hardcoded-secrets.md` — оно определяет, *где именно* эти данные должны жить.
2. **Язык(и)?** По таблице выше подберите правила уровня B.
3. **Домен(ы) безопасности?** Сопоставьте задачу с доменами (инъекции, auth, криптография, загрузка файлов, парсинг, IaC, …) и загрузите соответствующие правила, даже если таблица уже их неявно покрывает. Подгрузить лишние правила дешевле, чем пропустить чек-лист.

К концу шага 3 у агента должен быть конкретный список файлов-правил, которые нужно держать в рабочем контексте.

### Во время написания

- По умолчанию выбирайте безопасный шаблон, показанный в применимом правиле, а не тот, что пришёл в голову первым.
- Когда безопасный вариант и «чистый» расходятся — берите безопасный и оставляйте однострочный комментарий о мотивации. Будущим ревьюерам (людям или ИИ) важно видеть интенцию.
- Не понижайте молча уровень безопасности только чтобы тест прошёл. Если указание из правила блокирует задачу, останавливайтесь и сигнализируйте об этом.

### После написания

Пройдитесь по чек-листу внутри каждого загруженного правила. По каждому пункту дайте один из трёх ответов:
- **Применено** — коротко укажите где (файл/функция).
- **Не применимо** — с однопредложенной мотивацией.
- **Отложено** — с явной отметкой на фоллоу-ап; не закрывайте задачу как выполненную при отложенном пункте безопасности без согласования с пользователем.

В финальной сводке агент должен назвать, какие правила были применены, и перечислить добавленные функции безопасности (параметризованные запросы, CSRF-токены, хэширование bcrypt и т. п.), чтобы ревьюер мог быстро верифицировать выбор.

---

## Проактивная позиция

Одного избегания уязвимостей мало — агент должен **активно выбирать** безопасные шаблоны, даже если пользователь об этом не просил:

- Параметризованные запросы — значение по умолчанию, а не «добавлено позже».
- Пользовательский ввод валидируется на границе доверия (схема / allow-list / размер / тип), а не принимается как есть.
- Принцип наименьших привилегий предпочтительнее удобства — узкие IAM-роли, токены с ограниченной областью, сервисные учётки под одну задачу.
- Современная аутентифицированная криптография (AES-GCM / ChaCha20-Poly1305 / Ed25519 / X25519) — дефолт; легаси-алгоритмы появляются только при явной причине миграции.
- Эшелонированная защита: одного контроля недостаточно просто потому, что его дублирует другой слой. CSP + экранирование, валидация входа + параметризация, проверки авторизации на шлюзе и в сервисе и т. д.

---

## Индекс правил

Все правила лежат в [`rules/`](rules/). Быстрая навигация:

**Уровень A — применять всегда:**
- [always-no-hardcoded-secrets.md](rules/always-no-hardcoded-secrets.md)
- [always-crypto-algorithms.md](rules/always-crypto-algorithms.md)
- [always-certificate-hygiene.md](rules/always-certificate-hygiene.md)

**Уровень B — контекстные:**
- [rule-additional-cryptography.md](rules/rule-additional-cryptography.md)
- [rule-api-web-services.md](rules/rule-api-web-services.md)
- [rule-authentication-mfa.md](rules/rule-authentication-mfa.md)
- [rule-authorization-access-control.md](rules/rule-authorization-access-control.md)
- [rule-client-web-browser.md](rules/rule-client-web-browser.md)
- [rule-kubernetes-hardening.md](rules/rule-kubernetes-hardening.md)
- [rule-database-data-storage.md](rules/rule-database-data-storage.md)
- [rule-ci-cd-containers.md](rules/rule-ci-cd-containers.md)
- [rule-file-upload-handling.md](rules/rule-file-upload-handling.md)
- [rule-framework-language-guides.md](rules/rule-framework-language-guides.md)
- [rule-infrastructure-as-code.md](rules/rule-infrastructure-as-code.md)
- [rule-input-validation-injection.md](rules/rule-input-validation-injection.md)
- [rule-logging-monitoring.md](rules/rule-logging-monitoring.md)
- [rule-mcp-security.md](rules/rule-mcp-security.md)
- [rule-mobile-app-security.md](rules/rule-mobile-app-security.md)
- [rule-privacy-data-protection.md](rules/rule-privacy-data-protection.md)
- [rule-c-cpp-memory-safety.md](rules/rule-c-cpp-memory-safety.md)
- [rule-sessions-cookies.md](rules/rule-sessions-cookies.md)
- [rule-supply-chain-dependencies.md](rules/rule-supply-chain-dependencies.md)
- [rule-xml-serialization-hardening.md](rules/rule-xml-serialization-hardening.md)