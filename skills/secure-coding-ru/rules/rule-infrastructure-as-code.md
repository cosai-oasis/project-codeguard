---
description: Безопасные дефолты Infrastructure-as-Code (Terraform, CloudFormation, Pulumi) — сеть, данные, доступ, бэкапы
languages:
  - c
  - d
  - javascript
  - powershell
  - ruby
  - shell
  - yaml
alwaysApply: false
rule_id: rule-infrastructure-as-code
---

# Infrastructure as Code

Облачные misconfig-и, по статистике, разрушительнее большинства багов приложений — публично читаемому bucket-у не нужен эксплойт, чтобы слиться. При написании или ревью Terraform, CloudFormation, Pulumi, Bicep, Crossplane-манифестов дефолты должны быть безопасными, а рискованные решения — явными.

## Сетевая безопасность

### Удалённое администрирование и БД

**Не** разрешайте ingress `0.0.0.0/0` на:

- SSH (22), RDP (3389), WinRM (5985, 5986)
- Порты БД: MySQL (3306), PostgreSQL (5432), SQL Server (1433), Oracle (1521), MongoDB (27017), Redis (6379), Memcached (11211), Elasticsearch (9200), Cassandra (9042)
- Очереди сообщений и кэши на их портах
- Kubernetes API (`kubectl`) — публичные endpoint-ы EKS, AKS, GKE

Сужайте до конкретных CIDR и дальше до VPN/bastion-сети, где возможно.

### Managed database services

RDS, Aurora, Azure SQL, Cloud SQL, DocumentDB и компания не должны иметь публичного endpoint. Если он неизбежен (конкретная операционная надобность) — сужайте allow-list, требуйте TLS, аудитируйте доступ.

### Дефолтная позиция

- Частная сеть внутри VPC / VNET — дефолт; публичной делайте, только когда сервис по замыслу публичен.
- Default-deny на ingress и egress; явные allow-правила на нужные потоки.
- Flow-логи VPC / VNET включены — они пригодятся для инцидент-реакции, стоимость умеренная.
- Egress фильтруется, где осуществимо. Workload, которому нужны две upstream-API, должен *иметь возможность* ходить только в две upstream-API. Варианты:
  - Egress-firewall / proxy с явными правилами
  - Security-group / NACL, ограничивающие destination-IP
  - DNS-фильтрация по списку known-bad доменов

## Защита данных

### Шифрование at rest

Всё, что хранит данные, несёт шифрование at rest через KMS-интеграцию платформы:

- Object-storage (S3, Azure Blob, GCS) — bucket-policy требует шифрованных загрузок
- БД (RDS, Azure SQL, Cloud SQL, DocumentDB, Cosmos DB)
- Блочное хранилище (EBS, Azure Disk, GCE persistent disk)
- Файловое (EFS, Azure Files, Filestore)
- Очереди и стримы (SQS, Kinesis, Pub/Sub), где поддерживается

Customer-managed keys (CMK) — там, где требует комплаенс или политика; иначе platform-managed ключи допустимы, пока они не шарятся между несвязанными данными.

### Шифрование in transit

- TLS 1.2+ для всего HTTPS- и API-трафика (см. `rule-additional-cryptography.md`).
- DB-подключения через TLS с проверкой сертификата.
- Межсервисный трафик внутри VPC всё равно шифруется, когда данные чувствительные — сетевое расположение не секрет.
- Удалённый доступ — только по шифрованным протоколам (SSH, HTTPS, IPsec, WireGuard).

### Классификация

Контроли усиливаются по росту чувствительности:

| Класс | Примеры | Контроли |
|-------|---------|----------|
| Public | Маркетинг | База |
| Internal | Инжиниринг-доки | Контроль доступа, шифрование at rest |
| Confidential | Пользовательские данные | Выше + ключи на класс, узкие IAM, access-log |
| Restricted | PII, PHI, финансы, IP | Выше + выделенные ключи, data-access log, DLP |

Разделяйте ключи по классификации — компрометация «Internal» ключа не должна открывать «Restricted» данные.

### Retention и уничтожение

- Сроки хранения определены политикой и ставятся через lifecycle-правила (S3 lifecycle, Azure Blob lifecycle).
- Безопасное уничтожение при end-of-life — версионирование object-storage делает «удалить» нетривиальным; комбинируйте `DeleteObject` с `DeleteObjectVersion`, если данные реально должны исчезнуть.
- Тестируйте удаление — cold-tier-ы могут обрабатывать `DELETE` не так, как hot.

### Мониторинг доступа к данным

- CloudTrail / Cloud Audit Logs / Azure Activity Log — во всех аккаунтах, с отгрузкой в централизованное append-only место.
- Object-level-логирование для бакетов с данными.
- Алёрт на нетипичные паттерны доступа (массовый экспорт, доступ с неожиданных IP, обращение к редко трогаемым объектам).

### Бэкапы

- Шифрование at rest ключом, отличным от продового.
- Мультирегиональная репликация для критичных датасетов.
- Политика retention с автоматическим lifecycle.
- Периодический тест восстановления — непротестированный бэкап не бэкап.

## Контроль доступа

### IAM-политики

В продакшене никогда не используйте wildcard-права:

- `"Action": "*"` — запрещено, кроме явных break-glass-ролей
- `"Resource": "*"` — запрещено, кроме действий, действительно scoped на аккаунт (`iam:ListUsers`, например)

Стандарт — политика, узкая по ARN и списку verbs. Policy-as-code-чеки (Access Analyzer, IAM Access Preview, cfn-policy-validator) в пайплайне ловят регрессии.

### Identity сервисов

- Используйте workload identity / IAM-роли, не долгоживущие access-keys.
- IMDSv2 на AWS — IMDSv1 отключать полностью через launch-template.
- Короткоживущие креды через STS / эквивалент; ротация по расписанию.
- Легаси user/password или статический API-key — только когда целевой сервис не предлагает альтернативы.

### Дефолтная доступность

Ресурсы, которые никогда не должны быть анонимно-читаемы, если их явно не классифицировали как публичные:

- Storage-bucket-ы и blob-контейнеры
- Container-registries
- Снапшоты (EBS, RDS)
- AMI / VM-образы
- File-share-ы
- Дашборды / observability-стеки

«Bucket должен явно иметь block-public-access» — разумная базовая политика.

### Легаси-аутентификация

- Только Kerberos / только NTLM — апгрейдим до SAML / OIDC.
- Basic auth на облачных сервисах — отключаем, где сервис поддерживает современные.

## Образы

- Упрочнённые / минимальные образы. См. `rule-ci-cd-containers.md` и `rule-kubernetes-hardening.md`.
- Для контейнеров — distroless или вендор-поддерживаемая минимальная база (Chainguard, Wolfi, Bottlerocket).
- Для ВМ — hardened-образы облачного вендора или approved golden image от платформенной команды.

## Логирование

- Не отключайте логирование административной активности. В каждой облачной платформе есть свой audit-log (CloudTrail, Cloud Audit Log, Azure Activity Log) — держите его включённым во всех аккаунтах, во всех регионах.
- Централизуйте хранение в отдельном logging-аккаунте / подписке / проекте с собственным IAM; аккаунт, который *производит* логи, не должен иметь возможности их изменять.
- Retention согласован с комплаенсом; не короче времени, которое нужно на детекцию компрометации.

## Секреты в IaC

- Никогда не хардкодим секреты в Terraform, CloudFormation, Helm values и любом другом файле под VCS.
- Terraform: помечайте чувствительные output и variable `sensitive = true`. Это не шифрует их в state, только прячет из console-вывода. Используйте remote-backend с шифрованием и ограниченным доступом.
- CloudFormation: `NoEcho: true` на параметрах с секретами; реальное значение тяните из Secrets Manager / Parameter Store через dynamic reference.
- `terraform.tfstate` — вне git; защищённый backend (S3 + DynamoDB-lock, Terraform Cloud, Azure Storage + blob-lease).

## Бэкапы и восстановление

- Каждый критичный ресурс имеет план бэкапа в коде.
- Шифрование at rest и in transit.
- Cross-region репликация для устойчивости.
- Lifecycle-политика, которая старит бэкапы из.
- Регулярные restore-drill-ы в изолированный аккаунт, не в прод.

## Короткое резюме

Когда пишете IaC, спрашивайте:

1. Есть ли что-то, доступное из `0.0.0.0/0`, чему этого не должно быть?
2. Данные at rest зашифрованы? А in transit?
3. IAM-выражения сужены по actions и resources, без wildcard?
4. Дефолты приватные (bucket, снапшот, registry)?
5. Используется workload identity или где-то лежат статические креды?
6. Включён audit-log и указывает в безопасное место?
7. Секреты подтягиваются по dynamic-lookup, а не литералами?
8. Бэкапы шифрованы, реплицированы, с ограниченным retention?

Если на что-то ответ «нет» — это и нужно поправить до применения плана.
