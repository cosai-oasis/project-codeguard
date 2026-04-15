---
description: Упрочнение кластера Kubernetes и workload-ов — RBAC, admission-policy, network-policy, секреты, supply chain
languages:
  - javascript
  - yaml
alwaysApply: false
rule_id: rule-kubernetes-hardening
---

# Упрочнение Kubernetes

Кластер Kubernetes — это, по факту, маленький датацентр. Подход defense-in-depth тот же — identity, политики, сегментация сети, работа с секретами, целостность supply chain — адаптированный к примитивам кластера.

## Identity и RBAC

- Один service account на workload. Не переиспользуйте default-service-account; выключайте `automountServiceAccountToken` там, где подe не нужен API-доступ.
- RBAC-роли сужены до минимума API-групп, ресурсов и verbs. Не нужный приложению `list pods` — это и `list pods` для атакующего.
- Отдельные namespace на команду, приложение или окружение. Namespace сам по себе не граница безопасности, но это примитив, к которому крепятся остальные контроли.
- Люди аутентифицируются через корпоративный IdP (OIDC), не через статические `kubeconfig`-креды, живущие на ноутбуках.

## Admission-политики

Используйте admission-контроллер (OPA Gatekeeper, Kyverno), чтобы выставить политики, которые разработчик не обойдёт манифестом:

- Отклоняйте образы из registry вне allow-list.
- Отклоняйте privileged-поды, host-network, host-path, host-PID и CAP_SYS_ADMIN, если нет явного исключения.
- Требуйте `runAsNonRoot: true`, `readOnlyRootFilesystem: true` и сброс всех Linux-capabilities (`drop: [ALL]`).
- Требуйте наличия `NetworkPolicy` в любом namespace с workload-ами.
- Требуйте заявленные label/annotation для трекинга (команда, cost-center, critcalness).
- Блокируйте теги образов `:latest`; требуйте digest или неизменяемый тег.

Эти же политики прогоняются как CI-чеки на манифестах, не только на admission — сломать пайплайн дешевле, чем сломать деплой.

## Упрочнение workload-а (уровень пода)

Базовый `securityContext`:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

Ресурс-requests и limits заданы на каждом контейнере. Под без лимитов может сожрать узел.

## Сеть

- В каждом workload-namespace — default-deny NetworkPolicy. Явные allow-правила на трафик, реально нужный workload-у.
- Egress allow-list — ограничивайте, куда workload может обращаться. Это превращает скомпрометированный под из «ходит куда угодно» в «ходит только в два сервиса, с которыми он должен говорить».
- Service-mesh-identity / mTLS где применимо (Istio, Linkerd). Идентичность workload-а — криптографическая, а не по IP.
- Не выставляйте внутренности кластера (админку ingress-контроллера, дашборды, метрики) в Интернет. Это живёт за VPN или private-endpoint облачного провайдера.

## Секреты

- Используйте KMS-интеграцию провайдера (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault + secrets-csi-driver), чтобы в etcd лежал шифртекст.
- Никогда не коммитьте манифесты Secret в git в открытом виде. Если GitOps обязателен — SOPS, Sealed Secrets или External Secrets.
- Монтируйте секреты на конкретные пути; не прокидывайте их через env, если приложение не оставляет выбора (env-vars утекают в списки процессов, core-dump-ы, вывод отладчиков).
- Ротируйте по расписанию и по компрометации.

## Узлы

- Упрочнённая базовая ОС (CIS benchmark или минималистичный дистрибутив — Talos, Bottlerocket).
- Автоматический патчинг минорных версий; координированный патчинг ядра.
- Минимальная поверхность атаки — никаких SSH на продовые узлы; break-glass через session-manager облачного провайдера.
- Чувствительные workload-ы изолируйте taint/toleration и отдельными node-pool-ами.

## Supply chain

- Образы собираются в контролируемой среде с герметичными зависимостями (`rule-supply-chain-dependencies.md`).
- Подписанные образы (Cosign / Sigstore). Admission-контроллер проверяет подпись перед scheduling.
- SBOM публикуется с образом. Provenance-аттестация (SLSA уровень ≥ 2), где пайплайн это поддерживает.

## Готовность к инцидентам

- На API-сервере включён audit-log; централизован с адекватным retention.
- Доступ к etcd ограничен узлами control plane; шифрование etcd at rest включено.
- Регулярные учения по восстановлению состояния кластера и persistent-volume-ов.
- Break-glass роли с MFA и ограничением по времени; каждое использование аудитируется и разбирается.

## Чек-лист

- Namespace-ы по тенантам / приложениям; default SA не используется; RBAC узкий.
- Admission-политики жёстко фиксируют источник образов, non-root, сброс capabilities, read-only root FS, наличие NetworkPolicy, требуемые label.
- NetworkPolicy — default-deny; egress контролируется, где нужно.
- KMS-бэкед шифрование секретов; нет незашифрованных Secret-манифестов в VCS.
- Audit-log включён; etcd зашифрован; break-glass защищён MFA.

## Верификация

- CIS Kubernetes Benchmark-скан на каждом кластере.
- Юнит-тесты OPA / Kyverno-политик в CI.
- Периодический admission dry-run по текущим манифестам кластера.
- Chaos-style тест, что non-root, read-only-root, без capabilities под всё ещё поднимает workload (обычно да, когда образ готов правильно).
