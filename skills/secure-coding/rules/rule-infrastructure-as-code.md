---
description: Secure Infrastructure-as-Code defaults (Terraform, CloudFormation, Pulumi) — network, data, access, backups
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

Cloud misconfigurations are, statistically, more damaging than most application bugs — a publicly readable bucket needs no exploit to dump. When writing or reviewing Terraform, CloudFormation, Pulumi, Bicep, or Crossplane manifests, the defaults must be secure and the risky choices must be explicit.

## Network security

### Remote administration and databases

Do **not** allow `0.0.0.0/0` ingress to any of the following:

- SSH (22), RDP (3389), WinRM (5985, 5986)
- Database ports: MySQL (3306), PostgreSQL (5432), SQL Server (1433), Oracle (1521), MongoDB (27017), Redis (6379), Memcached (11211), Elasticsearch (9200), Cassandra (9042)
- Message queues and caches on their respective ports
- Kubernetes API (`kubectl`) endpoints — EKS, AKS, GKE public endpoints

Restrict these to specific CIDR ranges, and further to a VPN or bastion network when possible.

### Managed database services

RDS, Aurora, Azure SQL, Cloud SQL, DocumentDB, etc. should not have a public endpoint. If one is unavoidable (a specific operational need), restrict the allow-list, require TLS, and audit access.

### Default posture

- Private networking inside a VPC / VNET is the default; public only when the service is meant to be public.
- Default-deny ingress and egress rules; explicit allow rules for required flows.
- VPC / VNET flow logs enabled — you will want them for incident response, and the cost is modest.
- Egress filtered where feasible. A workload that only needs to reach two upstream APIs should only be *able* to reach two upstream APIs. Options:
  - Egress firewall / proxy with explicit rules
  - Security groups / NACLs restricting destination IPs
  - DNS filtering against a known-bad domain list

## Data protection

### Encryption at rest

Everything that stores data carries encryption at rest, using the platform's KMS integration:

- Object storage (S3, Azure Blob, GCS) — bucket policy requires encrypted uploads
- Databases (RDS, Azure SQL, Cloud SQL, DocumentDB, Cosmos DB)
- Block storage (EBS, Azure Disk, GCE persistent disk)
- File storage (EFS, Azure Files, Filestore)
- Message queues and streams (SQS, Kinesis, Pub/Sub) where supported

Use customer-managed keys (CMK) where compliance or policy requires it; otherwise platform-managed keys are acceptable as long as they are not shared across unrelated data.

### Encryption in transit

- TLS 1.2+ for all HTTPS and API traffic (see `rule-additional-cryptography.md`).
- Database connections use TLS with certificate validation.
- Inter-service traffic inside a VPC is still encrypted when the data is sensitive — network location is not a secret.
- Remote access uses encrypted protocols only (SSH, HTTPS, IPsec, WireGuard).

### Classification

Apply stricter controls as sensitivity rises:

| Class | Examples | Controls |
|-------|----------|----------|
| Public | Marketing content | Baseline |
| Internal | Engineering docs | Access control, encryption at rest |
| Confidential | Customer data | Above + per-class keys, narrow IAM, access logging |
| Restricted | PII, PHI, financial, IP | Above + dedicated keys, data-access logging, DLP |

Separate keys per classification — a compromise of the "Internal" key should not expose "Restricted" data.

### Retention and disposal

- Retention periods defined by policy and enforced via lifecycle rules (S3 lifecycle, Azure Blob lifecycle).
- Secure disposal on end-of-life — object-storage versioning makes "delete" interesting; combine `DeleteObject` with `DeleteObjectVersion` when the data must truly be gone.
- Test deletion — cold storage tiers may not honor `DELETE` the way hot tiers do.

### Data access monitoring

- CloudTrail / Cloud Audit Logs / Azure Activity Log — enabled in every account and shipped to a centralized, append-only destination.
- Object-level logging for data buckets.
- Alerts for unusual access patterns (bulk exports, access from unexpected IPs, access to rarely-touched objects).

### Backups

- Encrypted at rest with a key distinct from the live data key.
- Multi-region replication for critical datasets.
- Retention policy with automated lifecycle.
- Restore tested periodically — an untested backup is not a backup.

## Access control

### IAM policies

Never use wildcard permissions in production:

- `"Action": "*"` — forbidden except in explicit break-glass roles
- `"Resource": "*"` — forbidden except for actions that genuinely are account-scoped (`iam:ListUsers`, for example)

A policy tight to the resource ARN and action verbs is the standard. Policy-as-code checks (Access Analyzer, IAM Access Preview, cfn-policy-validator) in the pipeline catch regressions.

### Service identity

- Use workload identity / IAM roles, not long-lived access keys.
- IMDS v2 on AWS — disable IMDSv1 entirely via the launch template.
- Short-lived credentials issued via STS / equivalent; rotate on a schedule.
- Legacy user/password or static API key authentication only when the target service offers no alternative.

### Default exposure

Resources that should never be anonymously readable unless explicitly classified public:

- Storage buckets and blob containers
- Container registries
- Snapshots (EBS, RDS)
- AMIs / VM images
- File shares
- Dashboards / observability stacks

"Bucket must have explicit block-public-access" is a reasonable base policy.

### Legacy authentication

- Kerberos-only / NTLM-only — upgrade to modern SAML / OIDC.
- Basic authentication on cloud services — turn off where the service supports modern auth.

## Images

- Use hardened / minimal images. See `rule-ci-cd-containers.md` and `rule-kubernetes-hardening.md`.
- Prefer distroless for containers, or a vendor-supported minimal base (Chainguard, Wolfi, Bottlerocket).
- For virtual machines, use the cloud vendor's hardened images or an approved golden image from the platform team.

## Logging

- Do not disable administrative activity logging. Every cloud platform has a distinct audit log (CloudTrail, Cloud Audit Log, Azure Activity Log) — keep it on, in every account, in every region.
- Centralize log storage in a dedicated logging account / subscription / project, with its own IAM; the account that *produces* the logs must not be able to modify them.
- Retention aligned with compliance requirements; never shorter than the time it takes to detect a compromise.

## Secrets in IaC

- Never hardcode secrets in a Terraform file, a CloudFormation template, a Helm values file, or anything else checked into source.
- Terraform: mark sensitive outputs and variables `sensitive = true`. This does not encrypt them in the state file — it only hides them from console output. Use a remote backend with encryption and restricted access.
- CloudFormation: use `NoEcho: true` on parameters carrying secrets; pull the actual value from Secrets Manager or Parameter Store via dynamic references.
- Keep `terraform.tfstate` out of git; use a secure backend (S3 + DynamoDB lock, Terraform Cloud, Azure Storage + blob lease).

## Backups and recovery

- Every critical resource has a backup plan defined in code.
- Encryption at rest and in transit.
- Cross-region replication for resilience.
- Lifecycle policy that ages backups out.
- Regular restore drills into an isolated account, not production.

## Implementation summary

When writing IaC, ask:

1. Is anything reachable from `0.0.0.0/0` that shouldn't be?
2. Is data at rest encrypted? In transit?
3. Are IAM statements scoped to actions and resources, with no wildcards?
4. Are the defaults private (bucket, snapshot, registry)?
5. Is workload identity used, or are there static credentials?
6. Is audit logging enabled and pointed somewhere safe?
7. Are secrets referenced via dynamic lookups rather than literal values?
8. Are backups encrypted, replicated, and retention-bounded?

If any answer is "no," that is the thing to fix before the plan is applied.
