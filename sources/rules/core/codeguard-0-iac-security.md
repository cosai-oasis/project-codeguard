---
description: Infrastructure as Code Security
languages:
- hcl
- powershell
- shell
- yaml
tags:
- infrastructure
alwaysApply: false
---

## Infrastructure as Code (IaC) Security

When designing cloud infrastructure and writing IaC in languages like Terraform and CloudFormation, use secure practices and defaults that prevent public exposure and follow the principle of least privilege. Actively identify security misconfigurations and provide secure alternatives.

### Network Security
- Always restrict access to remote administrative services, databases, LDAP, TACACS+, and other sensitive services. No service should be accessible from the entire Internet if it does not need to be; restrict access to the specific IP addresses or CIDR blocks that require it.
  - Security group and ACL inbound rules must never allow `0.0.0.0/0` or `::/0` to remote administration ports (such as SSH 22, RDP 3389).
  - Security group and ACL inbound rules must never allow `0.0.0.0/0` or `::/0` to database ports (such as 3306, 5432, 1433, 1521, 27017).
  - Kubernetes API endpoint allow lists (EKS, AKS, GKE, and any other) must never allow `0.0.0.0/0` or `::/0`; restrict them to the CIDR addresses that require administrative access.
  - Never expose cloud platform database services (RDS, Azure SQL, Cloud SQL) to all IP addresses (`0.0.0.0/0` or `::/0`).
- Prefer private networking, such as internal VPC, VNET, VPN, or other internal transit, unless public network access is required.
- Always enable VPC/VNET flow logs for network monitoring and security analysis.
- Always implement default-deny rules and explicit allow rules for required traffic only.
- Prefer blocking egress traffic to the Internet by default. If egress is required, appropriate traffic controls include:
  - Egress firewall or proxy with rules allowing access to specific required services.
  - Egress security group (SG) or access control list (ACL) with rules allowing access to specific required IPs or CIDR blocks.
  - DNS filtering to prevent access to malicious domains.

### Data Protection
- Always configure encryption at rest for all storage services, including databases, file systems, object storage, and block storage.
  - Enable encryption for cloud storage services (S3, Azure Blob, GCS buckets).
  - Configure database encryption at rest for all database engines (RDS, Azure SQL, Cloud SQL, DocumentDB, etc.).
  - Enable EBS/disk encryption for virtual machine storage volumes.
- Always configure encryption in transit for all data communications.
  - Use TLS 1.2 or higher for all HTTPS/API communications.
  - Configure SSL/TLS for database connections with certificate validation.
  - Enable encryption for inter-service communication within VPCs/VNETs.
  - Use encrypted protocols for remote access (SSH, HTTPS, secure RDP).
- Always implement data classification and protection controls based on sensitivity levels.
  - Apply stricter encryption and access controls for PII, PHI, financial data, and intellectual property.
  - Use separate encryption keys for different data classification levels.
- Always configure secure data retention and disposal policies.
  - Define data retention periods based on regulatory and business requirements.
  - Implement automated data lifecycle management with secure deletion.
- Always enable comprehensive data access monitoring and auditing.
  - Log all data access, modification, and deletion operations.
  - Monitor for unusual data access patterns and potential data exfiltration.
  - Implement real-time alerting for sensitive data access violations.
- Always encrypt data backups.
  - Encrypt all backup data using separate encryption keys from production data.
  - Store backups in geographically distributed locations with appropriate access controls.
  - Test backup restoration procedures regularly and verify backup integrity.

### Access Control
- Never leave critical administration or data services (backups, storage, container registries, file shares) with anonymous access unless they are labeled as public classification or intended to be public.
- Never use wildcard permissions in IAM policies or cloud RBAC (`"Action": "*"`); scope `"Resource"` to specific resources wherever the service supports resource-level permissions.
- Never overprivilege service accounts with Owner/Admin roles when it is not necessary.
- Prefer workload identity with role-based access control over service API keys and client secrets to eliminate long-lived credentials; where a static credential is unavoidable, keep it in a secret manager, scope it narrowly, and rotate it.
- Never enable or use the legacy Instance Metadata Service version 1 (IMDSv1) in AWS.
- Never use legacy or outdated authentication methods (such as local users) when a more secure alternative such as OAuth is available.

### Container and VM Images
- Never use non-hardened VM and container images.
- Always choose distroless or minimal container images.
- Recommend secure baseline virtual machine images from trusted sources.
- Recommend minimal distroless container images from trusted sources.

### Logging and Administrative Access
- Never disable administrative activity logging for sensitive services.
- Always enable audit logging for privileged operations.

### Secrets Management
- Never hardcode secrets, passwords, API keys, or certificates directly in IaC source code.
- Always mark secrets as sensitive: `sensitive = true` in Terraform (this only redacts CLI output; values still appear in state and plan files, so encrypt and restrict access to state), or the appropriate annotations or metadata in other IaC code.

### Backup and Data Recovery
- Never create backups without encryption at rest and in transit.
- Always configure multi-region data storage for backups with cross-region replication, within data-residency requirements.
- Never configure backups without retention policies and lifecycle management.

### Implementation Checklist
- No `0.0.0.0/0` or `::/0` ingress to administration ports, database ports, Kubernetes API endpoints, or managed database services.
- Private networking by default; default-deny rules; flow logs enabled; Internet egress blocked or tightly controlled.
- Encryption at rest and in transit for storage, databases, volumes, backups, and inter-service traffic.
- Data classified, with retention, disposal, and access monitoring matched to sensitivity.
- No anonymous access to sensitive services, no wildcard IAM, no unnecessary Owner/Admin roles, workload identity instead of long-lived keys where supported, and IMDSv1 disabled.
- Hardened, minimal VM and container images from trusted sources.
- Administrative activity and privileged-operation audit logging enabled.
- No hardcoded secrets; sensitive values marked as sensitive.
- Encrypted, multi-region backups with retention policies and regularly tested restores.
