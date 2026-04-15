---
description: Database and data storage security — isolation, TLS, least privilege, credential storage, hardening
languages:
  - c
  - javascript
  - sql
  - yaml
alwaysApply: false
rule_id: rule-database-data-storage
---

# Database & Data Storage

Covers the configuration surface around SQL and NoSQL stores — network placement, transport, authentication, credentials, permissions, hardening, and per-platform gotchas. Query-level defenses (parameterization, SOQL, NoSQL operator injection) live in `rule-input-validation-injection.md`.

## Network placement

- Do not expose the database to the Internet. Bind it to a private VPC / VNET / private subnet.
- Between application and database: place them on different network segments where possible. A DMZ for the app tier and a database tier that only accepts connections from the app tier is the baseline pattern.
- Disable TCP access when the application runs on the same host and a local socket / named pipe works.
- If TCP is required, listen on a specific interface (not `0.0.0.0`) and restrict source addresses with firewall rules / security groups.
- Do not let thick clients (desktop applications, BI tools) connect directly to production. Front with an authenticated service.

## Transport security

- Accept only TLS-encrypted connections. Disable plaintext entirely.
- TLS 1.2 or higher, with modern cipher suites (see `rule-additional-cryptography.md`).
- Clients validate the server certificate — not `sslmode=require` alone (which often only means "use TLS if available"), but `verify-full` or the equivalent that checks hostname and CA.
- Certificates on the database server are signed by an internal CA or a public CA as appropriate; not self-signed with a client override.

All traffic is encrypted, including the initial authentication handshake — not just the post-auth data.

## Authentication

- Authentication is always required, even for local / loopback connections. A misconfigured local service is a privilege-escalation vector.
- Each application or service gets its own database user. Do not share credentials across services.
- Credentials are strong, unique, and rotated — especially on staff offboarding or a suspected compromise.
- Accounts are removed when the application they belong to is retired. An orphan service account is a backdoor.

## Credential storage

Credentials belong in a secret manager (see `always-no-hardcoded-secrets.md`), not in source code.

If a file-based config is unavoidable:

- Store it outside the document root of any web server.
- Set filesystem permissions so only the database client process can read it.
- Never commit it. `.gitignore` the file path *and* verify with a pre-commit hook that scans for known secret shapes.
- Encrypt if the platform supports it (Linux keyring, macOS keychain, Windows DPAPI).

Prefer, in order: **managed identity / workload identity (IMDS, GCP service account, Azure MSI) → secret manager → encrypted config → environment variables → file → literal in code (never).**

## Permission model

- Least privilege at the account level. The app account holds only the rights it actually uses. `SELECT`, `INSERT`, `UPDATE`, `DELETE` on specific tables — not `ALL` on `*`.
- Do not use built-in administrative accounts (`root`, `sa`, `SYS`, `postgres`) for application connections. These accounts exist for administration; their blast radius is total.
- Do not grant the application account administrative rights or database ownership. Object ownership can be used to bypass row-level security and to escalate.
- Restrict account connections to allowed hosts (`CREATE USER ... @'10.0.0.0/24'` in MySQL, `pg_hba.conf` in PostgreSQL).
- Separate environments — dev, staging, production — with distinct accounts, distinct databases, and a hard network boundary. A staging account with production credentials is not separation.
- Use table-, column-, and row-level permissions where the schema allows (`GRANT SELECT (public_columns) ON ...`, `CREATE POLICY ...` in PostgreSQL, VPD in Oracle).

## Configuration hardening

- Keep the database patched. Critical CVEs for DB engines are exploited quickly.
- Run the database service under an unprivileged OS account, not root.
- Remove default accounts, sample databases, and default passwords the engine ships with.
- Put transaction logs on a separate disk from the data files, with appropriate permissions.
- Regular encrypted backups, access-controlled and verified by periodic restore drills.
- Disable stored procedures and engine features you do not use — `xp_cmdshell`, CLR execution, external tables pointing at network resources, etc.
- Enable database activity monitoring where compliance or threat model calls for it. Alert on failed logins, privilege changes, and large exports.

## Platform-specific notes

### SQL Server

- Disable `xp_cmdshell` unless specifically needed (and it almost never is).
- Disable CLR execution unless a specific feature requires it.
- Turn off SQL Browser service.
- Use Windows Authentication or Azure AD for humans; SQL logins only for services.
- Mixed Mode Authentication off unless legitimately required.

### MySQL / MariaDB

- Run `mysql_secure_installation` on any new instance.
- Disable the `FILE` privilege for application users — it allows reading and writing arbitrary files as the MySQL user.
- Disable `LOCAL INFILE` in the client unless needed.
- Review `skip-networking` / `bind-address` for dev instances.

### PostgreSQL

- `pg_hba.conf` restricts host-based auth; default to `scram-sha-256` for password methods, `cert` for client-cert auth.
- `listen_addresses` bound to the private interface only.
- Row-level security policies on tenant-scoped tables.
- Keep `log_statement` tuned to avoid logging parameter values (queries with credentials in parameters).

### MongoDB

- Authentication enabled (`--auth`). The legacy "open to localhost" default has caused many breaches.
- `bindIp` to the private interface.
- Use SCRAM-SHA-256; LDAP or x.509 for enterprise.
- Field-level encryption where the threat model requires.
- Disable unused interfaces (HTTP status, REST).

### Redis

- Authentication enabled (`requirepass` or ACLs).
- Rename / disable dangerous commands (`CONFIG`, `FLUSHALL`, `DEBUG`, `SCRIPT`) on production instances.
- TLS terminated on the Redis side for any cross-host traffic.
- Do not expose `6379` to the public Internet — historically one of the most-scanned ports.

## Summary

Put the database on a private network, force TLS, authenticate every connection, store credentials in a manager, grant the minimum permissions the app needs, harden the engine's default configuration, and monitor what changes. Each layer blocks a different class of attacker — no single layer is enough on its own.
