---
description: CI/CD pipeline security, Docker and container hardening, virtual patching, toolchain flags
languages:
  - docker
  - javascript
  - powershell
  - shell
  - xml
  - yaml
alwaysApply: false
rule_id: rule-ci-cd-containers
---

# DevOps, CI/CD, and Containers

The build and delivery pipeline is a high-value target — compromise it once and every artifact it produces is backdoored. This rule covers pipeline hardening, container hardening, virtual patching as a stopgap, and native-code toolchain flags when C/C++ is in the mix.

## CI/CD pipeline hardening

### Repository

- Protected branches for anything merged to production. Required reviews, required status checks.
- Signed commits, ideally verified at merge time.
- Branch access is least-privilege; only designated service accounts push to release branches.

### Secrets inside the pipeline

- Never hardcode in workflow files. Pull from the secret store at runtime.
- Mask in logs. Most CI systems have a built-in masking mechanism — use it.
- Scope tokens to the minimum the step needs. A CI job that only needs to publish an artifact does not need a read token for the issue tracker.
- Prefer short-lived OIDC-issued tokens (GitHub OIDC → AWS, GitLab → GCP, etc.) over long-lived static secrets.

### Runners

- Ephemeral, isolated runners — each job gets a fresh container or VM, discarded on completion.
- Minimum permissions on the runner's identity. An over-privileged runner is an over-privileged attacker when compromised.
- No shared caches that cross trust boundaries (merged PR runs should not see secrets from an unmerged branch's tests).

### Security gates

In the pipeline, before anything merges or deploys:

- **SAST** — static application security testing on the source
- **SCA** — software composition analysis on the dependency tree
- **IaC scanning** — policy checks on Terraform, CloudFormation, Helm, Kustomize
- **Secrets scanning** — pre-commit and on-PR
- **DAST** — dynamic testing against staging
- **Container scanning** — on image build and on admission

Configure severity thresholds so critical findings block merge. Overrides require documented justification and a compensating control.

### Dependencies

- Lockfiles checked in and verified by the pipeline.
- Integrity checks (`npm ci` respects `package-lock.json`; `pip` can use `--require-hashes`).
- Private registries for internal packages; avoid wildcard public registries.
- Pin base images and other transitive dependencies by digest where the tooling supports it.

### Signing and provenance

- Sign commits, sign container images, sign release artifacts.
- Verify signatures on the deploy side — not "we sign things" but "we refuse to deploy unsigned things".
- Adopt SLSA-style provenance: the build system emits an attestation describing what was built, from what source, with what tooling.

## Docker and container hardening

### User and privileges

- Do not run as root. Create a non-root user in the Dockerfile and `USER` down to it.
- Never run with `--privileged`.
- Drop all Linux capabilities and re-add only what is necessary: `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` (and ideally run on a port above 1024 so even that is unnecessary).
- Set `--security-opt=no-new-privileges` to block `setuid` escalation.

### Daemon socket

Never mount `/var/run/docker.sock` into a container. It is a full privilege escalation to the host. The same applies to host-path mounts of the cgroup hierarchy, Kubernetes sockets, or anything that lets a process out of the container.

Do not expose the Docker daemon over TCP without mTLS. `-H tcp://0.0.0.0:...` with no TLS is a one-step takeover.

### Filesystem and networking

- Root filesystem read-only (`--read-only`); temporary write space via `tmpfs` mounts where needed.
- CPU and memory limits set on every container — an unbounded container can starve the host.
- Avoid host networking. Use user-defined bridges; expose only the ports the service actually needs.

### Images

- Minimal base: `distroless`, `alpine`, or a scratch image when it suffices.
- Pin by digest. Tag-based references (`node:20`) let a later push change what you run.
- Multi-stage builds: compile in a larger image, copy the artifact into a minimal runtime image. Compilers, shells, and package managers stay out of the final image.
- `HEALTHCHECK` set (or equivalent via the orchestrator).
- `.dockerignore` excludes git history, IDE metadata, cache directories, environment files.

### Secrets inside images

Do not bake secrets into image layers — they persist forever in the history, even when a later layer deletes them. Use BuildKit secrets (`--mount=type=secret`) at build time, and the orchestrator's secret mechanism at runtime.

### Scanning

- Scan every image on build (in CI).
- Scan again at admission (cluster side), because what was safe yesterday may have a CVE today.
- Block deploys on high-severity findings unless explicitly waived with a ticket.

## Node.js in containers

Specific patterns worth calling out:

```dockerfile
FROM node:20-alpine@sha256:...   # pinned by digest
WORKDIR /app

# Dependencies first — better cache
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --chown=node:node . .

ENV NODE_ENV=production
USER node

# Proper init and signal forwarding
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]
```

- `npm ci`, not `npm install` — deterministic.
- `--omit=dev` — dev dependencies out of the runtime image.
- `NODE_ENV=production` — many libraries key off this.
- Run as the `node` user, not root.
- Init process that forwards signals cleanly for graceful shutdown.

## Virtual patching

A virtual patch is a WAF / IPS rule that blocks exploitation of a known vulnerability while the real fix is in progress. It is a stopgap, not a fix.

- Keep the WAF deployment ready before you need it — no scrambling during an incident.
- Prefer positive (allow-list) rules for accuracy.
- Deploy in **log-only** first; observe; then switch to enforcing.
- Track each virtual patch with a link to the underlying CVE or bug ticket. Retire the patch once the code is fixed and deployed — stale virtual patches drift and produce false positives.

## C / C++ toolchain hardening

When building native code, enable the compiler-level mitigations. These are nearly free and cover classes of bugs that remain easy to introduce:

### Compiler flags

- `-Wall -Wextra -Wconversion` — warnings for common mistakes.
- `-fstack-protector-all` or at least `-fstack-protector-strong` — stack canaries.
- `-fPIE -pie` — Position-Independent Executables for ASLR.
- `-D_FORTIFY_SOURCE=2` (or `=3` on recent glibc) — compile-time + runtime bounds checks on a set of library functions.
- `-fsanitize=cfi` with LTO — Control Flow Integrity, to catch indirect-call hijacks.

### Linker flags

- `-Wl,-z,relro -Wl,-z,now` — RELRO/now, so the GOT is read-only after startup.
- `-Wl,-z,noexecstack` — non-executable stack.
- NX / DEP and ASLR enabled at the OS level.

### Debug vs release

- Sanitizers (`-fsanitize=address,undefined`) on in debug builds; off in release.
- Hardening flags on in release; assertions on in debug only.
- CI step with `checksec` that fails the build if a release binary is missing the expected protections.

## Implementation checklist

- Secrets are fetched from a vault at runtime; never hardcoded in pipeline definitions.
- Runners are ephemeral; scoped tokens; short-lived OIDC preferred.
- Security scans (SAST, SCA, DAST, IaC, container, secrets) gate merges; criticals block.
- Artifacts and commits are signed; signatures verified before deploy; provenance recorded.
- Containers run non-root, read-only FS, dropped capabilities, resource limits. No daemon socket mounts.
- Images minimal, pinned by digest, scanned at build and admission, with healthchecks.
- Node.js images use `npm ci`, production env, non-root, proper init.
- Virtual-patching process is defined and rules are retired after code fix.
- Native builds enable the documented hardening flags and verify them in CI.
