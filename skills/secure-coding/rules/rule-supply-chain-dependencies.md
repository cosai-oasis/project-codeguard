---
description: Dependency and supply-chain security — pinning, SBOM, provenance, integrity, private registries
languages:
  - docker
  - javascript
  - yaml
alwaysApply: false
rule_id: rule-supply-chain-dependencies
---

# Dependency & Supply Chain Security

Every third-party package runs with the privileges of the process that imports it. A minor version bump that ships malicious code, a typosquat, a compromised maintainer account — each is routine now, not rare. Controls fall into four buckets: **know what you pull, pull only from trusted sources, detect when it changes, and have a plan when it goes wrong.**

## Policy and governance

- Allow-list your registries and scopes. `@my-company/*` from the internal registry only; the public registry only as a named fallback for declared public packages.
- Require lockfiles. Pin versions exactly. For container images, pin by **digest** (`image@sha256:...`), not a tag — tags are mutable.
- Generate an **SBOM** for each application and each image. Store it with the artifact. (SPDX or CycloneDX.)
- Attest build **provenance** — SLSA level ≥ 2 produces a signed statement of what was built from what source.
- Document which dependency versions are acceptable for what kind of change (major bumps through a review, patches automatic).

## Package hygiene

### Applies across ecosystems; uses npm as the concrete example

- Run SCA regularly (`npm audit`, Dependabot, Renovate, Snyk, GitHub Advanced Security). Enforce SLAs per severity — critical fixes within hours, high within a week.
- **Deterministic installs in CI**: `npm ci` not `npm install`. `yarn install --frozen-lockfile`. `pip install --require-hashes`. `cargo install --locked`.
- Install scripts are attack vectors. Where the ecosystem allows, disable them (`npm config set ignore-scripts true`) and re-enable only for the few packages that genuinely need them.
- Scope private registries in `.npmrc` / `pip.conf` / `.cargo/config.toml`. Disable wildcard fallback to the public registry for internal scopes.
- Enable integrity verification. `npm ci` does this via the `integrity` field in the lockfile.
- **Publishing hygiene** — 2FA required on every maintainer account that can publish your organization's packages. Revoke tokens you are not actively using.

## Development practices

- Minimize dependencies. Adding a library is adding an attacker. Standard-library or first-party code is usually the correct answer for trivial utilities.
- Prefer packages with active maintenance and meaningful download counts. A fresh single-maintainer package with a single feature should raise the bar before adoption.
- Watch for **typosquats** and **dependency confusion**:
  - `requests` vs `request` vs `reuqests` — misspell, malicious.
  - A public package with the same name as your internal scope can bypass a misconfigured resolver.
- Monitor for **protestware** — packages whose maintainer inserts disruptive behavior in a later release. Pin and review.
- Hermetic builds — no network during compile and package steps, except against known caches. Anything pulled through the cache is integrity-checked.

## CI/CD integration

See `rule-ci-cd-containers.md`. Relevant to this rule:

- SCA, SAST, and IaC scanners run as gates. Criticals block the merge.
- Artifacts are signed; signatures verified at deploy time. Admission controllers on Kubernetes enforce the policy.
- Dependency-update PRs are tested like any other — do not merge on green lockfile alone.

## Vulnerability management

### Patched CVE

- Test and deploy the update. Document API-breaking changes so consumers know what to expect.
- For a patched transitive dependency, prefer updating the top-level dependency; a pinned transitive override is a maintenance cost.

### Unpatched CVE

- Input validation, safe wrappers, feature flags to disable the vulnerable path.
- Virtual patching at the WAF layer (`rule-ci-cd-containers.md`). Retire the WAF rule after the code is patched.
- Monitor the upstream for a fix; track in an issue.

### Risk acceptance

- Document why acceptance is the right call, with a business justification and a compensating control.
- Escalate to the appropriate authority (security, engineering leadership). An undocumented acceptance is an unfixed vulnerability.

## Incident response

- Rapid rollback paths for each artifact — old image available, old binary available.
- Ability to isolate compromised packages — deny-list in the registry so no build pulls them again.
- Throttled rollout for new versions when confidence is low.
- Stakeholder notification playbook — who tells customers, in what channel, with what SLA.

## Threat intelligence

- Subscribe to advisory feeds for the ecosystems you use (`npm security`, `pypi announce`, `rustsec`, distribution advisories).
- Auto-open tickets on critical CVEs that affect dependencies in your inventory.
- Keep the SBOM queryable — when a new CVE lands, the question "do we use this?" should be a grep, not an audit.

## Implementation checklist

- Lockfiles present and respected in CI (`npm ci`, equivalents elsewhere).
- Integrity checks / hash verification on.
- Private registries scoped; public registry not a wildcard fallback.
- SBOMs generated and stored with artifacts; provenance attested where tooling supports it.
- Signatures verified before deploy; admission controllers enforce.
- Automated dependency updates with tests and review gates.
- SLA for vulnerability remediation by severity; overdue items escalated.
- Rollback and isolation procedures tested, not just written down.
