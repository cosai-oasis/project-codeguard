---
description: Kubernetes cluster and workload hardening — RBAC, admission policy, network policies, secrets, supply chain
languages:
  - javascript
  - yaml
alwaysApply: false
rule_id: rule-kubernetes-hardening
---

# Kubernetes Hardening

A Kubernetes cluster is, in practice, a small data center. The same defense-in-depth approach applies — identity, policy, network segmentation, secrets handling, and supply chain integrity — adapted to cluster primitives.

## Identity and RBAC

- One service account per workload. Do not reuse the default service account; disable `automountServiceAccountToken` where the pod does not need API access.
- RBAC roles scoped to the minimum API groups, resources, and verbs required. A `list pods` that the app never calls is also an attacker's `list pods`.
- Separate namespaces per team, per application, or per environment. Namespaces are not a security boundary by themselves but are the scoping primitive the rest of the controls attach to.
- Humans authenticate via the corporate IdP (OIDC), not via static `kubeconfig` credentials that persist on laptops.

## Admission policy

Use an admission controller (OPA Gatekeeper, Kyverno) to enforce policies the developer cannot bypass in a manifest:

- Reject images pulled from outside allowed registries.
- Reject privileged pods, host-network, host-path, host-PID, and CAP_SYS_ADMIN unless explicitly allowed via an exception.
- Require `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, and the dropping of all Linux capabilities (`drop: [ALL]`).
- Require a `NetworkPolicy` to exist in any namespace that runs workloads.
- Require declared labels / annotations for tracking (team, cost center, criticality).
- Block `:latest` image tags; require a digest or an immutable tag.

These policies are also run as CI checks on manifests, not only at admission time — breaking the pipeline is cheaper than breaking at deploy.

## Workload hardening (pod level)

Baseline `securityContext`:

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

Resource requests and limits set for every container. A pod without limits can exhaust the node.

## Networking

- Default-deny network policies in every workload namespace. Explicit allow rules for the traffic each workload actually needs.
- Egress allow-lists — restrict which destinations a workload may reach. This turns a compromised pod from "pivots anywhere" into "can only reach the two services it legitimately talks to".
- Service mesh identity / mTLS where applicable (Istio, Linkerd). Workload identity is cryptographic, not based on IP.
- Do not expose cluster internals (ingress controller admin UI, dashboards, metrics) to the Internet. These belong behind a VPN or a cloud-provider private endpoint.

## Secrets

- Use the KMS provider integration (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault + secrets-csi-driver) so etcd stores ciphertext.
- Never check Secret manifests into git in plaintext. If GitOps is a requirement, use SOPS, Sealed Secrets, or External Secrets.
- Mount secrets at specific paths; do not expose them as environment variables unless the application leaves no other choice (env vars leak into process listings, core dumps, and debugger output).
- Rotate on schedule and on compromise.

## Nodes

- Hardened base OS (CIS benchmark, or a minimal distribution like Talos or Bottlerocket).
- Automatic minor-version patching; coordinated kernel patching.
- Minimal attack surface — no SSH to production nodes; break-glass access via the cloud provider's session manager or equivalent.
- Isolate sensitive workloads with taints, tolerations, and dedicated node pools.

## Supply chain

- Images built in a controlled environment with hermetic dependencies (`rule-supply-chain-dependencies.md`).
- Signed images (Cosign / Sigstore). Admission controller verifies the signature before scheduling.
- SBOM published with the image. Provenance attestation (SLSA level ≥ 2) where the pipeline supports it.

## Incident readiness

- Audit logging enabled on the API server; centralized with appropriate retention.
- Access to etcd restricted to the control plane nodes; etcd encryption at rest enabled.
- Regular restore drills of cluster state and persistent volumes.
- Break-glass roles that require MFA and are time-bound; every use is audited and reviewed.

## Checklist

- Namespaces per tenant / app; default service account unused; RBAC scoped tightly.
- Admission policies enforce image source, non-root, dropped capabilities, read-only root FS, NetworkPolicy presence, required labels.
- Network policies default-deny; egress controlled where appropriate.
- KMS-backed secret encryption; no plaintext Secret manifests committed.
- Audit logging on; etcd encrypted; break-glass roles MFA-protected.

## Verification

- CIS Kubernetes Benchmark scan on every cluster.
- OPA / Kyverno policy unit tests in CI.
- Periodic admission dry-run against the cluster's current manifests.
- Chaos-style tests that a non-root, read-only-root, no-capability pod can still run the workload (it usually can, once the image is right).
