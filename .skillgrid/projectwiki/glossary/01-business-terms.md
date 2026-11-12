---
type: Reference
title: "Business terms — product vocabulary"
status: stable
---

# Business terms

Product vocabulary, reverse-engineered from the code + ADRs (onboarding,
2026-11-12). One definition per term; keep under ~200 lines or split.

- **Cluster** — a Kubernetes cluster registered in the registry with its
  kubeconfig stored encrypted at rest (AES-256-GCM). The registry is a
  one-way door (ADR-0002). `backend/app/models/cluster.py`.
- **Local cluster** — the synthetic cluster (id 0) backed by the admin
  kubeconfig source (in-cluster or file); visible to `role == "admin"` users
  only (ADR-0021). `backend/app/services/k8s_client.py`.
- **Binding** — the user↔cluster association that gates access. A missing
  binding returns the same 404 `CLUSTER_NOT_FOUND` as a missing cluster
  (`bound_cluster_or_404`). `backend/app/models/binding.py`.
- **Bootstrap admin** — the local admin provisioned from
  `bootstrap_admin_email` + `[security] admin_password` (dev:
  admin@local / admin), idempotent at boot (ADR-0021).
- **Namespace-as-a-Service (NaaS)** — self-service namespace onboarding with
  TTL'd grants (ADR-0015); expiry is the `ns_request_expiry` task.
- **Privileged access (PAM)** — additive elevation over the user's baseline
  RBAC, with auto-revert and a break-glass path (ADR-0016).
- **RBAC template** — a reusable role definition for permission management:
  templates, self-service kubeconfig, drift detection (ADR-0013).
- **Air-gap** — the deployment constraint: zero outbound calls at runtime;
  the bundle must reference no CDN/external URL (ADR-0020, `task fe-check`).
- **One-way door** — a change that is cheap to enter and expensive to leave:
  the cluster registry schema and `KUBEDASH_SECRET_KEY`. ADR-gated +
  migration-gated; escalate before touching.

## Related

- [[glossary/02-technical-terms]] — the machinery terms
- [[decisions/README]] — the decision records these terms come from
