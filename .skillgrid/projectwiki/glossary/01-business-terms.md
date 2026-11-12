# KubeDash — Business Terms

> Domain / product / workflow vocabulary. **Vocabulary only** — no
> implementation details, no specs, no scratch. One term per entry; sharpen
> fuzzy or overloaded language the moment it is resolved.

| Term | Definition |
|---|---|
| **Cluster** | A registered Kubernetes API server that KubeDash manages. A first-class entity; users are bound to clusters. |
| **Binding** | The user × cluster × namespace × template permission grant. The unit of access. (`cluster_bindings` row.) |
| **Project** | A `projects.kubedash.io/v1` object: a 1:1 read-only projection of a Namespace, filtered by the requesting user's RBAC. `kubectl get projects` lists only namespaces the user can read. |
| **NaaS (Namespace-as-a-Service)** | Self-service namespace onboarding: a user requests access to (or a new) namespace, an approver approves, KubeDash provisions it. Optional TTL'd grants auto-revoke. |
| **Approver** | A user (in a configured approver group, or a `cluster-admin`) who can approve NaaS/PAM requests. Never the requester (except PAM break-glass). |
| **Elevation** | A time-boxed PAM grant that applies an elevated role template *on top of* a user's baseline binding and auto-reverts at TTL. |
| **Baseline** | A user's permanent binding (e.g. `viewer` on production). Elevation is additive; it never modifies the baseline. |
| **Break-glass** | The PAM path where a `cluster-admin` self-approves their own elevation under a short TTL cap, for when no approver is reachable. |
| **Template** | A named, reusable set of RBAC rules (a **role template**), stored in Postgres. Applying it creates the actual Role + RoleBinding in the cluster. |
| **Role template** | A named, reusable set of RBAC rules stored in KubeDash's Postgres (not as a ClusterRole). Built-ins: viewer, developer, admin, cluster-admin. |
| **Requester** | The user who submits an NaaS or PAM request. |
| **SCIM** | System for Cross-domain Identity Management (RFC 7644). The protocol by which an IdP/HR source pushes user/group lifecycle to KubeDash. |
| **Provisioning task** | A named, parameterised, idempotent cluster mutation declared in Helm and run by the JIT engine on a lifecycle trigger (login / elevation / NaaS approval). |
| **Air-gap** | A deployment with zero outbound calls at runtime (internal IdP, cached JWKS, pre-loaded images, offline CLI, vendored Helm). Air-gap ≠ no-IdP. |
