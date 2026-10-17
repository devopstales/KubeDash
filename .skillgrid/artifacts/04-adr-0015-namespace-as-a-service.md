# Namespace-as-a-Service (NaaS)

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

KubeDash's permission model (§ 5B) is **admin-driven**: an admin binds a user
to a role template in a namespace. For a platform team, that means every
"give me a namespace" is an ops ticket. OpenUnison's NaaS portal makes
namespace onboarding **self-service**: a user requests, an approver approves,
and the namespace is provisioned automatically. We want the same, reusing the
existing role-template system rather than introducing a parallel RBAC path.

The constraint: provisioning must stay idempotent and drift-checked (the
existing `rbac_drift_check` task depends on `kubedash.io/template` labels),
and optional time-boxed grants must be reversible without a human.

## Considered Options

- Keep admin-only binding (status quo). Simple, but every onboarding is a
  ticket; does not scale a platform team.
- Self-service with no approval. Fast, but uncontrolled namespace/role
  creation; bad for regulated environments.
- Request → approve → provision, reusing the role-template service.
  Controlled, auditable, and reuses existing code.

## Decision Outcome

Chosen option: "request → approve → provision, reusing the role-template
service", because it is self-service yet controlled, auditable, and does not
fork the RBAC path.

A user `POST /api/v1/namespaces/requests` (cluster, namespace existing or
new, template, reason, optional TTL). A row is created in
`namespace_requests` (status=pending). An approver (a user in
`naas.approverGroups` or a `cluster-admin`; not the requester) approves via
`POST .../approve`, which: creates the namespace if new (labelled
`kubedash.io/naas=true`), applies the role template (the § 5B service,
labelling the RBAC objects `kubedash.io/template`), runs the JIT provisioning
pipeline (§ 5E), records a `cluster_bindings` row, and — if a TTL was
requested — sets `expires_at`. Optional TTL'd grants are auto-revoked by the
`access_expiry` RQ task (leader-only, 1 min).

### Consequences

- Good, because onboarding is self-service and the RBAC objects carry the
  same `kubedash.io/template` labels, so the existing drift check covers NaaS
  grants for free.
- Good, because `cluster-admin`-scoped templates are excluded from NaaS
  requests — privileged access still goes through PAM (§ 5D), keeping the two
  concerns separated.
- Bad, because it introduces an approval workflow (notifications, approver
  model, a pending queue) that the current codebase does not have.
- Bad, because deleting a *new* namespace on grant expiry is a data-safety
  risk; the default is to keep it (`deleteOnExpire: false`).
