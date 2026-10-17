---
id: decision-015
title: "ADR-0015 Namespace-as-a-Service (NaaS)"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/artifacts/04-adr-0015-namespace-as-a-service.md`

# Namespace-as-a-Service (NaaS)

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash's permission model (§ 5B) is **admin-driven**: an admin binds a user
to a role template in a namespace. For a platform team, that means every
"give me a namespace" is an ops ticket. OpenUnison's NaaS portal makes
namespace onboarding **self-service**: a user requests, an approver approves,
and the namespace is provisioned automatically. We want the same, reusing the
existing role-template system rather than introducing a parallel RBAC path.

The constraint: provisioning must stay idempotent and drift-checked (the
existing `rbac_drift_check` task depends on `kubedash.io/template` labels),
and optional time-boxed grants must be reversible without a human.

#### Decision Drivers

- Onboarding must be **self-service** (not every grant an ops ticket).
- It must stay **controlled and auditable** (an approval step, a record of
  who approved what and why).
- It must **reuse the existing role-template service** (no fork of the RBAC
  path), so drift detection keeps working.
- Optional **time-boxed grants** must auto-revoke without a human.
- **Privileged** (`cluster-admin`-scoped) access must *not* be self-service —
  it stays with PAM (ADR-0016).

#### Considered Options

- Keep admin-only binding (status quo).
- Self-service with no approval.
- Request → approve → provision, reusing the role-template service.

#### Decision Outcome

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

##### Consequences

- Good, because onboarding is self-service and the RBAC objects carry the
  same `kubedash.io/template` labels, so the existing drift check covers NaaS
  grants for free.
- Good, because `cluster-admin`-scoped templates are excluded from NaaS
  requests — privileged access still goes through PAM (ADR-0016), keeping the
  two concerns separated.
- Bad, because it introduces an approval workflow (notifications, approver
  model, a pending queue) that the current codebase does not have.
- Bad, because deleting a *new* namespace on grant expiry is a data-safety
  risk; the default is to keep it (`deleteOnExpire: false`).

##### Confirmation

- A request → approve flow creates the namespace + Role + RoleBinding (labelled
  `kubedash.io/template`) and a `cluster_bindings` row.
- A TTL'd grant is auto-revoked by `access_expiry` at `expires_at` (binding
  removed, request marked `expired`).
- A `cluster-admin`-scoped template is rejected on a NaaS request (must go via
  PAM).
- The provisioned objects are picked up by `rbac_drift_check`.

#### Pros and Cons of the Options

##### Admin-only binding (status quo)

An admin binds every user by hand.

- Good, because it is simple and already exists; full control.
- Neutral, because it reuses the existing binding model.
- Bad, because every onboarding is an ops ticket; does not scale a platform
  team.

##### Self-service with no approval

Users create namespaces/bindings directly.

- Good, because fastest; zero friction.
- Neutral, because it reuses the role-template service.
- Bad, because uncontrolled namespace/role creation; poor fit for regulated
  environments; no audit trail of approval.

##### Request → approve → provision (chosen)

A user requests, an approver approves, KubeDash provisions via the existing
role-template service.

- Good, because self-service yet controlled and auditable; reuses the RBAC
  path so drift detection works; TTL'd grants auto-revoke.
- Good, because privileged access is kept out (deferred to PAM).
- Bad, because it adds an approval workflow (notifications, approver model,
  pending queue) the codebase lacks.
- Bad, because auto-deleting new namespaces on expiry is a data-safety risk
  (defaulted to keep).

#### More Information

- OpenUnison's NaaS portal is the reference pattern.
- Related: ADR-0013 (role templates + bindings), ADR-0016 (PAM for privileged
  access), ADR-0017 (the JIT pipeline runs on NaaS approval).
