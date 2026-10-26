# Privileged Access Management (PAM)

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash roles are **static**: a binding (user × cluster × namespace ×
template) is permanent until an admin changes it. There is no way to grant a
user *temporary* elevated access (e.g. a developer who needs `developer`
rights on `production` for a 4-hour hotfix) and have it automatically revert.
OpenUnison's PAM provides exactly this: a time-boxed, approved elevation.

The constraint that shaped the decision: reverting an elevation must **never
break the user's baseline access**. A naive "replace the binding with the
elevated one and restore it later" is fragile — if the revert fails, the user
loses even their baseline. We need a revert that is structurally safe.

#### Decision Drivers

- Elevation must be **time-boxed** and **auto-reverted** at TTL (no manual
  cleanup).
- Revert must be **structurally safe**: it can never downgrade a user below
  their baseline, even if the revert partially fails.
- Elevation must be **approved** (not self-granted), with a **break-glass**
  path for when no approver is reachable.
- The exact permission change must be **auditable** (which rules were added).
- It must compose with existing RBAC (K8s grants are a union) and stay
  drift-checkable.

#### Considered Options

- Replace the baseline binding with the elevated one, then restore at TTL.
- Apply the elevation as an **additive** second RoleBinding on top of the
  baseline, and delete only that binding at TTL.
- A separate "elevated" user identity / service account.

#### Decision Outcome

Chosen option: "additive elevation binding on top of the baseline, auto-
reverted at TTL", because reverting can never affect the baseline.

A user requests an elevation (`POST /api/v1/access/requests`: cluster,
namespace, baseline auto-detected, elevation template, bounded TTL, required
reason). On approval KubeDash creates a **second** RoleBinding labelled
`kubedash.io/elevation=<id>` pointing at the elevation Role; the baseline
binding is untouched. Effective permission is the union (standard K8s RBAC).
The `access_expiry` RQ task (leader-only, 1 min) deletes the elevation
binding when `expires_at` passes, marks the request `expired`, and audits the
RBAC delta. A **break-glass** path lets a `cluster-admin` self-approve their
own elevation under a short TTL cap (`pam.breakGlassTTLHours`, default 1 h),
flagged in audit and a dedicated report.

##### Consequences

- Good, because revert is additive-only: it can never downgrade a user below
  their baseline, and concurrent elevations on the same namespace are
  independent bindings.
- Good, because the exact rules added are recorded in `rbac_delta` for audit,
  and elevation objects are labelled for discovery, cleanup, and drift check.
- Bad, because the effective permission is a union, so an elevation can make
  a user's real access exceed the elevation template (baseline + elevation);
  the UI must surface the union, not just the elevation.
- Bad, because it adds a second request/approval lifecycle (parallel to NaaS)
  and a break-glass report to maintain.

##### Confirmation

- An approved elevation creates a second RoleBinding (labelled
  `kubedash.io/elevation=<id>`); the baseline binding is unchanged.
- At TTL, `access_expiry` deletes the elevation binding; the user retains their
  baseline (verified by a `SelfSubjectRulesReview` before/after).
- A break-glass self-approval is capped at `pam.breakGlassTTLHours` and is
  flagged in the audit + break-glass report.
- The `rbac_delta` on the request matches the rules actually granted.

#### Pros and Cons of the Options

##### Replace baseline, restore at TTL

Swap the user's binding for the elevated one, then swap back.

- Good, because the user has exactly the elevated role while elevated (no
  union ambiguity).
- Neutral, because it reuses the binding model.
- Bad, because a failed revert downgrades the user *below* baseline; the
  baseline is held hostage by the elevation.

##### Additive elevation on top of baseline (chosen)

A second RoleBinding, deleted at TTL; baseline untouched.

- Good, because revert is structurally safe (can't touch baseline); concurrent
  elevations are independent; auditable via `rbac_delta`; drift-checkable via
  labels.
- Bad, because effective permission is a union (baseline + elevation), so the
  UI must show the union, not just the elevation.
- Bad, because it adds a second request/approval lifecycle + a break-glass
  report.

##### Separate elevated identity / service account

A distinct "elevated" user or SA for the elevated access.

- Good, because clean isolation of the elevated privileges.
- Neutral, because it is a well-understood pattern.
- Bad, because a second identity is confusing and breaks the single-identity
  model; the user must switch identities to use it.

#### More Information

- OpenUnison's PAM is the reference pattern.
- Related: ADR-0013 (role templates), ADR-0015 (NaaS — the non-privileged
  self-service path), ADR-0014 (elevation uses the same auto-expiry task).
