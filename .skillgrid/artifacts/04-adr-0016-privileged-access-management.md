# Privileged Access Management (PAM)

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

KubeDash roles are **static**: a binding (user × cluster × namespace ×
template) is permanent until an admin changes it. There is no way to grant a
user *temporary* elevated access (e.g. a developer who needs `developer`
rights on `production` for a 4-hour hotfix) and have it automatically revert.
OpenUnison's PAM provides exactly this: a time-boxed, approved elevation.

The constraint that shaped the decision: reverting an elevation must **never
break the user's baseline access**. A naive "replace the binding with the
elevated one and restore it later" is fragile — if the revert fails, the user
loses even their baseline. We need a revert that is structurally safe.

## Considered Options

- Replace the baseline binding with the elevated one, then restore at TTL.
  Simple, but a failed revert downgrades the user below baseline.
- Apply the elevation as an **additive** second RoleBinding on top of the
  baseline, and delete only that binding at TTL. Revert is structurally safe:
  the baseline is never touched.
- A separate "elevated" user identity / service account. Clean isolation, but
  a second identity is confusing and breaks the single-identity model.

## Decision Outcome

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

### Consequences

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
