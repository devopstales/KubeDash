---
id: decision-017
title: "ADR-0017 Just-In-Time login provisioning"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/artifacts/04-adr-0017-jit-login-provisioning.md`

# Just-In-Time login provisioning

---
status: "accepted"
date: 2026-10-17
supersedes: none
---

## Context and Problem Statement

KubeDash already auto-creates the `users` row on first OIDC login — the
trivial case of "provision at login". OpenUnison's JIT login workflow
generalises this: at login (or at elevation/NaaS approval) KubeDash runs a
custom, declarative provisioning pipeline (create a namespace, bind a default
role, create a ServiceAccount, copy a Secret, apply a ResourceQuota). We want
that, but with two hard requirements: (1) provisioning must be **declared in
Helm**, not coded per-deployment, and (2) a provisioning failure must **not
block login** — a user whose workspace fails to provision is still a logged-in
user who can see the error.

## Considered Options

- Hardcode per-deployment provisioning in Python. Flexible but not
  declarative; every environment needs a code change or env var.
- A declarative, Helm-declared task pipeline of **builtin** task types, run
  by a `provisioning.py` service. Declarative, versioned in the chart, and the
  builtin set covers the common cases.
- A plugin task API (arbitrary user-supplied handlers). Most flexible, but a
  large new extension surface with its own security review; deferred.

## Decision Outcome

Chosen option: "declarative Helm-declared pipeline of builtin task types",
because it is versioned with the chart, covers the common cases, and keeps the
extension surface closed for now.

`provisioning.tasks` in `values.yaml` declares named tasks with a `trigger`
(`login` | `elevation` | `naas`) and a `type` (builtin: `namespace.ensure`,
`rbac.bind_template`, `serviceaccount.create`, `secret.copy`, `label.apply`,
`annotation.apply`, `quota.apply`, `limitrange.apply`) and `params` with
Jinja2 template variables (`{{ username }}`, `{{ namespace }}`,
`{{ cluster }}`). Tasks run in declared order, are idempotent, and are
individually retried. **Login-time tasks run after the JWT is issued** — a
failure is recorded in `provisioning_tasks` and surfaced in the UI, but the
login succeeds. Elevation/NaaS tasks run inside the approve handler (they must
succeed for access to be granted).

### Consequences

- Good, because provisioning is declarative and versioned in the Helm chart,
  and login availability is decoupled from provisioning correctness.
- Good, because each run is a `provisioning_tasks` row (params + result), so
  the pipeline is auditable and an admin can "Re-run provisioning".
- Bad, because only the builtin task types are available; an arbitrary custom
  task (e.g. a bespoke Vault call) is not expressible until the plugin API
  lands (deferred, § 11).
- Bad, because login-time tasks run synchronously in the OIDC callback, so a
  slow cluster adds latency to login (bounded by per-task timeouts).
