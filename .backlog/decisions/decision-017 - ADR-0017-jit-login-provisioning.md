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

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

KubeDash already auto-creates the `users` row on first OIDC login — the
trivial case of "provision at login". OpenUnison's JIT login workflow
generalises this: at login (or at elevation/NaaS approval) KubeDash runs a
custom, declarative provisioning pipeline (create a namespace, bind a default
role, create a ServiceAccount, copy a Secret, apply a ResourceQuota). We want
that, but with two hard requirements: (1) provisioning must be **declared in
Helm**, not coded per-deployment, and (2) a provisioning failure must **not
block login** — a user whose workspace fails to provision is still a logged-in
user who can see the error.

#### Decision Drivers

- Provisioning must be **declarative** (declared in the Helm chart), versioned
  with the chart, not coded per-deployment.
- A provisioning failure must **not block login** (availability decoupled from
  provisioning correctness).
- Tasks must be **idempotent** and **individually retryable**.
- The pipeline must be **auditable** (what ran, with what params, what result).
- The extension surface must stay **closed** for now (no arbitrary user
  handlers in v1).

#### Considered Options

- Hardcode per-deployment provisioning in Python.
- A declarative, Helm-declared task pipeline of **builtin** task types, run by
  a `provisioning.py` service.
- A plugin task API (arbitrary user-supplied handlers).

#### Decision Outcome

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

##### Consequences

- Good, because provisioning is declarative and versioned in the Helm chart,
  and login availability is decoupled from provisioning correctness.
- Good, because each run is a `provisioning_tasks` row (params + result), so
  the pipeline is auditable and an admin can "Re-run provisioning".
- Bad, because only the builtin task types are available; an arbitrary custom
  task (e.g. a bespoke Vault call) is not expressible until the plugin API
  lands (deferred, § 11).
- Bad, because login-time tasks run synchronously in the OIDC callback, so a
  slow cluster adds latency to login (bounded by per-task timeouts).

##### Confirmation

- A declared `login`-triggered task runs on login *after* the JWT is issued; a
  failure is recorded in `provisioning_tasks` and the login still succeeds.
- Re-running a task is a no-op (idempotency verified by running twice).
- An `elevation`/`naas`-triggered task failure fails the approve (access not
  granted).
- Each run produces a `provisioning_tasks` row with params + result.

#### Pros and Cons of the Options

##### Hardcode per-deployment provisioning in Python

Provisioning logic in code, configured by env per deployment.

- Good, because maximally flexible (any logic).
- Neutral, because no new abstraction.
- Bad, because not declarative; every environment needs a code change or env
  var; hard to version/audit.

##### Declarative Helm-declared builtin pipeline (chosen)

Tasks declared in `values.yaml`, run by a service; builtin types only.

- Good, because declarative + versioned with the chart; login not blocked on
  failure; idempotent + retryable; auditable per run.
- Bad, because limited to the builtin task types (no arbitrary custom task
  until the plugin API).
- Bad, because login-time tasks add synchronous latency (bounded by timeouts).

##### Plugin task API (arbitrary handlers)

User-supplied task handlers (plugins).

- Good, because most flexible (any bespoke action, e.g. a Vault call).
- Neutral, because it generalises the builtin pipeline.
- Bad, because a large new extension surface with its own security review;
  overkill for v1 (deferred to § 11).

#### More Information

- OpenUnison's customizable JIT login workflow is the reference pattern.
- Related: ADR-0015 (NaaS approval triggers the pipeline), ADR-0016 (PAM
  elevation triggers it), ADR-0013 (the `rbac.bind_template` task reuses the
  role-template service).
