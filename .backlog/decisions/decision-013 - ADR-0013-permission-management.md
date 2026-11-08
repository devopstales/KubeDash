---
id: decision-013
title: "ADR-0013 Permission management: role templates + self-service kubeconfig + drift detection"
date: '2026-10-17'
status: accepted
---

Source: `.skillgrid/knowledge/decisions/04-adr-0013-permission-management.md`

# Permission management: role templates + self-service kubeconfig + drift detection

---
status: "accepted"
date: 2026-10-17
backfilled: 2026-11-06
supersedes: none
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

K8s RBAC is object-scatter: Roles, RoleBindings, ClusterRoles,
ClusterRoleBindings, edited by hand, drifting by hand. Two OSS tools
solve halves of this: permission-manager (named **role templates**
applied to namespaces) and gangway (self-service kubeconfig for SSO).
The question: how does KubeDash give operators a manageable permission
layer, extended to N clusters + SSO?

#### Decision Drivers

- **Templates live in KubeDash's Postgres, not as ClusterRoles.** A
  template is data (JSONB rules) — versionable, listable, bindable —
  not a cluster object. Applying it creates the real Role +
  RoleBinding in the cluster, labelled `kubedash.io/template`.
- **Multi-cluster + SSO.** Both OSS tools are single-cluster; bindings
  are user × cluster × namespace × template, and the generated
  kubeconfig references the credential plugin (ADR-0011), not embedded
  tokens.
- **Drift must be detectable.** Manual edits to template-managed
  objects diverge from Postgres; a periodic check enforces or warns.

#### Considered Options

- **Hand-managed RBAC (status quo).** Rejected: the problem being solved.
- **Templates only (permission-manager pattern).** Rejected alone: no
  self-service access path for users.
- **Role templates + self-service kubeconfig + drift detection
  (CHOSEN).** The combined layer, extended for multi-cluster + SSO.

#### Decision Outcome

**Chosen option: the combined permission layer.**

- **Role templates** — `rbac_templates` (name, scope
  namespace/cluster, rules JSONB, builtin flag); built-ins: viewer,
  developer, admin, cluster-admin. Bind/unbind via `cluster_bindings`;
  apply creates Role + RoleBinding labelled `kubedash.io/template`.
  Core implemented: templates, bind/unbind, self-service kubeconfig.
- **Self-service kubeconfig** — a generated multi-cluster kubeconfig
  referencing the `kubectl kubedash` plugin (no embedded token),
  downloaded from the UI after login
  (`backend/app/services/kubeconfig_render.py`,
  `backend/app/services/permission.py`).
- **Drift detection** — the `rbac_drift` RQ task (leader, 10 min cadence
  target) compares template-labelled cluster objects against Postgres
  and enforces or warns. **Not in the base change:** as of the
  2026-11-06 backfill `backend/app/tasks/rbac_drift.py` is a stub
  no-op ("stub no-op (base structure)").

##### Consequences

- Good: named, reusable, multi-cluster permissions; users self-serve a
  working kubeconfig; drift is a checkable property.
- Bad: two stores of truth for RBAC (Postgres templates vs. cluster
  objects) — exactly why drift detection exists; template application
  is a cluster write (gated by RBAC + audit).
- Confirmation: `backend/tests/services/test_permission.py`,
  `test_permission_generate_kubeconfig.py`, `test_kubeconfig_render.py`,
  `backend/tests/api/test_permissions.py`.

#### Linking Decisions and Constraints

- ADR-0002 — bindings ride the cluster registry.
- ADR-0004 — template application and reads stay SAR-gated.
- ADR-0011 — the generated kubeconfig references the plugin.
- ADR-0014 — session revocation reaches plugin-derived credentials.
- ADR-0015 / ADR-0016 — NaaS and PAM build on the binding model.

#### More Information

Backfilled 2026-11-06 from `ARCHITECTURE.md` §12 + §5B; the drift-task
stub state was verified in `backend/app/tasks/rbac_drift.py` on
2026-11-06.
