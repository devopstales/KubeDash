# KubeDash User Management — Design Briefing (requirements & intent)

> **STATUS:** `draft` (2026-10-19)

> **Role:** this is the *what* — the validated design/spec: problem, intent,
> requirements, success criteria. The companion `blueprint.md` is the *how*
> (implementation plan). Do not rename.

## Problem / Intent

The base structure shipped the user-management surface as **ADR-pointing 501
stubs**: `app/api/admin.py` (users/clusters), `app/api/permissions.py`
(bind/templates), `app/api/kubeconfig.py` (self-service download), and
`app/services/permission.py` (bind/unbind/kubeconfig generation) all raise
`NOT_IMPLEMENTED`. The locked decisions that define what they must become are
in force:

- **ADR-0013** (permission management): role templates live in **Postgres**
  (not ClusterRoles), bind/unbind is **idempotent** Role/RoleBinding apply in
  the cluster with `kubedash.io/*` labels, the **kubeconfig is self-service,
  multi-cluster, and exec-plugin based** (no embedded token).
- **ADR-0011** (kubectl credential plugin): the downloaded kubeconfig's
  `users[]` entry must `exec` the `kubedash get-token` plugin with
  `--server=<kubedash-url>` — the token is always fresh (PKCE + keyring), so
  nothing secret ever sits in the YAML.
- **ADR-0004** (RBAC proxy via SubjectAccessReview): effective-permission
  reads go through SAR, not a local role map.
- **ADR-0021** (local admin auth): users are SSO-upserted rows plus the
  bootstrap `local:` admin; `users.role` (`user`|`admin`) already exists.

The consequence: an admin cannot manage *who can do what* on *which cluster/
namespace*, and an authenticated user with bindings cannot get a
ready-to-use kubeconfig. This change implements **the API side and the UI
side** of that surface — both are one feature end-to-end and are planned
together here.

This briefing covers the **core permission-management loop**: user admin,
template admin, bind/unbind, and self-service kubeconfig. It is the ADR-0013
core; the drift-detection RQ task, NaaS (5C), PAM (5D), JIT (5E), SCIM (5F),
and the aggregated API (5A) remain their own changes.

## Purpose & Success Criteria

- **Purpose:** give cluster admins a UI + API to (a) see all users, (b) bind
  an RBAC role template to a user on a cluster/namespace (or cluster scope),
  and (c) manage the templates; and give every authenticated user a
  **Download kubeconfig** button that yields a multi-cluster YAML that works
  with the `kubedash` credential plugin out of the box.
- **Success criteria:**
  - `GET /api/v1/admin/users` lists users (sub, email, display name, groups,
    role, status, cluster count, last login); non-admin callers get
    `403 RBAC_DENIED`; the bootstrap admin and any `role=admin` row pass.
  - `PATCH /api/v1/admin/users/<id>` changes `role` and/or `status`; each
    change lands in `audit_log` with actor + target; the bootstrap
    (`local:`) admin cannot be demoted or disabled.
  - Templates: `GET/POST /api/v1/admin/permissions/templates`,
    `GET/PUT/DELETE .../templates/<name>`. The four built-ins (`viewer`,
    `developer`, `admin`, `cluster-admin`) are seeded by migration; deleting
    a built-in returns `409` (new stable code `BUILTIN_TEMPLATE_PROTECTED`).
  - `POST /api/v1/admin/permissions/bind` applies a template to
    user × cluster × namespace (or cluster scope): creates/patches the
    `Role` + `RoleBinding` in the cluster with `kubedash.io/template` and
    `kubedash.io/user` labels, records `cluster_bindings`, and audits.
    **Idempotent:** re-binding the same triple is a no-op (HTTP 200, no
    duplicate objects, no new audit row).
  - `DELETE /api/v1/admin/permissions/bind` removes the binding: the
    `RoleBinding` is deleted; the `Role` is deleted **only when no other
    binding references it** (role GC); the `cluster_bindings` row is
    removed; the action is audited.
  - `GET /api/v1/permissions/my-access` returns the **caller's** bindings
    (cluster name, namespace, template, created at) — no admin needed.
  - `GET /api/v1/kubeconfig` returns the caller's **multi-cluster** YAML:
    one context per bound cluster, `namespace` set to the bound namespace
    (cluster-scoped bindings omit it), a single shared `users[]` entry that
    `exec`s `kubectl kubedash get-token --server=<KUBEDASH_PLUGIN_SERVER>`,
    `certificate-authority-data` from the decrypted registry kubeconfig,
    and `Content-Disposition: attachment; filename="kubedash-kubeconfig.yaml"`.
    **404** (`NO_BINDINGS`, new stable code) when the caller has none.
  - The generated YAML round-trips: `kubectl config view --kubeconfig <file>`
    parses it, and every `cluster.server` matches the registry's
    `api_server` for that cluster.
  - Frontend: `/permissions` (all users) shows My Access + Download
    kubeconfig; `/admin/permissions` (admin-gated) shows Users / User Detail
    (Bind/Unbind modal) / Templates (rule editor + Role YAML preview) /
    Audit. Error-envelope codes (`RBAC_DENIED`, `CONFLICT`, `NOT_FOUND`)
    render as messages, not console errors. `task fe-check` (no-CDN) stays
    green.
- **Out of scope:**
  - **RBAC drift detection** (`tasks/rbac_drift.py`, 10-min leader-only loop,
    `driftPolicy: enforce|warn`) — tracked separately; the `kubedash.io/*`
    labels it needs land with this change, so the loop can start on any
    existing surface.
  - **NaaS (5C), PAM (5D), JIT (5E), SCIM (5F), aggregated API (5A)** —
    their stub routes stay 501; this change does not touch them.
  - **Effective-permission read** (`rbac.effective_permissions`, SSOUser
    walk, `/auth/me/permissions`) — ADR-0004's read path; a separate change.
  - **CLI changes** — the `kubedash get-token` plugin contract is fixed by
    ADR-0011 and already built; this change only *consumes* it.
  - **User creation/deletion** — users are JIT (SSO upsert) + the bootstrap
    admin (ADR-0021); there is no manual create/delete in this scope.

## Context

- **Fits existing patterns: yes.** Smorest `Api` per domain
  (`app/api/<domain>.py`, ≤ ~300 lines, Pydantic schemas in `schemas/`,
  `apply_auth` on `on_init`, `flask.g.current_user`); pure-Python
  `app/services/` with no Flask imports; `k8s_client.py` K8sClientPool for
  per-cluster calls; `KubeDashHttpError` stable-code envelope;
  frontend view-folder layout + `apiFetch` error envelope + MSW-mocked
  Vitest.
- **In-force decisions constraining this change:**
  - ADR-0013 — the whole shape of the feature (Postgres templates, idempotent
    apply, plugin-based multi-cluster kubeconfig, audit on every change).
  - ADR-0011 — the kubeconfig `users[].exec` entry is the **only** auth
    mechanism in the YAML; the server URL comes from a new setting
    `KUBEDASH_PLUGIN_SERVER` (Helm: `rbac.kubeconfig.pluginServer`), because
    the plugin auto-detects the cluster from `cluster.server` and only needs
    the KubeDash URL to bootstrap.
  - ADR-0002 — cluster kubeconfigs are AES-256-GCM encrypted in the
    registry; the generator decrypts via `k8s_client.decrypt_kubeconfig`
    (`KUBEDASH_SECRET_KEY`) to pull `api_server` + `certificate-authority-data`
    — it never re-encrypts or stores new secrets.
  - ADR-0004 — this change *writes* RBAC (Role/RoleBinding) directly; it does
    not use SAR. SAR stays the read path for a later change.
  - ADR-0008 — bind/unbind are **synchronous HTTP** (an admin waits for the
    cluster call); no RQ task is introduced. The drift loop (out of scope)
    is what runs leader-only.
  - The **error contract is frozen at 12 codes** ("New code = new version"):
    this change adds exactly **two** — `409 BUILTIN_TEMPLATE_PROTECTED` and
    `404 NO_BINDINGS` — and bumps the contract note.
- **Conventions** (per AGENTS.md + base-structure briefing): Python 3.12 +
  `uv` + `ruff` + `mypy --strict` (services are `services/`-pure: no Flask
  imports); TypeScript strict + `pnpm`; Conventional Commits; work on the
  `rebase` branch; backend tests split `unit` (no container) / `integration`
  (kind-gated); frontend tests MSW-mocked (no live backend).

## Approaches Considered

- **Chosen: extend the existing stub surface in place.** The stub files
  (`api/admin.py`, `api/permissions.py`, `api/kubeconfig.py`,
  `services/permission.py`) and the two stub models (`rbac_templates`,
  `audit_log` reconciliation) are explicitly documented as "lands with the
  permission-management change". Implement there rather than adding parallel
  modules keeps one canonical path per concern and the 501 stub surface
  guard (TICKET-06) intact until each route is real.
- **Rejected: new `users` + `permissions` domains split.** Cleaner domain
  boundaries, but `admin.py` already owns `/admin/users` and `permissions.py`
  already owns `/admin/permissions/*`; moving them would touch the OpenAPI
  baseline (`apidocs_paths_baseline.json`) and the file-map guard for no
  user-visible benefit.
- **Chosen: kubeconfig CA data extracted from the decrypted registry
  kubeconfig.** The registry row already carries the full kubeconfig
  (encrypted); parsing it for the server + CA needs no new secret storage and
  stays one-way-door-safe (no new encrypted column).
- **Rejected: add a `ca_data` column to `clusters`.** Duplicates a secret
  that is already stored, requires a second encryption call, and widens the
  one-way-door surface for no gain — the registry kubeconfig is the single
  source of truth (ADR-0002).
- **Chosen: single shared `users[]` entry (`kubedash`) across all
  contexts.** The exec plugin is cluster-agnostic (auto-detect from
  `cluster.server`); one entry keeps the YAML minimal and matches the
  ARCHITECTURE.md §5B sample.
- **Rejected: per-cluster `users[]` entries.** Redundant; would force users
  to manage N entries for one plugin.

## Requirements

1. **R1 — Admin users list + patch.**
   `GET /api/v1/admin/users` returns every user: `sub`, `email`,
   `display_name`, `groups`, `role`, `status`, `cluster_count` (count of
   `cluster_bindings`), `last_login_at`. Auth: JWT (existing `apply_auth`) +
   `role == "admin"` gate → `403 RBAC_DENIED` otherwise.
   `PATCH /api/v1/admin/users/<id>` accepts `{role?, status?}`; validates
   `role ∈ {user, admin}`, `status ∈ {active, disabled}`; writes
   `audit_log` rows (`action=role_change` / `status_change`, actor =
   current user sub, target = user sub). The bootstrap `local:` admin is
   **immutable** for role/status → `409 CONFLICT` (message names the
   restriction). `disabled` users fail JWT acceptance with
   `401 UNAUTHORIZED` (existing `_auth_check` path extended to check
   `status`).
   - **Acceptance:** list returns seeded + SSO users with correct cluster
     count; non-admin gets 403; patch role/status audits; patching the
     bootstrap admin returns 409; a disabled user's next API call is 401.

2. **R2 — RBAC role templates CRUD.**
   `GET /api/v1/admin/permissions/templates` (list, built-in first),
   `POST` (create custom: `name` unique, `description`, `scope ∈
   {namespace, cluster}`, `rules[]` = `[{api_groups, resources, verbs}]`),
   `GET/<name>`, `PUT/<name>` (update a custom template), `DELETE/<name>`
   (custom only). The four built-ins are **seeded by migration** with the
   ARCHITECTURE.md §5B rule sets; `DELETE` on a built-in →
   `409 BUILTIN_TEMPLATE_PROTECTED` (new code). `DELETE` on a custom
   template that is still referenced by a binding → `409 CONFLICT`
   (detail: which bindings reference it). All mutations audit.
   - **Acceptance:** migration seeds 4 built-ins (asserted by a test);
     create/list/get/update/delete round-trip a custom template; built-in
     delete → 409 `BUILTIN_TEMPLATE_PROTECTED`; deleting a referenced custom
     template → 409 with the referencing binding names; invalid `rules`
     shape → 422.

3. **R3 — Bind (template apply).**
   `POST /api/v1/admin/permissions/bind` body
   `{user (email or sub), cluster (name), namespace?, template}`.
   Behavior: resolve user + cluster + template (404 with the stable code for
   each missing piece); **scope guard** — a `cluster`-scoped template must
   omit `namespace` (422), a `namespace`-scoped template must provide it
   (422); then apply in the cluster:
   1. create/patch `Role kubedash-<template>` in `<namespace>` (cluster
      scope: `ClusterRole`, no namespace) with `rules` from the template and
      label `kubedash.io/template=<template>`;
   2. create/patch `RoleBinding kubedash-<user>-<namespace|cluster>`
      (cluster scope: `ClusterRoleBinding`) with `roleRef` + subject
      `kind=User, name=<sub>` and labels `kubedash.io/user` +
      `kubedash.io/template`;
   3. upsert `cluster_bindings` (user, cluster, namespace nullable,
      template name, created_at) — **idempotent**: if the exact triple
      exists, return 200 without re-applying or re-auditing;
   4. audit `action=bind` (actor, target, cluster, namespace, template).
   The apply is synchronous (ADR-0008 note); a cluster error surfaces as
   `502 CLUSTER_UNREACHABLE` (existing code) with the binding **not**
   recorded.
   - **Acceptance:** bind creates the Role + RoleBinding with correct rules
     and labels and records the binding (kind integration tier); re-bind is
     a no-op (200, no new audit row, objects unchanged); scope mismatch →
     422; unknown user/cluster/template → 404; unreachable cluster → 502
     with no binding row.

4. **R4 — Unbind.**
   `DELETE /api/v1/admin/permissions/bind` body `{user, cluster, namespace?}`
   (same triple resolution). Behavior: find the `cluster_bindings` row (404
   `NO_BINDINGS` if absent); delete the `RoleBinding`; **role GC** — if no
   other binding references `kubedash-<template>` in that cluster/namespace,
   delete the `Role`; remove the row; audit `action=unbind`.
   - **Acceptance:** unbind deletes the binding + RoleBinding and the Role
     only when it was the last referrer; a second unbind on the same triple →
     404 `NO_BINDINGS`; GC is verified in the integration tier (bind two
     users on one template, unbind one, Role remains; unbind the second, Role
     goes).

5. **R5 — My access (self-read).**
   `GET /api/v1/permissions/my-access` returns the **caller's** bindings:
   `[{cluster, namespace, template, created_at}]`. Any authenticated user
   (no admin gate). Empty list (not 404) when the caller has none.
   - **Acceptance:** a bound user sees exactly their bindings; an
     unbound user sees `[]`; another user's bindings are never returned.

6. **R6 — Self-service kubeconfig download.**
   `GET /api/v1/kubeconfig` (authenticated, any role): collect the caller's
   bindings, group by cluster, and for each cluster decrypt the registry
   kubeconfig (`k8s_client.decrypt_kubeconfig` + `KUBEDASH_SECRET_KEY`) to
   extract `server` + `certificate-authority-data`; render the YAML per the
   ARCHITECTURE.md §5B shape (one context per cluster, `namespace` from the
   binding when namespaced, one shared `users[]` exec entry referencing
   `KUBEDASH_PLUGIN_SERVER`). Response: `Content-Type: application/yaml`,
   `Content-Disposition: attachment; filename="kubedash-kubeconfig.yaml"`.
   **404 `NO_BINDINGS`** (new code) when the caller has no bindings.
   `KUBEDASH_PLUGIN_SERVER` is a new required-for-this-route setting
   (env `KUBEDASH_PLUGIN_SERVER`, Helm `rbac.kubeconfig.pluginServer`); if
   unset the route returns `500 INTERNAL_ERROR` with a clear message rather
   than embedding an empty URL.
   - **Acceptance:** a user bound to 2 clusters gets a YAML with 2 contexts,
     2 clusters, 1 `users[]` exec entry, correct server + base64 CA per
     cluster, and `namespace` set for namespaced bindings; the file parses
     via `kubectl config view` (integration); a no-binding user gets 404
     `NO_BINDINGS`; the YAML contains **no** `token:`, `tokenFile:`, or
     `oidc-*` keys (plugin-only auth, ADR-0011).

7. **R7 — Audit reconciliation + reads.**
   The `audit_log` table exists (Task 2 migration) but has no model. This
   change imports the `AuditLog` stub into `app/models/__init__.py`,
   reconciles the model with the **existing table** (an Alembic migration
   `inspect`s the live columns and adds any missing ones — no destructive
   change), and gives every R1–R4 mutation an audit row
   (`actor_sub`, `action`, `target`, `cluster`, `namespace`, `template`,
   `at`). `GET /api/v1/admin/audit?actions=bind,unbind,template_*,
   role_change,status_change` (admin-only, paginated) returns the history
   the UI's Audit tab renders.
   - **Acceptance:** each bind/unbind/template/role/status mutation produces
     exactly one audit row with the correct actor + target; the audit
     endpoint filters by action type; the reconciliation migration is a
     no-op on a fresh DB and additive on a dev DB.

8. **R8 — Frontend: My Access + download (all users).**
   New view `src/views/Permissions/` at route `/permissions`: a table of the
   caller's bindings (cluster, namespace, template, created) from R5 and a
   **Download kubeconfig** button that fetches R6 (blob), triggers a
   download named `kubedash-kubeconfig.yaml`, and toasts the error-envelope
   message on 404/500. Empty state (no bindings) shows a hint, not a broken
   table. `apiFetch` gains a blob-capable path (or a thin `downloadFile`
   helper) without breaking the JSON error-envelope contract.
   - **Acceptance:** render + download flow covered by MSW-mocked Vitest
     (no live backend); the download uses the right filename; the empty
     state renders; `task fe-check` passes.

9. **R9 — Frontend: admin permissions view.**
   New route `/admin/permissions` (sidebar entry gated on
   `role == "admin"`; the route itself redirects non-admins to `/`):
   - **Users tab** — DataTables list from R1 (sub, email, role, status,
     cluster count, last login); click → **User Detail**: the user's
     bindings + **Bind** (modal: pick cluster, namespace *hidden for
     cluster-scoped templates*, template) → R3; **Unbind** per row → R4;
     **Download kubeconfig** (as the admin, for that user) → R6 with a
     `?user=<id>` param.
   - **Templates tab** — list from R2; **rule editor** for a custom
     template (add/remove `api_groups` + `resources` + `verbs` rows, scope
     selector); a **Role YAML preview** rendered client-side from the rules;
     create + delete buttons (built-in rows show a lock, delete disabled).
   - **Audit tab** — R7 history table (actor, action, target, cluster,
     namespace, template, at) with an action-type filter.
   Error handling: `RBAC_DENIED` (403), `CONFLICT` (409), `NO_BINDINGS`
   (404), `CLUSTER_UNREACHABLE` (502) all render the envelope `message` in
   a toast/inline; no unhandled console errors.
   - **Acceptance:** MSW-mocked Vitest covers Users list, User Detail
     bind-submit, unbind, template rule editor + preview, 403/409/404 error
     paths; nav + routes updated; `task fe-check` passes; a Playwright e2e
     (kind + Helm) binds a template via the UI and downloads a kubeconfig.

10. **R10 — Docs + contract.**
    Update `.skillgrid/ARCHITECTURE.md` (the stub `app/services/permission.py`
    signature block → the implemented `PermissionService` shape; note the
    two new error codes) and the ADR index note. Add `KUBEDASH_PLUGIN_SERVER`
    to the AGENTS.md config table. Bump the `errors.py` "10 stable codes"
    comment to the new count and list the two additions.
    - **Acceptance:** ARCHITECTURE.md's §5B service block matches the code;
      AGENTS.md lists the new env var; the error-code count comment is
      accurate; `task fe-check` + backend unit suite green.

## Risks & open questions

- **CA extraction robustness:** the registry kubeconfig is an arbitrary
  user-supplied YAML; if it uses `certificate-authority` (file path) instead
  of `certificate-authority-data`, the generator must base64 the file
  contents or fall back to the in-cluster CA. Open: is file-form CA in the
  registry a supported input, or should registration (R3, ADR-0002) normalize
  it to `-data`? Default: support both; document the normalization.
- **`cluster_bindings` shape change:** the model currently is
  (user, cluster, role) with `ALLOWED_ROLES = {viewer, editor, admin}`.
  ADR-0013's binding is (user, cluster, **namespace nullable, template**,
  role-computed). This is a **one-way-door** schema change (migration-gated).
  Open: keep `role` as a denormalized, template-derived column (viewer
  template → viewer, etc.) for the existing R3 gate, or drop it and let
  bindings be template-only? Default: keep `role` derived from the template
  scope so the existing cluster-visibility gate keeps working; record as an
  ADR-0013 addendum if it conflicts.
- **Plugin server URL in air-gap (ADR-0020):** `KUBEDASH_PLUGIN_SERVER` is
  an internal URL; the air-gap check targets the *bundle*, not the
  generated YAML, so this is fine — but the Helm value must default to the
  in-cluster Service DNS so an air-gapped install works without a public
  ingress.
- **Two new stable error codes** touch the frozen v1 contract; confirm the
  contract-bump note lands in the same ticket as the codes (no separate
  versioning task).
