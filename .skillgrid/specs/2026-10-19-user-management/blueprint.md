# KubeDash User Management — Implementation Blueprint (steps, files, verification)

> **Status:** PROPOSED
> **Goal:** Implement the ADR-0013 permission-management core end-to-end — admin users + RBAC role templates + idempotent bind/unbind + self-service multi-cluster kubeconfig download — on the backend (API + service + models + migration) and the frontend (My Access + admin view), so an admin can manage who can do what and any authenticated user can get a working kubeconfig.
> **Architecture:** Existing Smorest domains (`admin`, `permissions`, `kubeconfig`) filled in from 501 stubs; pure-Python `services/permission.py`; `k8s_client` K8sClientPool for Role/RoleBinding apply; `cluster_bindings` extended (one-way-door migration) to carry namespace + template; new `KUBEDASH_PLUGIN_SERVER` setting drives the exec-plugin kubeconfig.
> **Tech Stack:** Python 3.12 + Flask-Smorest + SQLAlchemy 2.0 + Alembic (backend); React 18 + TypeScript + CoreUI + TanStack Query/Vitest/MSW (frontend). Lists use `datatables.net-react` + `datatables.net-bs5` (ADR-0023). **No other new runtime deps** — `pyyaml` is already a direct dependency (`pyproject.toml`) and imported in `k8s_client.py`/`clusters.py`; the kubeconfig emitter reuses it.
> **Spec:** `.skillgrid/specs/2026-10-19-user-management/briefing.md`
> **Build shape:** Tracer thread — bind → my-access → kubeconfig works end-to-end for ONE user on ONE cluster first (Task 3-5), then thickens to templates CRUD, multi-cluster, admin UI, and the frontend.
> **Change classification:** `risky` (one-way-door `cluster_bindings` schema change + 2 new stable error codes + writes RBAC into clusters; L2 + security review)

---

## Hypothesis

**Claim:** The ADR-0013 loop (Postgres templates → idempotent Role/RoleBinding apply → plugin-based multi-cluster kubeconfig) is implementable on the existing stub surface without a new domain, and the downloaded YAML is directly usable by the already-built `kubedash` credential plugin.
**Right condition:** An admin binds template `developer` to a user on a namespace; the user downloads a kubeconfig; `kubectl config view` parses it; `kubectl get pods` (with the plugin) works and the YAML contains **no** embedded token.
**Wrong condition:** The kubeconfig needs an `oidc-*` / `token` field, the plugin can't find the cluster, or a re-bind creates a second RoleBinding.
**Thinnest MVP:** `bind` (one user, one namespace-scoped template, one cluster) + `GET /permissions/my-access` + `GET /kubeconfig` (single context, exec plugin) + a download button. No templates CRUD, no admin UI, no multi-cluster yet.
**Door check:** Task 3 (bind) + Task 5 (kubeconfig) — a real bind produces a RoleBinding in a kind cluster, and the generated kubeconfig's single context `exec`s the plugin with the right `--server`. If the YAML shape or the idempotency is wrong, stop and re-examine before thickening.

---

## In-Force Constraints (must hold)

- **ADR-0013** — templates in Postgres; idempotent apply; `kubedash.io/*` labels; plugin-based multi-cluster kubeconfig; audit on every change.
- **ADR-0011** — kubeconfig `users[]` is an **exec** entry (`kubectl kubedash get-token --server=<KUBEDASH_PLUGIN_SERVER>`); no `token`/`tokenFile`/`oidc-*`.
- **ADR-0002** — registry kubeconfig is AES-256-GCM (`KUBEDASH_SECRET_KEY`); decrypt to read server + CA; do **not** add a `ca_data` column.
- **ADR-0008** — bind/unbind are synchronous HTTP; no RQ task in this change.
- **Error contract** — frozen at 12 codes; add exactly **2**: `409 BUILTIN_TEMPLATE_PROTECTED`, `404 NO_BINDINGS`. Bump the count comment.
- **One-way-door** — `cluster_bindings` schema change is migration-gated.
- **ADR-0023** — every list in this feature is `datatables.net-react` with the Bootstrap 5 skin (`datatables.net-bs5`), wrapped in the CoreUI card. No `datatables.net-dt`, no DataTables Editor, no jQuery.
- **Services purity** — `services/permission.py` has **no Flask imports** (takes db session + client pool as args).

---

## File Structure

### Backend — modify
- `backend/app/core/errors.py` — add `BuiltinTemplateProtectedError` (409, `BUILTIN_TEMPLATE_PROTECTED`) + `NoBindingsError` (404, `NO_BINDINGS`); add both to `CODES`; update the "10 stable codes" → count comment.
- `backend/app/core/config.py` — add `plugin_server` setting (env `KUBEDASH_PLUGIN_SERVER`, optional, default None).
- `backend/app/models/binding.py` — add `namespace` (nullable), `template` (str), `created_at`; derive/keep `role`; update `ALLOWED_ROLES` handling (role becomes template-derived, default `viewer`).
- `backend/app/models/rbac_template.py` — flesh out the stub: `description`, `scope`, `rules` (JSONB), `created_by`, `created_at`, `builtin`; remove `STUB`.
- `backend/app/models/audit.py` — reconcile to the live table columns; remove `STUB`.
- `backend/app/models/__init__.py` — import `RBACTemplate` + `AuditLog` (un-stub them onto `db.metadata`).
- `backend/app/api/admin.py` — `GET /admin/users`, `PATCH /admin/users/<id>` (replace stubs).
- `backend/app/api/permissions.py` — templates CRUD + `POST/DELETE /admin/permissions/bind` + `GET /permissions/my-access`.
- `backend/app/api/kubeconfig.py` — `GET /kubeconfig` (real generation).
- `backend/app/services/permission.py` — implement `bind`, `unbind`, `generate_kubeconfig`, `list_templates`, `create_template`, `update_template`, `delete_template`, `list_bindings_for_user` (pure Python).
- `backend/app/services/k8s_client.py` — add `apply_role`, `apply_role_binding`, `delete_role_binding`, `delete_role`, `apply_cluster_role`, `apply_cluster_role_binding`, `delete_cluster_role_binding`, `delete_cluster_role` (idempotent, label-aware) on `K8sClient`; expose via `K8sClientPool`.
- `backend/app/api/_authhook.py` — no change (path-scoped auth already covers `/api/v1/*`); the admin gate is a per-handler `require_admin` helper.
- `backend/app/core/security.py` — add `require_admin()` (raises `RbacDeniedError` if `flask.g.current_user.role != "admin"`); extend `_auth_check` to reject `status == "disabled"` users.
- `backend/tests/api/test_admin_users.py`, `test_permissions.py`, `test_kubeconfig.py` — new API tests (replace the relevant 501 cases in `test_stubs.py`).
- `backend/tests/services/test_permission.py` — new service tests.
- `backend/tests/tasks/` — (none; no RQ in scope).

### Backend — new
- `backend/migrations/versions/<rev>_user_management_adr_0013.py` — Alembic: add `rbac_templates` (seed 4 built-ins via `op.bulk_insert`), add `audit_log` model columns if missing (reconcile, additive), extend `cluster_bindings` (+`namespace`, +`template`, +`created_at`, backfill `role` default), add unique constraint on `(user_id, cluster_id, namespace, template)`.
- `backend/app/schemas/permissions.py` — Pydantic request/response models (`TemplateOut`, `TemplateIn`, `BindIn`, `BindingOut`, `UserOut`, `UserPatch`, `MyAccessOut`, `AuditOut`).
- `backend/app/services/kubeconfig_render.py` — `render_kubeconfig(clusters, contexts, plugin_server) -> str` (pure, testable YAML emitter).

### Frontend — modify
- `frontend/package.json` — add `datatables.net-react` and `datatables.net-bs5` (ADR-0023). Do not add `datatables.net-dt`, `datatables.net-editor`, or jQuery.
- `frontend/src/lib/api.ts` — add a `downloadFile(path, filename)` blob helper (reuses token + 401 refresh, returns the error envelope on failure).
- `frontend/src/lib/types.ts` — add `User`, `Binding`, `RBACTemplate`, `AuditEntry` types.
- `frontend/src/_nav.tsx` — Users opens `/admin/permissions`; Audit Log opens `/admin/permissions?tab=audit` (ADR-0022). My Access stays `/permissions`.
- `frontend/src/routes.tsx` — `/permissions`, `/admin/permissions`, `/admin/permissions/users/:sub`.
- `frontend/tests/views/permissions.test.tsx` — MSW-mocked Vitest. Mock `KubeDataTable` and assert columns and rows.

### Frontend — new
- `frontend/src/components/KubeDataTable.tsx` — one `DataTable.use(datatables.net-bs5)` plus the Bootstrap 5 CSS import. Options `responsive: true`, `pageLength: 25`, class `table table-bordered`. Exports `Column`.
- `frontend/src/views/Permissions/index.tsx` — CoreUI card + `KubeDataTable` (Cluster, Namespace, Template, Created) + Download kubeconfig. Empty state does not mount the table.
- `frontend/src/views/AdminPermissions/index.tsx` — 4.1 User List only (no tab strip). Card header "User List". Columns Username, Email, Permission, Type, Action. Action: Privileges, Edit. Edit modal title "Update Information" patches role and status.
- `frontend/src/views/AdminPermissions/Privileges.tsx` — bindings `KubeDataTable` for the header's selected cluster, Unbind per row, and the 4.1 privilege form (cluster-scoped template select; namespaced template + namespace multi-select + all-namespaces; add row).
- `frontend/src/views/AdminPermissions/Templates.tsx` — own page at `?tab=templates`. Template `KubeDataTable` + rule editor + Role YAML preview.
- `frontend/src/views/AdminPermissions/Audit.tsx` — own page at `?tab=audit`. Audit `KubeDataTable` + action filter.

---

## Tasks

### Task 1 — Error codes + setting + model un-stub (foundation)
- **Do:**
  1. `errors.py`: add the two new error classes + `CODES` entries + count comment.
  2. `config.py`: add `plugin_server`.
  3. Un-stub `RBACTemplate` + `AuditLog` (add columns, drop `STUB`, import in `models/__init__.py`).
  4. Extend `ClusterBinding` (namespace/template/created_at + unique constraint + derived role).
- **Files:** `core/errors.py`, `core/config.py`, `models/rbac_template.py`, `models/audit.py`, `models/binding.py`, `models/__init__.py`.
- **Verify:** `uv run pytest -m "not integration"` green; `mypy --strict` clean; a model test asserts the new `cluster_bindings` columns + unique constraint; `errors.py` `CODES` length == 14 (12 + 2).

### Task 2 — Migration (one-way-door)
- **Do:**
  1. New Alembic revision (down_revision = `6feadb091ff4`):
     - `CREATE TABLE rbac_templates` + `op.bulk_insert` the 4 built-ins (rules per ARCHITECTURE.md §5B, `builtin=True`).
     - Reconcile `audit_log`: `inspect` live columns, `add_column` any missing (`actor_sub`, `target`, `cluster`, `namespace`, `template`, `at`), additive only.
     - Extend `cluster_bindings`: add `namespace` (nullable), `template` (str, nullable), `created_at` (server_default now), `role` default backfill to `viewer`; add `UniqueConstraint(user_id, cluster_id, namespace, template)`.
  2. Make the revision **idempotent-ish** (guard `add_column` with a column-exists check) so it applies on a fresh DB and a dev DB.
- **Files:** `migrations/versions/<rev>_user_management_adr_0013.py`.
- **Verify:** on a fresh Postgres, `flask db upgrade` creates `rbac_templates` with 4 rows and extends `cluster_bindings`; on a dev DB with data, it applies without dropping rows; `flask db downgrade` reverses cleanly; a test asserts the 4 seeded built-ins.

### Task 3 — k8s_client RBAC apply + permission service (bind/unbind) [TRACER]
- **Do:**
  1. `k8s_client.py`: `apply_role` / `apply_role_binding` / `apply_cluster_role` / `apply_cluster_role_binding` (get-or-create + patch rules, label-aware, idempotent) and their `delete_*` counterparts.
  2. `services/permission.py`: `bind(user, cluster, namespace, template)` — resolve (404), scope guard (422), apply in cluster (502 on error), upsert `cluster_bindings` (no-op + no re-audit if the triple exists), audit. `unbind(...)` — find row (404 `NO_BINDINGS`), delete RoleBinding, role GC (delete Role only if last referrer), delete row, audit.
  3. `require_admin()` in `security.py`; extend `_auth_check` to reject disabled users.
- **Files:** `services/k8s_client.py`, `services/permission.py`, `core/security.py`.
- **Verify:** unit tests (mock K8sClient) cover: idempotent re-bind (no 2nd audit row), role GC (Role deleted only on last referrer), scope mismatch 422, unknown triple 404, unreachable cluster 502 with no row; **integration (kind-gated)**: a real bind creates the Role + RoleBinding with correct rules + labels, re-bind is a no-op, unbind + GC verified.

### Task 4 — API: admin users + templates + bind endpoints
- **Do:**
  1. `api/admin.py`: `GET /admin/users` (list + cluster count), `PATCH /admin/users/<id>` (role/status, audit, bootstrap-admin immutable 409).
  2. `api/permissions.py`: templates CRUD (list/create/get/update/delete, built-in guard 409 `BUILTIN_TEMPLATE_PROTECTED`, referenced-custom guard 409), `POST/DELETE /admin/permissions/bind`, `GET /permissions/my-access` (caller's bindings, `[]` when none).
  3. `schemas/permissions.py` for all request/response models.
  4. Replace the corresponding 501 stubs; update `test_stubs.py` to drop those paths from the "still 501" baseline.
- **Files:** `api/admin.py`, `api/permissions.py`, `schemas/permissions.py`, `tests/api/*`, `tests/api/apidocs_paths_baseline.json`.
- **Verify:** API tests (Testcontainers Postgres, mocked K8sClient): admin 403 for non-admin, list/patch/audit, template CRUD + both 409 guards, bind 200/idempotent/422/404, my-access isolation, bootstrap-admin 409; OpenAPI baseline updated; `uv run pytest -m "not integration"` green.

### Task 5 — kubeconfig generation + render [TRACER]
- **Do:**
  1. `services/kubeconfig_render.py`: `render_kubeconfig(clusters, contexts, plugin_server)` — pure YAML (one context/cluster per bound cluster, `namespace` when namespaced, one shared `users[]` exec entry with `--server`, base64 CA).
  2. `services/permission.py`: `generate_kubeconfig(user)` — collect bindings, group by cluster, decrypt each registry kubeconfig for `server` + `certificate-authority-data` (support `certificate-authority` file-form by base64-ing the path's content or the CA from the client), `NO_BINDINGS` (404) when none, `INTERNAL_ERROR` if `plugin_server` unset.
  3. `api/kubeconfig.py`: `GET /kubeconfig` returns the YAML as an attachment (`Content-Disposition`, `application/yaml`).
- **Files:** `services/kubeconfig_render.py`, `services/permission.py`, `api/kubeconfig.py`, `tests/services/test_kubeconfig_render.py`, `tests/api/test_kubeconfig.py`.
- **Verify:** unit tests: single-cluster YAML shape (1 context/cluster/user, exec entry, base64 CA, `namespace` set), multi-cluster (N contexts, 1 shared user), no-binding 404 `NO_BINDINGS`, unset plugin_server 500, **no `token`/`tokenFile`/`oidc-*` keys present**; integration: `kubectl config view --kubeconfig <generated>` parses, and the exec entry's `--server` matches `KUBEDASH_PLUGIN_SERVER`.

### Task 6 — Frontend: My Access + download (all users)
- **Do:**
  1. Add `datatables.net-react` and `datatables.net-bs5`. Add `components/KubeDataTable.tsx` (`DataTable.use`, Bootstrap 5 CSS, `responsive`, `pageLength: 25`, `table table-bordered`).
  2. `lib/api.ts`: `downloadFile(path, filename)` blob helper (token + 401 refresh, error envelope on failure).
  3. `views/Permissions/index.tsx`: CoreUI card + `KubeDataTable` (R5 columns Cluster, Namespace, Template, Created) + Download kubeconfig (R6). Empty state does not mount the table.
  4. `lib/types.ts` types; `_nav.tsx` + `routes.tsx` for `/permissions`.
  5. `tests/views/permissions.test.tsx` (MSW): mock `KubeDataTable`, assert columns and rows, download filename, empty state.
- **Files:** `package.json`, `components/KubeDataTable.tsx`, `lib/api.ts`, `lib/types.ts`, `views/Permissions/*`, `_nav.tsx`, `routes.tsx`, `tests/views/permissions.test.tsx`.
- **Verify:** `task fe-build` (tsc + lint + build) green; `task fe-check` (no-CDN) green; Vitest MSW suite passes (no live backend); the download triggers `kubedash-kubeconfig.yaml`.

### Task 7 — Frontend: 4.1 User List + privileges
- **Do:**
  1. `views/AdminPermissions/index.tsx`: User List card (header "User List"). Columns Username, Email, Permission, Type, Action. Privileges link. Edit modal "Update Information" (role, status). No tab strip, no Add User, no Delete.
  2. `views/AdminPermissions/Privileges.tsx`: bindings table for the header's selected cluster, Unbind, and the 4.1 privilege form (cluster template select; namespaced template + namespaces + all-namespaces; add row). Save calls bind once per pair.
  3. `Templates.tsx` at `?tab=templates` (rule editor + Role YAML preview, built-ins locked). `Audit.tsx` at `?tab=audit` (action filter). Both are separate pages.
  4. Routes: `/admin/permissions`, `/admin/permissions/users/:sub`. Non-admin redirect.
  5. MSW tests mock `KubeDataTable` and cover User List columns, privilege submit, unbind, template editor + preview, 403/409/404 messages.
- **Files:** `views/AdminPermissions/*`, `_nav.tsx`, `routes.tsx`, `tests/views/admin_permissions.test.tsx`.
- **Verify:** `task fe-build` + `task fe-check` green; MSW suite passes; error codes render as messages (no console errors); a Playwright e2e (kind + Helm) opens the User List, binds a template from the privilege form, and downloads a kubeconfig from My Access.

### Task 8 — Docs + contract + full-suite verification
- **Do:**
  1. `errors.py` count comment + AGENTS.md config table (`KUBEDASH_PLUGIN_SERVER`) + ARCHITECTURE.md §5B service block (stub → implemented) + ADR index note.
  2. Run the full matrix: backend unit (`-m "not integration"`), backend integration (kind, where Docker present), frontend unit, `task fe-check`, `helm lint` + `helm template`.
  3. Update the `apidocs_paths_baseline.json` and confirm the stub-surface guard (TICKET-06) no longer lists the implemented paths.
- **Files:** `.skillgrid/ARCHITECTURE.md`, `AGENTS.md`, `backend/tests/api/apidocs_paths_baseline.json`.
- **Verify:** all suites green (or Docker-blocked `skipped` where no runtime); docs match the code; the OpenAPI baseline reflects the real (non-501) routes.

---

## Execution Order & Waves

| Wave | Tasks | Why this order |
|---|---|---|
| 1 | Task 1 (errors/config/models) | Foundation every other task imports; un-stubs the models so `db.metadata` is correct. |
| 2 | Task 2 (migration) | One-way-door schema must exist before service/API write it; isolated, revertable. |
| 3 | Task 3 (k8s_client + service bind/unbind) | **Tracer core** — the apply loop; unit-testable with a mock, integration-gated for kind. |
| 4 | Task 4 (API: users + templates + bind) | Exposes Task 3 over HTTP; needs Task 1's schemas + codes. |
| 5 | Task 5 (kubeconfig render + endpoint) | **Tracer end** — consumes bindings from Task 3/4; completes the user-facing loop. |
| 6 | Task 6 (frontend My Access) | First UI on the now-real API; all-users surface (lowest risk). |
| 7 | Task 7 (4.1 User List + privileges) | Richest UI; depends on Tasks 4 + 5 endpoints + Task 6's `KubeDataTable` and `downloadFile` helper. |
| 8 | Task 8 (docs + full verification) | Closes the change; docs + baseline + full matrix. |

Dependencies: `2 ← 1`, `3 ← 2`, `4 ← 1,3`, `5 ← 3`, `6 ← 5`, `7 ← 4,5,6`, `8 ← 4,5,6,7`.
Tasks 6 and 7 are independently reviewable once Tasks 4+5 land; Task 3 and Task 5 are the
two **tracer** checkpoints (stop-and-re-examine if the YAML shape or idempotency is wrong).

---

## Self-Review

- **Does every briefing requirement map to a task?**
  R1→T4, R2→T4, R3→T3+T4, R4→T3+T4, R5→T4, R6→T5, R7→T2+T4(audit)+T1, R8→T6, R9→T7, R10→T8. ✓
- **Is the one-way-door handled?** `cluster_bindings` change is Task 2 (dedicated migration, additive, revertable). ✓
- **Are the two new error codes scoped?** Only in Task 1; count comment bumped in Task 1 + Task 8. ✓
- **Is the service Flask-free?** `services/permission.py` + `kubeconfig_render.py` take session/pool as args, no Flask imports. ✓
- **Is the plugin contract honored?** Kubeconfig `users[]` is exec-only, `--server` from `KUBEDASH_PLUGIN_SERVER`, no embedded token (asserted by a test). ✓
- **What's explicitly out?** Drift RQ task, NaaS/PAM/JIT/SCIM/aggregated API, effective-permission read, CLI changes — all listed as out of scope and untouched. ✓

## Owed-Decision Gate

- **`cluster_bindings.role` — keep (template-derived) or drop?** Default: keep, derived from template scope so the existing R3 cluster-visibility gate keeps working. If it conflicts with a template that maps to a role outside `{viewer, editor, admin}`, record an ADR-0013 addendum before Task 2.
- **CA file-form vs data-form in the registry.** Default: support both (base64 the file content when `certificate-authority` path is present). If registration (ADR-0002) should instead normalize to `-data`, that is a change to the cluster-registry change, not this one.
- **`KUBEDASH_PLUGIN_SERVER` Helm default.** Default: in-cluster Service DNS (`kubedash.<ns>.svc`) so an air-gapped install works without a public ingress; overridable to an ingress URL.

## Plan Review

- Risk: `risky` (one-way-door schema + 2 frozen-contract codes + writes RBAC into clusters) → L2 + security review.
- Rollback unit: the `rebase` work branch; the migration (Task 2) is a single revertable revision.
- Tracer checkpoints: end of Task 3 (idempotent apply) and end of Task 5 (YAML the plugin accepts). If either fails the "Wrong condition", stop and re-examine before Task 4/6/7.

## Execution Handoff

Publish to the tracker as two tasks (already created): **TASK-023** (Tasks 1-5, 8-backend — the API) and **TASK-024** (Tasks 6-7, 8-frontend — the UI, depends on TASK-023). Each worker researches the current system and records the per-ticket plan after activating the task; this blueprint is the *how* they slice from.
