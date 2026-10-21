# Report — User management (role templates, bindings, self-service kubeconfig)

> Change: `.skillgrid/specs/2026-10-19-user-management/` (moves to `.skillgrid/xarchive/2026-10-19-user-management/` at ship)
> Generated: 2026-10-21T13:55:00+02:00 (qa)
> Gate: **FAIL**
> Branch: `rebase` @ `bea190f1` · Ticket commits: T-01 `7e860022`, T-02 `3d94e54c` (+`bcf8a025`), T-03 `177acf86`, T-04 `114d762a`, T-05 `82869872` (+`a2075093`, `384a796d`), T-06 `0ca343e0`, T-07 `46282ddf`, T-08 `c2f5f015` `3fe5cf54` `bea190f1` (+ AppFooter hunk in `57f7551e`). State pointer `bcc2a8f4`.
> Change classification: `risky` (blueprint `## Plan Review`) → floor **L2 + security review**. Effective tier: no `Tier:` line in briefing/blueprint, no `rules.tiers.default` in config → inferred from classification (T2-equivalent: L2+L3). Applied floor: L2 + security review.
> Blueprint status: `PROPOSED` (not `ASSUMED` — no decision-debt flag).
> **quality: not configured — using defaults.** Run `skillgrid:onboarding` to set thresholds. (`.skillgrid/config.yaml` has no `quality:`, `testing.runner`, `testing.coverage`, `testing.mutation`, `commands.lint`, `security.trivy`, or `duplication` keys. Defaults: coverage_min 80, mutation_min 80, p0 100, p1 95; Trivy/duplication not configured.)
>
> **Spec-zone note (load-bearing).** At gate time `briefing.md`, `blueprint.md`, `acceptance.feature`, and `tasks.md` carry **uncommitted** working-tree edits (+112/−73 lines vs `HEAD`) and a new untracked `adr.md`. The edits re-scope R8/R9 to the 4.1 DataTables UI (ADR-0023) and rewrite scenario `admin-binds-a-template-from-the-admin-view`. The committed tickets T-06/T-07 were built against the earlier spec. This gate reads the **working-tree** spec (what is on disk); where the verdict would differ against `HEAD`'s spec, the row says so.
>
> Two phases, one file: **qa** writes the QA half (the sections above `## Final-State Facts`,
> through `## Gate Decision` + `## Human Override`) into the spec folder. **ship** reads the
> `## Gate Decision` verdict PRE-MOVE, then moves the folder. **reflect** completes the retro
> half (from `## Final-State Facts` onward) IN PLACE in the archive folder.

## Test Plan

> Derived from `blueprint.md`, `tasks.md`, and `acceptance.feature` (working tree).
> Risk-ordered. Every row must be covered by a named test or scenario before the gate passes.

### Risk Ranking

The most likely production break is **bind/unbind writing the wrong RBAC into a live cluster** (non-idempotent re-bind, Role GC deleting a Role another user still references, or a binding row recorded after a cluster error) — it grants or revokes real cluster access. Second is the **self-service kubeconfig** leaking a credential or server-side data (ADR-0011: plugin-only auth), and the **one-way-door migration** seeding/extending tables. The plan tests these hardest; the UI is P1.

### Plan

Evidence legend — **[QA]** = re-run by QA this session; **[impl]** = implementer-reported only.
QA runs this session (all from `backend/` unless noted):
- R1 `uv run pytest -m "not integration" -q` → **270 passed, 6 deselected, exit 0** [QA] (default collection order).
- R2 `uv run pytest -m "not integration" tests/api/test_admin_users.py tests/api/test_permissions.py tests/api/test_kubeconfig.py tests/services/test_permission.py tests/services/test_kubeconfig_render.py tests/services/test_permission_generate_kubeconfig.py tests/models/test_user_management_models.py tests/migrations/test_user_management_revision.py` → **80 passed, 1 failed** (`test_builtin_templates_are_seeded_and_protected`: `assert 17 == 4`) [QA]. Order-dependent — see CRITICAL C5.
- R3 `uv run pytest -m "not integration" tests/migrations/test_user_management_revision.py` → **5 passed** [QA].
- R4 `uv run pytest -m integration tests/integration -v` → **2 passed** (`test_bind_rebind_unbind_gc_on_kind`, `test_downloaded_yaml_passes_kubectl_config_view`) against kind [QA].
- R5 `frontend/: corepack pnpm vitest run permissions admin_permissions` → **2 files, 18 tests passed** [QA] (the `permissions` filter matches both files; 4 in `permissions.test.tsx`, 14 in `admin_permissions.test.tsx`).
- R6 `uv run ruff check app tests` → **26 errors** in this change's test files (app/ clean) [QA]; `uv run mypy --strict` on the changed `app/` modules → **0 issues in 17 files** [QA].
- Parent re-verify (controller, exit 0): `test_health.py` + `test_stubs.py` 7 passed; `task fe-check` (incl. `fe-build`); `helm lint charts/kubedash`; `helm template t charts/kubedash`.

| # | Risk / Behavior | Seam | Layer | Test / Scenario | Priority | Cadence | Status |
|---|-----------------|------|-------|-----------------|----------|---------|--------|
| 1 | Bind creates Role+RoleBinding with template rules + `kubedash.io/*` labels, records the binding | `permission.bind` → K8s RBAC API | integration | `tests/integration/test_bind_kind.py::test_bind_rebind_unbind_gc_on_kind`; unit `tests/services/test_permission.py::test_bind_applies_role_and_rolebinding`; API `tests/api/test_permissions.py::test_admin_bind_records_binding_and_audits` | P0 | nightly (kind) / pr (unit) | covered [QA R1, R4] |
| 2 | Re-bind same triple is a no-op (one RoleBinding, no new audit row) | `permission.bind` | integration | `test_bind_kind.py::test_bind_rebind_unbind_gc_on_kind` (re-bind half); `test_permission.py::test_rebind_is_noop`; `test_permissions.py::test_rebind_is_a_noop_no_new_audit` | P0 | pr | covered [QA R1, R4] |
| 3 | Role GC: Role kept while another binding references it, deleted on last referrer | `permission.unbind` | unit (+integration last-referrer) | `test_permission.py::test_unbind_deletes_rolebinding_and_gc_keeps_role`, `::test_unbind_last_referrer_deletes_role`, `::test_unbind_cluster_scoped_gc_deletes_cluster_role`; kind last-referrer in `test_bind_rebind_unbind_gc_on_kind` | P0 | pr | covered [QA R1, R4] — two-user "Role remains" half is unit/mocked only |
| 4 | Unreachable cluster → 502, no binding row | `permission.bind` error path | unit | `test_permission.py::test_unreachable_cluster_records_nothing`; `test_permissions.py::test_bind_unreachable_cluster_is_502_no_binding` | P0 | pr | covered [QA R1] |
| 5 | Scope guard (cluster tpl + ns → 422; ns tpl w/o ns → 422) | `permission.bind` | unit | `test_permission.py::test_scope_mismatch_is_422` (parametrized); `test_permissions.py::test_bind_scope_mismatch_is_422` | P0 | pr | covered [QA R1] |
| 6 | Kubeconfig carries no `token`/`tokenFile`/`oidc-*`; single exec user | `render_kubeconfig`, `GET /kubeconfig` | unit + API | `tests/services/test_kubeconfig_render.py::test_no_token_anywhere`; `tests/api/test_kubeconfig.py::test_bound_user_downloads_multi_cluster_yaml` | P0 | pr | covered [QA R1] |
| 7 | Multi-cluster kubeconfig shape + `kubectl config view` parses | `GET /kubeconfig` | integration | `test_kubeconfig.py::test_bound_user_downloads_multi_cluster_yaml`; `test_kubeconfig_render.py::test_multi_cluster_multi_namespace`; `tests/integration/test_kubeconfig_kind.py::test_downloaded_yaml_passes_kubectl_config_view` | P0 | pr / nightly | covered [QA R1, R4] |
| 8 | Migration seeds exactly 4 built-ins; extends `cluster_bindings`; reconciles `audit_log` additively | Alembic revision `3c9f21a7d5b4` | integration (Testcontainers) | `tests/migrations/test_user_management_revision.py::test_builtin_templates_are_seeded_and_protected`, `::test_cluster_bindings_extended_with_unique_triple`, `::test_audit_log_reconciled_additively`, `::test_upgrade_is_idempotent_safe` | P0 | pr | covered in default order [QA R1, R3]; **FAILED when run after service tests** [QA R2] |
| 9 | Admin gate: non-admin → 403 `RBAC_DENIED` on admin routes | `require_admin()` | API | `test_admin_users.py::test_non_admin_get_admin_users_is_403`; `test_permissions.py::test_templates_require_admin`; `test_permission.py::test_require_admin_denies_non_admin` | P0 | pr | covered [QA R1] |
| 10 | Disabled user → 401 on next call | `_load_user_for_claims` | API | `test_admin_users.py::test_admin_patches_user_status_disabled_next_call_401`; `test_permission.py::test_disabled_user_rejected_at_auth` | P0 | pr | covered [QA R1] |
| 11 | Bootstrap `local:` admin immutable (409) | `PATCH /admin/users/<id>` | API | `test_admin_users.py::test_bootstrap_admin_role_change_is_409`, `::test_bootstrap_admin_status_change_is_409` | P0 | pr | covered [QA R1] |
| 12 | My-access isolation (never another user's bindings) | `GET /permissions/my-access` | API | `test_permissions.py::test_a_user_never_sees_another_users_bindings` | P0 | pr | covered [QA R1] |
| 13 | Admin users list + patch + audit | `GET/PATCH /admin/users` | API | `test_admin_users.py::test_admin_lists_users_with_cluster_count`, `::test_admin_patches_user_role_and_audits` | P1 | pr | covered [QA R1] |
| 14 | Template CRUD, built-in delete 409, referenced delete 409, malformed 422 | `/admin/permissions/templates` | API | `test_permissions.py::test_admin_creates_and_reads_a_custom_template`, `::test_delete_builtin_template_is_409`, `::test_referenced_custom_template_cannot_be_deleted`, `::test_malformed_template_rule_is_rejected` | P1 | pr | covered [QA R1] |
| 15 | Audit read `GET /api/v1/admin/audit?actions=…` (R7) | `app/api/audit.py` | API | — none (route is a 501 stub at `/v1/audit`) | P1 | pr | **pending** |
| 16 | My Access list + download `kubedash-kubeconfig.yaml` + empty state | `views/Permissions` | unit (MSW) | `frontend/tests/views/permissions.test.tsx` › `user-downloads-a-kubeconfig-from-my-access`, `my-access-shows-an-empty-state-for-no-bindings` | P1 | pr | covered [QA R5] |
| 17 | My Access list is a `KubeDataTable` (ADR-0023, working-tree R8) | `components/KubeDataTable.tsx` | unit (MSW) | — none (component absent; no `datatables.net-*` dep) | P1 | pr | **pending** |
| 18 | 4.1 User List DataTable (Username/Email/Permission/Type/Action) + Privileges page save + listed (working-tree R9) | `views/AdminPermissions/index.tsx`, `Privileges.tsx` | unit (MSW) + e2e | — none (`Privileges.tsx`, `Templates.tsx`, `Audit.tsx`, `frontend/e2e/admin_permissions.spec.ts` absent) | P1 | pr / nightly | **pending** |
| 19 | Admin view renders API errors as messages, no unhandled rejection | `views/AdminPermissions` | unit (MSW) | `admin_permissions.test.tsx` › `bind-409-surfaced-as-message-without-unhandled-rejection`, `users-tab-403-surfaced-as-text-danger` | P1 | pr | covered [QA R5] |
| 20 | Non-admin redirected from admin route | `AdminRoute` | unit (MSW) | `admin_permissions.test.tsx` › `non-admin-redirected-away-from-the-admin-view` | P1 | pr | covered [QA R5] |
| 21 | No CDN / outbound URLs in bundle (ADR-0020) | `task fe-check` | build | `task fe-check` | P1 | pr | covered [controller re-verify] |

**Layer** — `testing.layers` not configured; available in repo: unit (pytest, Vitest+MSW), integration (Testcontainers / kind-gated pytest), e2e (Playwright, kind+Helm). Duplicate Coverage Guard applied: the API rows rely on the unit/mocked-K8s tier; kind is used only where the real API server is the oracle (labels, rules normalization, `kubectl config view`).

**Cadence** — `pr` (runs on every pull request, blocks merge) or `nightly` (runs in scheduled CI, regression net only).

### Edge-Case Matrix

| Requirement | Edge / Boundary | Expected Behavior | Test / Scenario | Status |
|-------------|-----------------|-------------------|-----------------|--------|
| R3 bind | unknown user / cluster / template | 404 with stable code | `test_permissions.py::test_bind_unknown_user_is_404`, `::test_bind_unknown_cluster_is_404`, `::test_bind_unknown_template_is_404`; `test_permission.py::test_missing_*_is_404` | covered |
| R3 bind | cluster-scoped template | ClusterRole + ClusterRoleBinding, no namespace | `test_permission.py::test_bind_cluster_scoped_template` | covered |
| R4 unbind | second unbind on same triple | 404 `NO_BINDINGS` | `test_permissions.py::test_unbind_missing_is_404_no_bindings`; `test_permission.py::test_unbind_missing_is_404` | covered |
| R4 unbind | unknown cluster | 404 | `test_permissions.py::test_unbind_unknown_cluster_is_404` | covered |
| R2 templates | name collision | 409 | `test_permissions.py::test_template_name_collision_is_409` | covered |
| R2 templates | PUT on built-in | 409 | `test_permissions.py::test_put_builtin_template_is_409` | covered |
| R1 users | invalid role value | 422 | `test_admin_users.py::test_patch_invalid_role_is_422` | covered |
| R1 users | unknown user id | 404 | `test_admin_users.py::test_patch_unknown_user_is_404` | covered |
| R6 kubeconfig | `KUBEDASH_PLUGIN_SERVER` unset | 500 `INTERNAL_ERROR` | `test_kubeconfig.py::test_plugin_server_unset_500`; `test_permission_generate_kubeconfig.py::test_plugin_server_unset_is_internal_error` | covered |
| R6 kubeconfig | CA as file path (`certificate-authority`) | file bytes base64-embedded | `test_permission_generate_kubeconfig.py::test_ca_from_file_path`, `::test_file_form_ca_is_embedded` | covered (see security W2) |
| R6 kubeconfig | no CA in registry kubeconfig | `certificate-authority-data` key omitted | `test_kubeconfig_render.py::test_empty_ca_omits_certificate_authority_data_key`; `test_permission_generate_kubeconfig.py::test_no_ca_is_omitted` | covered |
| R6 kubeconfig | same cluster, two namespaces | two contexts, one cluster entry | `test_kubeconfig_render.py::test_same_cluster_two_namespaces_two_contexts_one_cluster_entry` | covered |
| R6 kubeconfig | cluster-scoped binding only | context has no `namespace` key | `test_kubeconfig.py::test_cluster_scoped_binding_only_omits_namespace`; `test_kubeconfig_render.py::test_cluster_scoped_binding_omits_namespace_key` | covered |
| R6 kubeconfig | non-mapping registry kubeconfig | `ValueError` (500) | `test_permission_generate_kubeconfig.py::test_ca_non_mapping_doc_raises_value_error` | covered |
| R2 migration | DB that already ran `create_all()` (dev-DB path) | guarded no-op, additive reconcile | `test_user_management_revision.py::test_upgrade_is_idempotent_safe`, `::test_audit_log_reconciled_additively` | covered |
| R7 audit read | action filter | returns only filtered actions | — | pending (route not implemented) |
| R8 download | 404 from `/kubeconfig` | message shown, no file saved | `permissions.test.tsx` › `download failure surfaces the error message, no unhandled rejection` | covered |

### Out of Scope

- RBAC drift detection (`tasks/rbac_drift.py`), NaaS (5C), PAM (5D), JIT (5E), SCIM (5F), aggregated API (5A) — out of scope per briefing; their stub routes stay 501.
- Effective-permission read (ADR-0004 SAR path, `/auth/me/permissions`) — separate change.
- CLI `kubedash get-token` behavior — ADR-0011 contract, consumed not changed.
- Pre-existing red suites not touched by this diff (controller proved `git diff bcc2a8f4..HEAD` does not touch them or `permission.py`): integration `test_clusters_admin`, `test_worker_gate`, `test_resources` (2 failed, 2 errors) [impl]; frontend `tests/views/Cluster.test.tsx` [impl]. Recorded as pre-existing, not regressions of this change.

## Goal-Backward Verification

**Stated goal** (from briefing.md): give cluster admins a UI + API to see users, bind RBAC role templates to user × cluster × namespace, and manage templates; give every authenticated user a Download kubeconfig button yielding a multi-cluster, plugin-auth YAML.

**Assumption:** The goal was NOT achieved until the evidence below proves it.

| Level | Item | Evidence | Status |
|-------|------|----------|--------|
| Truth | R1 — admin users list/patch, audit, bootstrap immutable, disabled → 401 | `test_admin_users.py` (8 tests) [QA R1] | VERIFIED |
| Truth | R2 — template CRUD, 4 seeded built-ins, built-in/referenced delete 409, malformed 422 | `test_permissions.py` template tests + `test_user_management_revision.py::test_builtin_templates_are_seeded_and_protected` [QA R1, R3] | VERIFIED (seed test is order-dependent — C5) |
| Truth | R3 — bind applies Role+RoleBinding, idempotent, scope guard, 404s, 502 w/o row | `test_bind_kind.py` [QA R4] + `test_permission.py` + `test_permissions.py` [QA R1] | VERIFIED |
| Truth | R4 — unbind + Role GC on last referrer, 404 `NO_BINDINGS` on repeat | `test_permission.py::test_unbind_*` [QA R1]; kind last-referrer [QA R4] | VERIFIED |
| Truth | R5 — my-access returns caller's bindings only, `[]` when none | `test_permissions.py::test_user_lists_their_own_bindings`, `::test_unbound_user_sees_empty_list`, `::test_a_user_never_sees_another_users_bindings` [QA R1] | VERIFIED |
| Truth | R6 — multi-cluster kubeconfig, exec-only user, headers, 404/500, kubectl parses | `test_kubeconfig.py`, `test_kubeconfig_render.py`, `test_permission_generate_kubeconfig.py` [QA R1]; `test_kubeconfig_kind.py` [QA R4] | VERIFIED |
| Truth | R7 — every mutation audits exactly once | audit-row asserts in `test_admin_patches_user_role_and_audits`, `test_admin_bind_records_binding_and_audits`, `test_unbind_removes_binding_and_audits`, kind re-bind count [QA R1, R4] | VERIFIED |
| Truth | R7 — `GET /api/v1/admin/audit?actions=…` (admin-only, paginated, filtered) | `backend/app/api/audit.py:20-23` raises `NotImplementedError_` at `/v1/audit`; no `/admin/audit` route; frontend test `audit-tab-renders-empty-state-on-501` mocks the 501 | **UNVERIFIED** |
| Truth | R8 — My Access list + download + empty state | `permissions.test.tsx` [QA R5] | VERIFIED |
| Truth | R8 — list rendered via `KubeDataTable` (ADR-0023, working-tree spec) | `frontend/src/components/KubeDataTable.tsx` absent; no `datatables.net-react`/`-bs5` in `frontend/package.json` | **UNVERIFIED** |
| Truth | R9 — 4.1 User List DataTable, Privileges page, separate Templates/Audit pages, Playwright e2e | `views/AdminPermissions/` has only `index.tsx` + `components/BindModal.tsx`, `TemplateEditor.tsx` (tab strip; `admin_permissions.test.tsx` clicks a "Templates" tab button and asserts "per-user binding listing is not available"); `Privileges.tsx`, `Templates.tsx`, `Audit.tsx`, `frontend/e2e/admin_permissions.spec.ts` absent | **UNVERIFIED** |
| Truth | R9 — errors render as messages; non-admin redirect | `admin_permissions.test.tsx` error + redirect tests [QA R5] | VERIFIED |
| Truth | R10 — error codes 14, ARCHITECTURE §5B, AGENTS env row | `test_user_management_models.py::test_new_error_codes_are_frozen_at_14` [QA R1]; ARCHITECTURE/AGENTS are docs (grep-only: `git grep KUBEDASH_PLUGIN_SERVER HEAD -- AGENTS.md` hits; the **working-tree** AGENTS.md condensation drops the config table) | PRESENT_BEHAVIOR_UNVERIFIED (docs) |
| Artifact | `services/permission.py` (`bind`/`unbind`/`generate_kubeconfig`), `services/kubeconfig_render.py`, `api/admin.py`, `api/permissions.py`, `api/kubeconfig.py`, migration `3c9f21a7d5b4` | exist, wired, exercised by tests above [QA R1, R4] | VERIFIED |
| Artifact | `components/KubeDataTable.tsx`, `AdminPermissions/Privileges.tsx`, `Templates.tsx`, `Audit.tsx`, `e2e/admin_permissions.spec.ts` (tasks.md T-06/T-07 Files, working tree) | absent on disk | **UNVERIFIED** |
| Key Link | API → `permission.bind` → K8s RBAC API → `cluster_bindings` + `audit_log` | `test_bind_kind.py` (service → real API server); API tier with fake K8s [QA R1, R4] | VERIFIED |
| Key Link | `GET /kubeconfig` → decrypt registry kubeconfig → render → `kubectl config view` | `test_kubeconfig_kind.py` [QA R4] | VERIFIED |
| Key Link | Admin UI → `POST /admin/permissions/bind` → binding listed on privilege page | `bind-submits-user-cluster-namespace-template` mounts `BindModal` standalone; no test (and no UI) lists the created binding per user | **UNVERIFIED** |
| Data Flow | registered cluster + binding → downloaded YAML with real server + base64 CA | `test_kubeconfig.py::test_bound_user_downloads_multi_cluster_yaml` asserts `certificate-authority-data == b64(CA_PEM)` and `--server=` arg [QA R1] | VERIFIED |

## Traceability Matrix

Scenario count read from `acceptance.feature` (working tree): **26**. Scope: COMPLETE.

| Scenario (from acceptance.feature) | Test / Scenario (from test plan) | Ran | Result |
|--------------------------------------|----------------------------------|-----|--------|
| admin-lists-and-patches-a-user | `test_admin_users.py::test_admin_lists_users_with_cluster_count`, `::test_admin_patches_user_role_and_audits` | yes [QA R1] | pass — COMPLIANT |
| bootstrap-admin-cannot-be-demotion-or-disabled | `test_admin_users.py::test_bootstrap_admin_role_change_is_409`, `::test_bootstrap_admin_status_change_is_409` | yes [QA R1] | pass — COMPLIANT |
| non-admin-cannot-reach-admin-users | `test_admin_users.py::test_non_admin_get_admin_users_is_403` | yes [QA R1] | pass — COMPLIANT |
| disabled-user-is-rejected | `test_admin_users.py::test_admin_patches_user_status_disabled_next_call_401`; `test_permission.py::test_disabled_user_rejected_at_auth` | yes [QA R1] | pass — COMPLIANT |
| admin-creates-and-reads-a-custom-template | `test_permissions.py::test_admin_creates_and_reads_a_custom_template` | yes [QA R1] | pass — COMPLIANT |
| builtin-templates-are-seeded-and-protected | `test_user_management_revision.py::test_builtin_templates_are_seeded_and_protected`; `test_permissions.py::test_template_list_builtins_first`, `::test_delete_builtin_template_is_409` | yes [QA R1, R2, R3] | pass in default order and alone; **fail** (`17 == 4`) when run after service tests — COMPLIANT on the gate run, flagged C5 |
| template-in-use-cannot-be-deleted | `test_permissions.py::test_referenced_custom_template_cannot_be_deleted` | yes [QA R1] | pass — COMPLIANT |
| malformed-template-rule-is-rejected | `test_permissions.py::test_malformed_template_rule_is_rejected` | yes [QA R1] | pass — COMPLIANT |
| admin-binds-a-template-and-it-applies-in-the-cluster | `test_bind_kind.py::test_bind_rebind_unbind_gc_on_kind`; `test_permissions.py::test_admin_bind_records_binding_and_audits` | yes [QA R1, R4] | pass — COMPLIANT |
| rebinding-the-same-binding-is-a-no-op | `test_bind_kind.py::test_bind_rebind_unbind_gc_on_kind`; `test_permissions.py::test_rebind_is_a_noop_no_new_audit` | yes [QA R1, R4] | pass — COMPLIANT |
| binding-with-a-mismatched-scope-is-rejected | `test_permissions.py::test_bind_scope_mismatch_is_422`; `test_permission.py::test_scope_mismatch_is_422` | yes [QA R1] | pass — COMPLIANT |
| unbinding-the-last-user-deletes-the-cluster-role | `test_permission.py::test_unbind_deletes_rolebinding_and_gc_keeps_role`, `::test_unbind_last_referrer_deletes_role`; kind last-referrer in `test_bind_rebind_unbind_gc_on_kind` | yes [QA R1, R4] | pass — COMPLIANT (two-user half is mocked-K8s only; scenario says kind-gated) |
| unbinding-a-missing-binding-is-a-404 | `test_permissions.py::test_unbind_missing_is_404_no_bindings` | yes [QA R1] | pass — COMPLIANT |
| binding-against-an-unreachable-cluster-records-nothing | `test_permissions.py::test_bind_unreachable_cluster_is_502_no_binding`; `test_permission.py::test_unreachable_cluster_records_nothing` | yes [QA R1] | pass — COMPLIANT |
| user-lists-their-own-bindings | `test_permissions.py::test_user_lists_their_own_bindings` | yes [QA R1] | pass — COMPLIANT |
| user-with-no-bindings-sees-an-empty-list | `test_permissions.py::test_unbound_user_sees_empty_list` | yes [QA R1] | pass — COMPLIANT |
| a-user-never-sees-another-users-bindings | `test_permissions.py::test_a_user_never_sees_another_users_bindings` | yes [QA R1] | pass — COMPLIANT |
| user-downloads-a-multi-cluster-kubeconfig | `test_kubeconfig.py::test_bound_user_downloads_multi_cluster_yaml`; `test_kubeconfig_kind.py::test_downloaded_yaml_passes_kubectl_config_view` | yes [QA R1, R4] | pass — COMPLIANT |
| user-bound-to-one-cluster-gets-a-single-context-kubeconfig | `test_kubeconfig_render.py::test_single_cluster_single_namespace`; `test_kubeconfig.py::test_cluster_scoped_binding_only_omits_namespace` | yes [QA R1] | pass — COMPLIANT |
| user-with-no-bindings-gets-a-404 | `test_kubeconfig.py::test_no_bindings_404`; `test_permission_generate_kubeconfig.py::test_no_bindings_raises_no_bindings_error` | yes [QA R1] | pass — COMPLIANT |
| the-kubeconfig-never-embeds-a-token | `test_kubeconfig_render.py::test_no_token_anywhere`; token asserts in `test_bound_user_downloads_multi_cluster_yaml` | yes [QA R1] | pass — COMPLIANT |
| user-downloads-a-kubeconfig-from-my-access | `permissions.test.tsx` › `user-downloads-a-kubeconfig-from-my-access` | yes [QA R5] | pass — COMPLIANT |
| my-access-shows-an-empty-state-for-no-bindings | `permissions.test.tsx` › `my-access-shows-an-empty-state-for-no-bindings` | yes [QA R5] | pass — COMPLIANT |
| admin-binds-a-template-from-the-admin-view | — no test asserts a DataTable with Username/Email/Permission/Type/Action, a privileges page, or the binding listed after save (`bind-submits-user-cluster-namespace-template` mounts `BindModal` alone; `user-detail-opens-…` asserts "per-user binding listing is not available") | no | **pending — UNTESTED** (against `HEAD`'s older wording this would be PARTIAL: bind submits, but "the new binding is listed" is not asserted) |
| the-admin-view-shows-api-errors-as-messages | `admin_permissions.test.tsx` › `bind-409-surfaced-as-message-without-unhandled-rejection`, `users-tab-403-surfaced-as-text-danger` | yes [QA R5] | pass — COMPLIANT |
| a-non-admin-is-redirected-away-from-the-admin-view | `admin_permissions.test.tsx` › `non-admin-redirected-away-from-the-admin-view` | yes [QA R5] | pass — COMPLIANT |

**Coverage:** 25/26 scenarios covered by a test that ran and passed this session. 1 pending (`admin-binds-a-template-from-the-admin-view`).
Caveat: QA re-ran the full backend unit suite (270 passed), both user-management kind tests, and the two frontend view files this session. The full frontend suite (`corepack pnpm test`) was **not** re-run; implementer reports it red only on the untouched `Cluster.test.tsx`.

## Verification-Gap Audit

| Gap | Location | Shape | Evidence | Smallest Regression |
|-----|----------|-------|----------|---------------------|
| **Missing oracle on all 26 scenarios** | `acceptance.feature` (whole file); `briefing.md` R1–R10 | missing-oracle | `rg "#### Gates\|G[0-9]"` over the spec folder: 0 hits. No requirement carries a `#### Gates` block; no scenario has a `G<n>` with `CHECK`+`EXPECT`, `manual`, or `ABANDON`. The SDD ledger records the ruling "Do not retrofit `#### Gates`" (`.skillgrid/sdd/2026-10-19-user-management/progress.md`). | A regression in any happy path is caught only if someone runs the right pytest/vitest file; the gate auditor has no runnable oracle to bind to the scenario. |
| Audit read route never implemented | `backend/app/api/audit.py:20-23`; R7 | missing-adoption | `GET /v1/audit` raises `NotImplementedError_`; briefing R7 requires `GET /api/v1/admin/audit?actions=…`. Frontend `admin_permissions.test.tsx:90-97` mocks the 501. | The Audit page shows "audit log not available" for every admin. |
| 4.1 DataTables UI not built (working-tree R8/R9, ADR-0023) | `frontend/src/views/AdminPermissions/`, `frontend/src/components/`, `frontend/package.json` | missing-adoption | No `KubeDataTable.tsx`, `Privileges.tsx`, `Templates.tsx`, `Audit.tsx`; no `datatables.net-*` deps; UI is a tab strip with `BindModal`. | Admin cannot open a per-user privileges page; created bindings are not listed per user. |
| Playwright e2e for R9 absent | `frontend/e2e/` (only `auth-smoke.spec.ts`, `smoke.spec.ts`) | missing-adoption | tasks.md T-07 Files lists `frontend/e2e/admin_permissions.spec.ts`; not on disk. | The UI bind → kubeconfig download path is never driven against a real stack. |
| Seed test depends on collection order | `backend/tests/migrations/test_user_management_revision.py:205-217` (`fresh_engine` yields the shared `db.engine`, lines 159-164) | broken-verification | QA R2: `assert 17 == 4` when `tests/services/*` run first (they commit `builtin=True` rows like `viewer-28cf5023`); passes alone (R3) and in default order (R1). | Reordering, `-p randomly`, or xdist turns the seed check red without a code change — or, worse, a future guard that deletes leaked rows could mask a real seed-count bug. |
| Two-user Role GC verified only against a fake K8s client | `tests/services/test_permission.py:264` vs `tests/integration/test_bind_kind.py` | broken-verification (partial) | The kind test binds one user and checks last-referrer deletion only; "Role remains while a second user is bound" is asserted only against the mock. Scenario comment says "kind-gated". | A real-API label/selector mismatch in the GC query would delete a shared Role in production while the unit test stays green. |

## TDD Evidence Audit

> Per `_shared/references/strict-tdd.md` § TDD Cycle Evidence Table.
> `qa` cross-references each cell against git history and the working tree —
> the implementer's narrative is not the evidence.

Every hash below resolves (`git cat-file -t` → `commit`) and every test file exists on disk. In every ticket the tests and the implementation land in the **same** commit; there is no RED commit preceding GREEN. T-01, T-02, T-03 commit bodies carry a narrative "RED: N new tests failed on the pre-implementation tree" — a claim inside the GREEN commit, not a RED commit + exit code.

| Task | SATISFIES | RED (commit + exit) | GREEN (commit + exit) | TRIANGULATE (commit + exit) | REFACTOR (suite exit) | Verdict |
|---|---|---|---|---|---|---|
| TICKET-01 | builtin-templates-are-seeded-and-protected; malformed-template-rule-is-rejected; admin-lists-and-patches-a-user | none (narrative in `7e860022` body) | `7e860022` — exit 0 now [QA R1] | n/a | exit 0 [QA R1] | **MISSING_RED** |
| TICKET-02 | builtin-templates-are-seeded-and-protected | none (narrative in `3d94e54c` body) | `3d94e54c` (+`bcf8a025`, `a2075093`) — exit 0 alone/default order; exit 1 reordered [QA R1–R3] | n/a | exit 0 [QA R1] | **MISSING_RED** |
| TICKET-03 | admin-binds-…-in-the-cluster; rebinding-…-no-op; binding-with-a-mismatched-scope-…; unbinding-the-last-user-…; unbinding-a-missing-binding-…; binding-against-an-unreachable-cluster-…; disabled-user-is-rejected | none (narrative "RED->GREEN" in `177acf86` body) | `177acf86` — exit 0 [QA R1, R4] | in-commit (parametrized + kind) | exit 0 | **MISSING_RED** |
| TICKET-04 | admin-lists-and-patches-a-user; bootstrap-admin-…; non-admin-…; admin-creates-…; malformed-…; template-in-use-…; user-lists-…; user-with-no-bindings-sees-an-empty-list; a-user-never-sees-… | none | `114d762a` — exit 0 [QA R1] | in-commit | exit 0 | **MISSING_RED** |
| TICKET-05 | user-downloads-a-multi-cluster-kubeconfig; user-bound-to-one-cluster-…; user-with-no-bindings-gets-a-404; the-kubeconfig-never-embeds-a-token | none | `82869872` (+`384a796d`) — exit 0 [QA R1, R4] | in-commit | exit 0 | **MISSING_RED** |
| TICKET-06 | user-downloads-a-kubeconfig-from-my-access; my-access-shows-an-empty-state-for-no-bindings | none | `0ca343e0` — exit 0 [QA R5] | n/a | exit 0 [QA R5] | **MISSING_RED** |
| TICKET-07 | admin-binds-a-template-from-the-admin-view; the-admin-view-shows-api-errors-as-messages; a-non-admin-is-redirected-away-from-the-admin-view | none | `46282ddf` — exit 0 [QA R5] | n/a | exit 0 | **MISSING_RED** (and SATISFIES `admin-binds-…` text changed in the uncommitted spec after this commit — STALE against the working-tree scenario) |
| TICKET-08 | (verification ticket — no scenario) | n/a | `c2f5f015`, `3fe5cf54`, `bea190f1` | n/a | controller re-verify exit 0 | n/a |

**Summary:** 0/7 implementation tickets have complete TDD evidence (7 MISSING_RED; T-07 also STALE against the working-tree spec). T-08 is n/a.

## Assertion Quality Audit

> Re-scan of test files created/modified by this change.

| File | Line | Pattern | Evidence | Severity |
|---|---|---|---|---|
| `frontend/tests/views/admin_permissions.test.tsx` | 306 | vacuous companion assertion | `expect(screen.queryByText(/users/i, { selector: '.c-tabs' })).toBeNull()` — no element has class `.c-tabs`, so this holds whether or not the view renders. The real assertion (`findByText('Home page')`, line 305) carries the test. | SUGGESTION |
| `frontend/tests/views/permissions.test.tsx` | 97-99 | implementation-detail coupling | `expect(url).toMatch(/^blob:mock-/)` asserts the spy's own return shape, not the downloaded content; the filename assert at line 96 is the behavioral check. | WARNING |
| `frontend/tests/views/admin_permissions.test.tsx` | 154-160 | smoke-only (for the scenario it claims) | Marked "SATISFIES admin-binds-a-template-from-the-admin-view" but only asserts user names/subs render; no column headers, no Action controls. | WARNING |
| `backend/tests/migrations/test_user_management_revision.py` | 159-164, 217 | incomplete precondition (shared state) | `fresh_engine` is the shared `db.engine`, not a fresh DB; the count assert depends on prior tests not leaving `rbac_templates` rows. | WARNING (the run-and-fail itself is C5) |

No tautologies, ghost loops, or assertion-without-production-call found in the backend files read (`test_admin_users.py`, `test_permissions.py` my-access block, `test_kubeconfig.py`, `test_bind_kind.py`) or the two frontend view files.

**Summary:** 0 CRITICAL, 3 WARNING, 1 SUGGESTION.

## Changed-File Coverage

Coverage: n/a — no coverage tool configured (`testing.coverage` absent). Not run.

## Test Quality Audit

| Test | Contract Violated | Evidence |
|------|-------------------|----------|
| `test_user_management_revision.py::test_builtin_templates_are_seeded_and_protected` | test-claimed-path (fresh DB) | Fixture docstring claims "the Testcontainers PG after `db.create_all()`"; in practice it is the session-shared engine carrying other tests' rows (QA R2). |
| `admin_permissions.test.tsx` › `bind-submits-user-cluster-namespace-template` | test-claimed-path | Labeled under `admin-binds-a-template-from-the-admin-view`, but renders `BindModal` in isolation — not opened from the admin view, no listing assertion. |
| `test_permissions.py` bind/unbind block (`fake_k8s`) | complete-mocks (acceptable) | API tier uses a fake K8s client; the real-API behavior is separately covered by `test_bind_kind.py`. Not a violation — noted for the two-user GC half only (see gap table). |

**P0 triangulation:** bind, re-bind, scope guard, 502, GC, token-free kubeconfig, isolation, admin gate, disabled user each have ≥2 tests with different inputs (unit + API, or unit + kind). Migration seed has one test (plus the API built-in list test) — acceptable.

## Test Strategy Audit

**Available layers** (from `testing.layers`): not configured. Present in repo: unit, integration (Testcontainers + kind-gated), e2e (Playwright).

| Behavior | Assigned Layer | Degrade? | Duplicate Coverage? | Rationale |
|----------|---------------|----------|---------------------|-----------|
| RBAC object shape + labels in cluster | integration (kind) | no | no | Only a real API server proves rule normalization and labels. |
| Bind/unbind control flow (idempotency, 404/422/502) | unit (fake K8s) + API | no | intentional overlap service vs API | Service tests prove logic; API tests prove HTTP mapping. |
| Kubeconfig shape | unit (renderer) + API + kind (`kubectl config view`) | no | no | kubectl parse needs a real binary. |
| Migration | integration (Testcontainers PG) | no | no | Needs real Postgres DDL. |
| UI views | unit (Vitest + MSW) | yes — e2e planned (T-07) but absent | no | e2e missing; MSW is the only UI evidence. |

**Layer distribution:** ~87 unit/API (backend user-management files), 2 kind integration, 18 MSW view tests, 0 e2e. Reasonable for the backend risk profile; the UI lacks the planned e2e.

## Security Audit

**Mode:** Manual fallback (Mode B) — `security.trivy` not configured. Trivy was used as the Mode B dependency/secret scanner.

### Trivy Findings (Mode A)

N/A — `security.trivy.command` not set. See Mode B dependency audit below for the Trivy run used as the scanner.

**Trivy gate:** `fail_on: ""` → N/A

### Manual Findings (Mode B — when Trivy is not configured)

#### Secrets Archaeology

| Location | Type | Evidence | Severity |
|----------|------|----------|----------|
| — | — | `trivy fs --severity CRITICAL,HIGH --scanners vuln,secret .` reported no secrets. Kubeconfig output has no `token`/`tokenFile` (tests above). | none |

#### Dependency Audit

Command: `trivy fs --severity CRITICAL,HIGH --scanners vuln,secret --skip-dirs node_modules --skip-dirs frontend/node_modules --skip-dirs backend/.venv --quiet .` (exit 0, report-only).

| Dependency | CVE / Issue | Severity | Fix Available |
|------------|-------------|----------|---------------|
| `certifi@2026.7.22` (backend/uv.lock, production transitive) | GHSA-6q48-6c7w-9gw2 — emSign roots with compromised intermediate keys | CRITICAL | yes (2026.10.19) |
| `cryptography@47.0.0` (backend/uv.lock) | CVE-2026-69247 (PKCS#7 Bleichenbacher oracle) | HIGH | yes (50.0.0) |
| `cryptography@47.0.0` | CVE-2026-69249 (path-building DoS) | HIGH | yes (49.0.0) |
| `cryptography@47.0.0` | GHSA-537c-gmf6-5ccf (bundled OpenSSL) | HIGH | yes (48.0.1) |

`frontend/pnpm-lock.yaml`, `cli/go.mod`: 0 findings. None of these were introduced by the ticket commits: `cryptography 47.0.0` is pinned by `9ab53b83` (chore, macOS x86_64 wheel) and no ticket commit touches `backend/uv.lock` or `pyproject.toml`. Classified per Mode B (HIGH/CRITICAL with a fix in a production dependency) as **CRITICAL — pre-existing**.

#### OWASP Spot-Check

| File | OWASP Item | Pattern | Evidence |
|------|------------|---------|----------|
| `backend/app/services/permission.py:243-249` | A01 Broken Access Control (server-side file read crossing a privilege boundary) | `certificate-authority` path from the registry kubeconfig is opened as given and its bytes are base64'd into every bound user's downloaded kubeconfig | `with open(str(ca_path), "rb") as f: return ..., base64.b64encode(f.read())`. An admin (or anyone who can register a cluster) can point it at e.g. `/var/run/secrets/kubernetes.io/serviceaccount/token`; any non-admin bound to that cluster downloads it. Reachable; requires admin-level registration. |
| `backend/app/api/admin.py:72,97`; `backend/app/api/permissions.py:120-300` | A01 | admin gate | Every admin route calls `require_admin()` first; `GET /kubeconfig` and `GET /permissions/my-access` intentionally do not. Non-admin 403 and isolation covered by tests. OK. |
| `backend/app/core/security.py:199-204` | A07 Identification & Auth Failures | disabled user | `status == "disabled"` → same 401 as a missing user (no status enumeration). OK. |
| `backend/app/services/permission.py:227`; `kubeconfig_render.py:80` | A08 Software/Data Integrity | YAML parsing | `yaml.safe_load` / `yaml.safe_dump` only. OK. |
| `backend/app/services/permission.py` (bind) | A01 | RBAC write scope | Templates are admin-authored and can carry `verbs: ["*"]`; that is by design (ADR-0013), gated by `require_admin()`. Noted, not a finding. |

**Security verdict:** 4 findings — CRITICAL: 1 (certifi, pre-existing; cryptography HIGH ×3 rolled in as pre-existing dependency debt), WARNING: 1 (CA file-path read, W2), SUGGESTION: 0. A separate `security-review` pass (required by the `risky` floor) has **not** been run by this gate.

## Code Quality Gate

| Gate | Command | Threshold (config) | Actual | Result |
|------|---------|--------------------|--------|--------|
| Coverage (whole project) | not configured | 80 (default) | not measured | N/A |
| Changed-file coverage | not configured | 80 (default) | not measured | N/A |
| Mutation | not configured | 80 (default) | N/A | N/A |
| Lint (backend) | `uv run ruff check .` (what CI runs, `.github/workflows/ci.yaml:14`) | errors only | 27 errors (26 in this change's test files: E501 ×22, F841 ×1 `test_kubeconfig_kind.py:45`, E402 ×1, SIM115 ×1, + others; 1 pre-existing `wsgi.py:26`) | **FAIL** |
| Lint (frontend) | `task fe-build` (eslint) | errors only | 0 errors (controller re-verify) | PASS |
| Typecheck | `uv run mypy --strict` on changed `app/` modules; `task fe-build` (tsc) | errors only | 0 / 0 | PASS |
| P0 pass rate | P0 rows 1–12 | 100 (default) | 12/12 rows green in the gate run; row 8 failed once under reordering (C5) | PASS (gate run) — see C5 |
| P1 pass rate | P1 rows 13–21 | 95 (default) | 6/9 (rows 15, 17, 18 pending) = 67% | **FAIL** |
| Trivy security | not configured | report only | 1 CRITICAL, 3 HIGH (pre-existing) | N/A |
| Duplication (jscpd) | not configured (ran ad hoc: `jscpd --reporters console <25 changed app/src files>`) | report only | 1 clone · 0.26% | N/A (advisory) |

**Quality config status:** not configured — using defaults.

**Dead code (if configured):** N/A

**Duplication (if configured):** scoped to the 25 changed `backend/app` + `frontend/src` files; 1 clone · 0.26% — advisory (SUGGESTION).

## Duplication

> Scoped to the changed files. Advisory; `duplication.fail_on` not set.

**Command:** `jscpd --reporters console $(git diff --name-only a1f8298e..HEAD -- backend/app frontend/src)`

**Result:** 1 clone · 0.26% duplication — scope: COMPLETE (25 files, 4 formats)

| Files (lines) | Kind | Introduced? | Severity | Note |
|---------------|------|-------------|----------|------|
| `frontend/src/views/AdminPermissions/components/TemplateEditor.tsx:42-51` ~ `frontend/src/views/AdminPermissions/index.tsx:46-58` | exact | yes (T-07, `46282ddf`) | SUGGESTION | 10-line block repeated across the editor and the view; extract a shared helper if the 4.1 rework touches both. |

## State Drift

> `qa-gate.mjs` could not run its sub-checks: `node ~/.agents/skills/verification/qa/scripts/qa-gate.mjs .` returned `verdict: ERROR` with `state_drift`, `size_budget`, `adr_invariants` → exit 2 "script not found" (the gate resolves sub-scripts under the project's `.agents/` path, which does not exist here). Drift derived manually instead.

**Verdict:** DRIFT DETECTED (manual)

| Field | Stale (state.yaml) | Derived (spec zone) |
|-------|-------------------|---------------------|
| `pipeline.current_phase` | `executing` | `qa` (tickets 1–8 committed; this gate running) |

**Fix applied:** none — this run was instructed not to edit or commit outside `report.md`. Controller to set `current_phase: qa` (skill Step 11).

**Scope (from the guard's `SCOPE:` line):** UNREADABLE (guard script missing) → worked around by reading `.skillgrid/state.yaml` directly; manual derivation COMPLETE.

## Verification Scope

| Derivation | Scope | Stale? |
|---|---|---|
| Traceability matrix | COMPLETE (all 26 scenarios read from the working-tree `acceptance.feature`) | spec zone has uncommitted edits to `acceptance.feature`, `briefing.md`, `blueprint.md`, `tasks.md` made after T-06/T-07 landed |
| Verification-gap audit | COMPLETE (`git diff a1f8298e..HEAD` for `backend/app`, `frontend/src`, tests) | none |
| State Drift (9.5) | UNREADABLE (guard) → manual COMPLETE | n/a |
| Structure Drift (9.6) | skipped (`ship_drift`: "no --anticipated paths") | n/a |

**Stale-verification:** `STALE: none` for code — no prior QA verdict exists for this change, and this run's evidence (QA R1–R6) is current against `bea190f1`. The **spec** moved after the code: the working-tree R8/R9 + `admin-binds-a-template-from-the-admin-view` postdate `0ca343e0`/`46282ddf`.

## Floor

| Dimension | Verdict |
|---|---|
| Goal-backward verification (weakest truth) | UNVERIFIED (R7 audit read; R8 DataTable; R9 4.1 UI) |
| Traceability (weakest scenario) | UNTESTED (`admin-binds-a-template-from-the-admin-view`) |
| Verification-gap audit | CRITICAL (missing oracle on 26/26 scenarios) |
| TDD evidence (weakest ticket) | MISSING_RED (7/7) |
| Assertion quality audit (weakest finding) | WARNING |
| Changed-file coverage (weakest file) | N/A |
| Test quality audit | WARNING |
| Code-quality gates (weakest gate) | FAIL (backend lint; P1 pass rate) |
| Security audit | CRITICAL (pre-existing certifi CVE) + WARNING (CA file read) |
| Verification scope (composite) | COMPLETE (with the state-drift guard UNREADABLE, worked around manually) |

**FLOOR:** FAIL — several dimensions sit at their FAIL value: goal-backward (UNVERIFIED truths), traceability (UNTESTED scenario), verification-gap (missing-oracle CRITICAL), TDD evidence (MISSING_RED), and code-quality gates (lint, P1). The gate cannot render above FAIL.

## Findings

> Open WARNING/SUGGESTION findings below are meant to be auto-appended to
> `.skillgrid/WINDOWS.md`. **Not appended this run** — this run was told to write only
> `report.md` and not commit. `.skillgrid/WINDOWS.md` does not exist yet; the rows to add
> (W001–W011) are listed at the end of this section for the controller.

### CRITICAL (must fix before merge)

- **C1 — Missing oracle on every scenario.** `acceptance.feature` has 26 scenarios and 0 `#### Gates` / `G<n>` blocks (`rg "#### Gates|G[0-9]"` over the spec folder → 0 hits). Under the skill's FAIL row, "a missing-oracle gap (a happy-path scenario with no `G<n>`)" is a FAIL criterion; at least 20 of the 26 are happy paths.
- **C2 — Scenario UNTESTED:** `admin-binds-a-template-from-the-admin-view` has no covering test. The scenario requires a DataTable with Username/Email/Permission/Type/Action, a privileges page, and the binding listed after save; the code has none of these (`frontend/src/views/AdminPermissions/` contains only `index.tsx`, `components/BindModal.tsx`, `components/TemplateEditor.tsx`).
- **C3 — Truths UNVERIFIED.** R7 audit read (`backend/app/api/audit.py:20-23` is still a 501 stub, wrong path `/v1/audit` vs `/api/v1/admin/audit`); R8 `KubeDataTable` (absent); R9 4.1 User List / Privileges / Templates / Audit pages + Playwright e2e `frontend/e2e/admin_permissions.spec.ts` (absent). R7's audit read was required in the committed spec too, so this is not only a spec-amendment gap.
- **C4 — MISSING_RED on TICKET-01..07.** Tests and implementation land in the same commit for `7e860022`, `3d94e54c`, `177acf86`, `114d762a`, `82869872`, `0ca343e0`, `46282ddf`; no RED commit or recorded RED exit code. T-01..03 carry RED narratives in the commit body only.
- **C5 — A test ran and failed this session.** `backend/tests/migrations/test_user_management_revision.py::test_builtin_templates_are_seeded_and_protected` → `AssertionError: assert 17 == 4` (line 217) when run after `tests/services/*` (QA R2, exit non-zero). It passes alone (QA R3) and in default order (QA R1). Root cause: `fresh_engine` (lines 159-164) yields the shared session engine, and service tests commit `builtin=True` template rows that are never cleaned up.
- **C6 — Backend lint gate FAIL.** `uv run ruff check .` (the CI command) → 27 errors, 26 of them in this change's test files (e.g. `tests/integration/test_kubeconfig_kind.py:45` F841, `tests/services/test_permission_generate_kubeconfig.py:308` E402, `:311` SIM115, 22× E501). CI's `ruff check . && mypy app` step would fail.
- **C7 — P1 pass rate 67% < 95% (default).** Plan rows 15 (audit read), 17 (KubeDataTable), 18 (4.1 admin UI) pending.
- **C8 — Dependency CVE with a fix in a production dependency (pre-existing).** `certifi 2026.7.22` GHSA-6q48-6c7w-9gw2 (CRITICAL, fix 2026.10.19) and `cryptography 47.0.0` ×3 HIGH (fixes 48.0.1–50.0.0) in `backend/uv.lock`. Not introduced by the ticket commits (`cryptography` pinned in `9ab53b83`). Trivy gate is N/A (no `fail_on`), and AGENTS.md calls Trivy advisory-only; the Mode B classification is CRITICAL regardless.

### WARNING (should fix before archive)

- **W1 — Spec amended after code, uncommitted.** `briefing.md`, `blueprint.md`, `acceptance.feature`, `tasks.md` are modified in the working tree (+112/−73) with a new untracked `adr.md` (ADR-0023 review). T-06/T-07 were built to the earlier spec. Commit the spec zone (spec-zone-first rule) and re-slice the 4.1 UI work, or revert the amendment.
- **W2 — Server-side file read into user-downloadable kubeconfig.** `backend/app/services/permission.py:243-249` opens the registry kubeconfig's `certificate-authority` path as given and embeds the bytes for every bound user. An admin-registered path such as the pod's service-account token would be disclosed to non-admin users. Normalize to `-data` at registration, or restrict/validate the path.
- **W3 — Order-dependent migration fixture.** `test_user_management_revision.py:159-164` `fresh_engine` is not fresh (see C5); make it truncate `rbac_templates` or use a dedicated database.
- **W4 — Two-user Role GC only against the fake K8s client.** `test_bind_kind.py` covers last-referrer deletion only; the "Role remains while another user is bound" half is mocked (`test_permission.py:264`). The scenario comment says kind-gated.
- **W5 — Smoke-only test labeled as the admin-bind scenario.** `admin_permissions.test.tsx:154-160` asserts names render, not the columns or Action controls.
- **W6 — Implementation-detail assertion.** `permissions.test.tsx:97-99` asserts the blob-URL spy's return shape.
- **W7 — State pointer drift + QA guard scripts unresolvable.** `.skillgrid/state.yaml` `current_phase: executing` (should be `qa`); `qa-gate.mjs` cannot find `state-drift-check.mjs` / `skill-size-budget.mjs` / ADR invariants from the project root.
- **W8 — Working-tree AGENTS.md drops the config table** (uncommitted condensation). HEAD still lists `KUBEDASH_PLUGIN_SERVER`; committing that condensation as-is would undo R10's env-row requirement.

### SUGGESTION (nice to have)

- **S1 — Vacuous companion assertion** `admin_permissions.test.tsx:306` (`.c-tabs` selector matches nothing).
- **S2 — Duplicated 10-line block** `TemplateEditor.tsx:42-51` ~ `AdminPermissions/index.tsx:46-58` (jscpd, introduced by `46282ddf`).
- **S3 — Configure the gate.** Add `quality:`, `testing.runner`, `testing.coverage`, `commands.lint`, `security.trivy` to `.skillgrid/config.yaml` (`skillgrid:onboarding`) so coverage/lint/Trivy become measured gates instead of ad-hoc runs.

**WINDOWS.md rows pending (not written):**
`| W001 | 2026-10-19-user-management | WARNING | Spec amended after code (R8/R9 4.1 DataTables), uncommitted | qa-auto | 2026-10-21 | open |`
`| W002 | 2026-10-19-user-management | WARNING | permission.py:243-249 reads certificate-authority file path into user-downloadable kubeconfig | qa-auto | 2026-10-21 | open |`
`| W003 | 2026-10-19-user-management | WARNING | Migration seed test fixture is order-dependent (shared engine) | qa-auto | 2026-10-21 | open |`
`| W004 | 2026-10-19-user-management | WARNING | Two-user Role GC verified only against fake K8s | qa-auto | 2026-10-21 | open |`
`| W005 | 2026-10-19-user-management | WARNING | admin_permissions users-tab test is smoke-only for its scenario | qa-auto | 2026-10-21 | open |`
`| W006 | 2026-10-19-user-management | WARNING | permissions.test.tsx asserts blob-URL spy shape | qa-auto | 2026-10-21 | open |`
`| W007 | 2026-10-19-user-management | WARNING | state.yaml phase drift; qa-gate sub-scripts not found | qa-auto | 2026-10-21 | open |`
`| W008 | 2026-10-19-user-management | WARNING | Working-tree AGENTS.md drops KUBEDASH_PLUGIN_SERVER config row | qa-auto | 2026-10-21 | open |`
`| W009 | 2026-10-19-user-management | SUGGESTION | Vacuous .c-tabs assertion in admin_permissions.test.tsx:306 | qa-auto | 2026-10-21 | open |`
`| W010 | 2026-10-19-user-management | SUGGESTION | 10-line clone TemplateEditor.tsx ~ AdminPermissions/index.tsx | qa-auto | 2026-10-21 | open |`
`| W011 | 2026-10-19-user-management | SUGGESTION | Configure quality/testing/lint/trivy keys in config.yaml | qa-auto | 2026-10-21 | open |`

## Gate Decision

**Verdict:** FAIL

**Reasoning:** The backend core is strong: the full unit suite (270) and both kind integration tests passed this session, and bind/idempotency/GC/502/token-free kubeconfig are each proven at the real-API layer. But the skill's FAIL table is met on several independent criteria: missing `G<n>` oracles on every happy-path scenario (C1), one UNTESTED scenario (C2), UNVERIFIED truths R7/R8/R9 (C3), MISSING_RED on all seven implementation tickets (C4), a test that ran and failed (C5, order-dependent), and failing lint and P1 gates (C6, C7). Any one of these makes the gate FAIL.

**On the missing-oracle finding (for the controller to rule):** the 26 scenarios do have runnable oracles in practice. Each one except `admin-binds-a-template-from-the-admin-view` maps to a named pytest or Vitest function, most docstrings say `SATISFIES <scenario>`, and each ticket's `Fails-when` line in `tasks.md` names the command. The SDD ledger also recorded a deliberate ruling not to retrofit `#### Gates`. So C1 is mostly a process/format gap: the tests exist, but the spec never binds them as `G<n>` CHECK/EXPECT lines the gate can run. The table still treats it as FAIL, and I have not softened it. Resolving it means authoring `#### Gates` per requirement, pointing at the test IDs in the traceability matrix above, and that cannot be waived inline because the traceability oracle is part of the floor. Even if C1 were ruled process-only, C2–C7 would each still hold the verdict at FAIL.

**Open items (if CONCERNS):** n/a (FAIL). Path to resolution, in order:
1. Decide the spec: commit the working-tree R8/R9 amendment and slice the 4.1 DataTables UI as new tickets, or revert it. Either way, implement or explicitly descope the R7 audit read (C3).
2. Author `#### Gates` (`G<n>` CHECK + EXPECT) for R1–R10, bound to the test IDs in the traceability matrix (C1).
3. Fix `fresh_engine` isolation (C5), `ruff` errors in the new test files (C6), add a kind two-user GC assertion (W4).
4. Bump `certifi`/`cryptography` under an ADR/ASSUMPTIONS note (C8; pre-existing, may be split to its own change).
5. MISSING_RED (C4) cannot be fixed retroactively. It needs a human WAIVE of that criterion, with the accepted risk recorded, or RED-first commits for any re-done tickets.
6. Run the `risky`-floor `security-review` pass (W2 is its first lead).

**Waiver (if WAIVED):** none.

## Human Override

> A human decision always overrides this machine verdict.
> An epic that fails its criteria with no human decision is recorded as **not accepted** — never as silently accepted.

**Human decision (fill in):** <accept / accept-with-open-items / reject> — <name> — <date>

<!-- reflect completes this half at archive time -->

## Final-State Facts

**Shipped:** <what actually shipped>
**Base branch:** <base-branch> · **Chain strategy:** <strategy>
**Integration:** <merged @ <commit> | PR <url> | kept branch <name>> (from ship context)

## Gates

| Gate | Result |
|------|--------|
| Ship gate | ✅ success + `diff -r` empty (or: blocked — {reason}) |
| QA gate | ✅ {PASS \| WAIVED \| CONCERNS — human override recorded} |
| Verdict gate (advisory) | {accepted \| accepted-with-open-items \| rejected} — recorded, not enforced |

## Decisions

**Every entry MUST cite a source** — a file:line, a commit, a ticket ID, or a scenario name. No source = undiagnosed, not a learning.

| Decision | Tradeoff | Why | Source |
|----------|----------|-----|--------|
| <choice made> | <what was given up> | <why it won> | <file:line / commit / ADR / ticket> |

## Lessons

| Lesson | Root Cause | Do Differently | Source |
|--------|-----------|----------------|--------|
| <what to do differently> | <why it went wrong — root, not symptom> | <the concrete change> | <file:line / commit / ticket> |

## Patterns

| Pattern | Reuse | Source |
|---------|-------|--------|
| <named reusable approach / convention> | <when a future change should apply it> | <file:line / commit / ticket> |

## Surprises

| Surprise | Signal | Source |
|----------|--------|--------|
| <non-obvious gotcha / edge case / behavior> | <what the evidence shows> | <file:line / commit / scenario> |

## Environment Retro

**Written by `skillgrid:environment-retro` (a reflect sub-phase), not qa.** Improvements to the *agent environment*, never the code. A finding appears only where its "Use when" fired; a clean session leaves this empty.

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| <navigation \| automated checks \| coding standards \| steering no-ops \| tool economy \| information access> | <what to change + why> | <linter rule / pre-commit / CI job / ARCHITECTURE.md pointer / steering file / tooling> | <file:line / commit / tool call / session symptom> |

## Acceptance Verdict

**Verdict:** accepted | accepted-with-open-items | rejected

**Grounding:** <goal from briefing.md + the Goal-Backward Verification / Traceability Matrix evidence above that supports the verdict>

**Reasoning:** <2–3 sentences: what drove the verdict>

## Open Items (→ next change)

- <item + path to resolution> (or "None")

## Web-cache promotion candidates

<!-- Written by `skillgrid:reflect` Step 3.7 (retro half), not qa. -->

### Candidate: <title, from the cache entry>

- **Concept home:** <where the concept would live, e.g. `decisions/` or `invariants/`>
- **Why:** <why this is worth promoting — reusable across changes, not true for this change alone>
- **sources:** <the cache source — context7 | exa | deepwiki | fetch | manual>
- **Claim:** <the checkable claim, one falsifiable statement>
- **Cache id + URL:** <id> · <url>

## Prior-Change Follow-Through

| Prior open item (from previous archived change) | Addressed by this change? | Evidence |
|--------------------------------------------------|---------------------------|----------|
| <item> | yes / no / partially | <commit / file:line / scenario, or "still open"> |

## Move Evidence (from ship context)

**From:** `.skillgrid/specs/2026-10-19-user-management/` → **To:** `.skillgrid/xarchive/2026-10-19-user-management/`
**`diff -r` readback:** <empty → PASS | verbatim output → FAIL>

## Overrides / Waivers / Contradictions

- <QA waiver, human CONCERNS override, size-exception, or "None">
- <Unrankable contradiction: both statements + sources + when written — or "None">

## Lineage (observation IDs)

Every artifact read this close, for traceability:

- briefing: {id}
- blueprint: {id}
- tasks: {id}
- ship: {id}
- report (QA half): {id}
- research / findings / ADRs: {ids or "none"}
