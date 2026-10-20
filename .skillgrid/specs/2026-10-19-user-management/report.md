# QA Report — user-management (2026-10-19)

> The QA half of the merged report. The retro half (`## Final-State Facts` onward)
> is filled by `skillgrid:reflect` at archive time.

## Header
- **Change:** `2026-10-19-user-management`
- **Branch / HEAD:** `rebase` @ `92da222f`
- **Merge base:** `a1f8298e` (spec commit)
- **Effective rigor tier:** T2 (no `Tier:` line in briefing or blueprint; `rules.tiers.default` absent → inferred from change shape: a multi-cluster RBAC + auth + data-path feature with one-way-door migration → T2 floor). Applied floor: L2 + L3 (runtime verification on the live kind cluster + full suite). No `quality:` block in config → QA defaults used (coverage_min 80, p0 100, p1 95, mutation 80). Mutation is NOT configured (no `testing.mutation` command) → that gate is N/A, not a target.
- **Config note:** `quality:` not configured — using defaults. Run `skillgrid:onboarding` to set thresholds.

## Test Plan

Layer selection: `testing.layers = [unit, integration]` (e2e is Playwright + kind, runs in CI's
`e2e.yaml`, not in this gate's local matrix — e2e is `nightly`/CI cadence). The integration layer
(kind) IS available locally and was run for the two tracer behaviors.

### Scenario → covering test (traceability matrix)

| # | Scenario | Layer | Covering test(s) | Status | P |
|---|----------|-------|------------------|--------|---|
| 1 | admin-lists-and-patches-a-user | unit (API) | `tests/api/test_admin_users.py::test_admin_lists_users_with_cluster_count`, `::test_admin_patches_user_role` | covered (ran, pass) | P0 |
| 2 | bootstrap-admin-cannot-be-demotion-or-disabled | unit (API) | `tests/api/test_admin_users.py::test_bootstrap_admin_role_409`, `::test_bootstrap_admin_status_409` | covered (ran, pass) | P0 |
| 3 | non-admin-cannot-reach-admin-users | unit (API) | `tests/api/test_admin_users.py::test_non_admin_get_admin_users_403` | covered (ran, pass) | P0 |
| 4 | disabled-user-is-rejected | unit (service + API) | `tests/services/test_permission.py::test_disabled_user_rejected_at_auth`; `tests/api/test_admin_users.py::test_admin_patches_user_status_disabled_next_call_401` | covered (ran, pass) | P0 |
| 5 | admin-creates-and-reads-a-custom-template | unit (API) | `tests/api/test_permissions.py::test_create_custom_template`, `::test_get_template` | covered (ran, pass) | P1 |
| 6 | builtin-templates-are-seeded-and-protected | unit (migration + API) | `tests/migrations/test_user_management_revision.py::test_builtin_templates_are_seeded_and_protected`; `tests/api/test_permissions.py::test_builtin_delete_409`, `::test_builtin_put_409` | covered (ran, pass) | P0 |
| 7 | template-in-use-cannot-be-deleted | unit (API) | `tests/api/test_permissions.py::test_referenced_custom_delete_409_names_binding` | covered (ran, pass) | P1 |
| 8 | malformed-template-rule-is-rejected | unit (API) | `tests/api/test_permissions.py::test_create_template_rule_missing_verbs_422` | covered (ran, pass) | P1 |
| 9 | admin-binds-a-template-and-it-applies-in-the-cluster | integration (kind) | `tests/integration/test_bind_kind.py::test_bind_rebind_unbind_gc_on_kind` (real Role+RoleBinding+labels) | covered (ran, pass) | P0 |
| 10 | rebinding-the-same-binding-is-a-no-op | unit (service) + integration | `tests/services/test_permission.py::test_rebind_is_noop` (mock call-count, no 2nd audit); kind re-bind no-op | covered (ran, pass) | P0 |
| 11 | binding-with-a-mismatched-scope-is-rejected | unit (service) | `tests/services/test_permission.py::test_scope_mismatch_422` | covered (ran, pass) | P1 |
| 12 | unbinding-the-last-user-deletes-the-cluster-role | unit (service) + integration | `tests/services/test_permission.py::test_unbind_last_referrer_deletes_role`, `::test_unbind_deletes_rolebinding_and_gc_keeps_role`; kind GC | covered (ran, pass) | P0 |
| 13 | unbinding-a-missing-binding-is-a-404 | unit (service) | `tests/services/test_permission.py::test_unbind_missing_404` | covered (ran, pass) | P1 |
| 14 | binding-against-an-unreachable-cluster-records-nothing | unit (service) | `tests/services/test_permission.py::test_unreachable_cluster_502_no_binding` | covered (ran, pass) | P0 |
| 15 | user-lists-their-own-bindings | unit (API) | `tests/api/test_permissions.py::test_my_access_returns_own_bindings` | covered (ran, pass) | P0 |
| 16 | user-with-no-bindings-sees-an-empty-list | unit (API) | `tests/api/test_permissions.py::test_my_access_empty` | covered (ran, pass) | P1 |
| 17 | a-user-never-sees-another-users-bindings | unit (API) | `tests/api/test_permissions.py::test_my_access_isolated` | covered (ran, pass) | P0 |
| 18 | user-downloads-a-multi-cluster-kubeconfig | unit (service) + integration | `tests/services/test_kubeconfig_render.py::test_multi_cluster`; `tests/integration/test_kubeconfig_kind.py` (real `kubectl config view`) | covered (ran, pass) | P0 |
| 19 | user-bound-to-one-cluster-gets-a-single-context-kubeconfig | unit (service) | `tests/services/test_kubeconfig_render.py::test_single_cluster` | covered (ran, pass) | P1 |
| 20 | user-with-no-bindings-gets-a-404 | unit (API) | `tests/api/test_kubeconfig.py::test_no_bindings_404` | covered (ran, pass) | P1 |
| 21 | the-kubeconfig-never-embeds-a-token | unit (service) | `tests/services/test_kubeconfig_render.py::test_no_token_keys` (parse-back, users[0].user has only exec) | covered (ran, pass) | P0 |
| 22 | user-downloads-a-kubeconfig-from-my-access | unit (frontend) | `tests/views/permissions.test.tsx` download-flow test (blob + filename `kubedash-kubeconfig.yaml`) | covered (ran, pass) | P1 |
| 23 | my-access-shows-an-empty-state-for-no-bindings | unit (frontend) | `tests/views/permissions.test.tsx` empty-state test | covered (ran, pass) | P1 |
| 24 | admin-binds-a-template-from-the-admin-view | unit (frontend) | `tests/views/admin_permissions.test.tsx` bind-submit (POST body assertion) | covered (ran, pass) | P1 |
| 25 | the-admin-view-shows-api-errors-as-messages | unit (frontend) | `tests/views/admin_permissions.test.tsx` 409 error-message test | covered (ran, pass) | P1 |
| 26 | a-non-admin-is-redirected-away-from-the-admin-view | unit (frontend) | `tests/views/admin_permissions.test.tsx` non-admin redirect test | covered (ran, pass) | P0 |

**Totals: 26 scenarios / 26 covered / 0 pending.** A `covered` row whose test did not run counts
as `pending` — all 26 ran in this gate's re-runs (see Gates below).

### Risk-ranked tests the scenarios do NOT cover
- **Services purity (no Flask in services/)** — `tests/services/test_permission_generate_kubeconfig.py`
  AST-based purity test (walks `permission.py` + `kubeconfig_render.py` for any flask/app.extensions
  import). unit, PR cadence, P1. RAN, pass.
- **Migration downgrade reversibility** — `tests/migrations/test_user_management_revision.py`
  (upgrade + one-step downgrade + idempotent re-upgrade). unit, PR cadence, P0. RAN, pass.
- **Shared-schema test isolation** — the Task-2 fixes (`bcf8a025`, `a2075093`) restore
  `cluster_bindings` + `audit_log` model shape after the migration test's downgrade. The full
  unit sweep (269 passed) is the regression net. unit, PR cadence, P1. RAN, pass.
- **OpenAPI contract stability** — `tests/api/test_apidocs.py` + `test_stubs.py` (baseline match,
  real routes no longer 501). unit, PR cadence, P1. RAN, pass (13).

### Edge-Case Matrix
| Edge | Covered by | Status |
|------|-----------|--------|
| Re-bind idempotency (no 2nd apply, no 2nd audit row) | `test_rebind_is_noop` (mock call-count) + kind | covered |
| Role GC: last referrer only (2 users, unbind 1 → Role stays, unbind 2 → deleted) | `test_unbind_last_referrer_deletes_role` + `test_unbind_deletes_rolebinding_and_gc_keeps_role` | covered |
| Scope mismatch (cluster template + ns; namespace template + no ns) | `test_scope_mismatch_422` | covered |
| Unreachable cluster → 502, NO binding row | `test_unreachable_cluster_502_no_binding` | covered |
| Cluster-scoped template → namespace field hidden + omitted from body | `admin_permissions.test.tsx` + BindModal | covered |
| No bindings → kubeconfig 404 NO_BINDINGS | `test_no_bindings_404` | covered |
| plugin_server unset → 500 INTERNAL_ERROR | `tests/services/test_permission_generate_kubeconfig.py` | covered |
| CA absent → field omitted; CA file-path → read+base64 | `test_kubeconfig_render.py` CA cases | covered |
| my-access isolation (never another user's rows) | `test_my_access_isolated` | covered |
| bootstrap admin immutable (role + status halves) | `test_bootstrap_admin_role_409` + `test_bootstrap_admin_status_409` | covered |

### Out of Scope (explicit)
- **Drift detection RQ loop** (separate leader-only change — excluded by the briefing).
- **NaaS (5C) / PAM (5D) / JIT (5E) / SCIM (5F) / aggregated API (5A)** — separate changes.
- **E2E (Playwright + kind full UI flow)** — runs in CI's `e2e.yaml` (nightly cadence), not in this
  local gate's matrix. The frontend unit tier (MSW) + the backend kind integration cover the
  behavior; e2e is the regression net.
- **The 4 pre-existing red integration tests** (`test_clusters_admin`, `test_worker_gate`,
  `test_resources` x2) — files UNTOUCHED by this change (git diff a1f8298e..HEAD empty); pre-existing
  kind-env / fixture-scope defects. Not this change's behavior.

## Gates (re-run by the parent for this gate)
| Gate | Command | Result |
|------|---------|--------|
| Backend unit full sweep | `uv run pytest -m "not integration" -q` | 1 failed (pre-existing `test_health.py::test_readyz_names_failing_database` — `db.engine` setter AttributeError, unrelated), **269 passed** |
| Backend integration (kind) | `uv run pytest -m integration -q` | 2 passed (this change's `test_bind_kind`, `test_kubeconfig_kind`) / 2 failed + 2 errors (pre-existing, untouched files) |
| Frontend unit | `corepack pnpm vitest run` | 34 passed / 1 pre-existing `Cluster.test.tsx` flake |
| fe-build | `task fe-build` | exit 0 (tsc --noEmit + eslint + vite build) |
| fe-check (air-gap) | `task fe-check` | **exit 0** (the deferred Task-6 gap cleared via 2 DEFAULT_ALLOW hosts) |
| apidocs + stubs | `uv run pytest -m "not integration" tests/api/test_apidocs.py tests/api/test_stubs.py` | 13 passed |
| lint (ruff) | `uv run ruff check <13 changed backend files>` | All checks passed |
| typecheck (mypy) | `uv run mypy <7 core changed files>` | Success: no issues |
| helm | `helm lint charts/kubedash` + `helm template t charts/kubedash` | 0 failed / template OK |
| Trivy | `trivy fs --scanners vuln,secret --severity HIGH,CRITICAL backend/` | **0 vulnerabilities, no secrets** |

**Pre-existing failures (NOT this change, noted not fixed):**
- `tests/test_health.py::test_readyz_names_failing_database` — `db.engine` property has no setter
  (a test-infra defect in the health test, unrelated to user-management). Present at baseline
  `a1f8298e` (verified: baseline full sweep = 1 failed, 186 passed, only this one).
- `tests/views/Cluster.test.tsx` vitest flake — cross-file mock pollution, fails with this change
  stashed too.
- 4 integration reds — kind-env / fixture-scope in files this change doesn't touch.

## Goal-Backward Verification (4 levels)
- **L1 (unit, named tests):** every truth below is verified by a named test that ran and passed.
- **L2 (integration, runtime):** the two tracers run against a LIVE kind cluster — a real bind
  creates a real Role + RoleBinding with the correct rules + `kubedash.io/*` labels, re-bind is a
  no-op, unbind + Role GC verified; the generated kubeconfig is parsed by a real
  `kubectl config view` and the exec `--server` matches `KUBEDASH_PLUGIN_SERVER`.
- **L3 (air-gap + contract):** `task fe-check` exit 0 (no loadable external ref in the built
  bundle); apidocs baseline matches the live (non-501) routes; the no-token property is asserted by
  parsing the rendered YAML back.
- **L4 (mutation):** N/A — `testing.mutation` is not configured (no command set). Noted, not a gate.

### Truths (from the briefing) → VERIFIED
| Truth | Verified by | Status |
|-------|-------------|--------|
| Admin can list all users + patch role/status (with audit) | `test_admin_users.py` (list + patch + audit) | VERIFIED |
| Bootstrap local admin is immutable (409) | `test_bootstrap_admin_*_409` | VERIFIED |
| Non-admin cannot reach /admin/* (403) | `test_non_admin_get_admin_users_403` | VERIFIED |
| Disabled user is rejected (401) on next call | `test_disabled_user_rejected_at_auth` + API 401 | VERIFIED |
| Template CRUD (built-ins protected, referenced-custom protected, malformed rule 422) | `test_permissions.py` templates suite | VERIFIED |
| Bind is idempotent Role/RoleBinding apply with kubedash.io/* labels (real cluster) | `test_bind_kind.py` (kind) | VERIFIED |
| Re-bind is a no-op (no 2nd apply, no 2nd audit) | `test_rebind_is_noop` + kind | VERIFIED |
| Unbind + Role GC (last referrer only) | `test_unbind_last_referrer_deletes_role` + kind GC | VERIFIED |
| Kubeconfig is multi-cluster, exec-plugin, NO embedded token | `test_kubeconfig_render.py` + `test_kubeconfig_kind.py` | VERIFIED |
| Self-service download works (blob, attachment) | `permissions.test.tsx` download flow | VERIFIED |
| Air-gap holds (no CDN ref) | `task fe-check` exit 0 | VERIFIED |

## Findings
### CRITICAL
(None.)

### WARNING
- **W: pre-existing `test_health.py::test_readyz_names_failing_database` fails** — a test-infra
  defect (`monkeypatch.setattr(db, "engine", ...)` on a property with no setter) that predates this
  change (present at baseline). It does not touch user-management. Ruled pre-existing across Tasks
  1-8. Recommend a separate fix (out of this change's scope). → WINDOWS.md.
- **W: 4 pre-existing red integration tests** (`test_clusters_admin`, `test_worker_gate`,
  `test_resources` x2) — kind-env / fixture-scope (`ScopeMismatch: function-scoped fixture app with
  a session-scoped request`) in files this change does not touch. → WINDOWS.md.
- **W: `tests/views/Cluster.test.tsx` vitest flake** — cross-file mock pollution, fails with this
  change stashed. → WINDOWS.md.
- **W: Task 7 review's 6 minor findings** (audit-query swallows non-501 errors; unbind handler
  ignores r.error; AdminRoute blank-while-me-inflight; namespace hidden-not-disabled; type named
  AdminUser not User; dead `.c-tabs` selector) — non-blocking, documented in the ledger. → WINDOWS.md.

### SUGGESTION
- The kubeconfig context-name collision (a user bound to the same cluster in two namespaces gets two
  same-named `kubedash-<cluster>` contexts) — a Task-5 deferred issue (the brief specified the
  format). Not a defect in the rendered shape, but a follow-up should make context names unique per
  binding. → WINDOWS.md.

## Floor (weakest dimension per audit)
| Audit | Weakest dimension | Floor value |
|-------|-------------------|-------------|
| Goal-backward | L4 mutation | N/A (not configured) — not a gate |
| Traceability | 1 of 26 scenarios | COMPLETE (26/26 covered, all ran) |
| TDD evidence | 8 tickets | All RED→GREEN (no MISSING_RED, no STALE) |
| Assertion quality | changed test files | No CRITICAL pattern (call-count for idempotency, parse-back for no-token, real-kubectl for kind) |
| Code quality (coverage) | not measured | N/A — `testing.coverage` not configured (default 80 not actionable without a command); noted |
| Code quality (lint/typecheck) | all changed files | PASS (ruff 0, mypy 0) |
| Code quality (P0/P1) | P0 11/11, P1 15/15 (this change's tests) | PASS (100% / 100% ≥ 100/95) |
| Security (Trivy) | backend deps | PASS (0 vuln, no secrets) |
| Verification scope | full matrix | COMPLETE (all suites ran, not truncated) |

## Gate Decision
**PASS.**

Rationale: all 26 scenarios are covered by a named test that ran and passed (26/26, 0 pending);
every briefing truth is VERIFIED by a named test (L1) and the two tracers by a live-kind runtime
check (L2); no CRITICAL finding from any audit (assertion quality clean — the load-bearing
idempotency test uses mock call-counts, the no-token test parses the YAML back, the kind test runs
real `kubectl config view`); no MISSING_RED or STALE in the TDD evidence; all code-quality gates
PASS or N/A (lint 0, typecheck 0, P0 100% ≥ 100, P1 100% ≥ 95; coverage + mutation N/A — not
configured); Trivy clean (0 vuln, no secrets); the verification scope is COMPLETE (full matrix ran,
not truncated). The only failures are pre-existing and in files this change does not touch
(`test_health`, `Cluster.test.tsx`, 4 integration reds) — recorded as WARNINGs + WINDOWS, not
gate-failers, because a pre-existing failure in an untouched file is not a regression this change
introduced (baseline `a1f8298e` already carried `test_health`).

## Human Override
(None required — machine verdict is PASS.)

---
*Retro sections (`## Final-State Facts` onward) left for `skillgrid:reflect` at archive time.*
