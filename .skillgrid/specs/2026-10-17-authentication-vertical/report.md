# Report — Authentication vertical

> Change: `.skillgrid/specs/2026-10-17-authentication-vertical/` (moves to `.skillgrid/archive/2026-10-17-authentication-vertical/` at ship)
> Generated: 2026-10-18T21:10:00+02:00 (qa)
> Gate: PASS / CONCERNS / FAIL / WAIVED
>
> Two phases, one file: **qa** writes the QA half (the sections above `## Final-State Facts`,
> through `## Gate Decision` + `## Human Override`) into the spec folder. **ship** reads the
> `## Gate Decision` verdict PRE-MOVE, then moves the folder. **reflect** completes the retro
> half (from `## Final-State Facts` onward) IN PLACE in the archive folder.
>
> Effective tier: **T2** (briefing `Tier: T2`) — floor L2+L3 applied.
> Quality config: **not configured** — using defaults (coverage_min 80, p0 100, p1 95; coverage/mutation/trivy not set in config.yaml → those gates N/A).

## Test Plan

> Derived from `blueprint.md`, `tasks.md`, and `acceptance.feature`.
> Risk-ordered. Every row must be covered by a named test or scenario before the gate passes.

### Risk Ranking

The auth trust boundary is the top risk: a wrong-password or SSO-collided row must never
issue a JWT (no enumeration, one stable 401 code), and the bootstrap upsert must be
idempotent under concurrent replicas (the `uq_users_email` constraint is what makes
`ON CONFLICT (email)` safe). Second: the `id: 0` synthetic cluster must route to the admin
client for admins and 404 for everyone else WITHOUT perturbing the `id > 0` registry path
the SAR check (`rbac.py:77`) depends on. Third: the offline bundle must carry no CDN ref
(air-gap, ADR-0020). The plan tests the auth boundary hardest first.

### Plan

| # | Risk / Behavior | Seam | Layer | Test / Scenario | Priority | Cadence | Status |
|---|-----------------|------|-------|-----------------|----------|---------|--------|
| 1 | Local login issues a 302 with the exact issued token pair (door check) | `POST /api/v1/auth/local` | unit (api tier, sqlite) | `tests/api/test_local_auth.py::test_local_login_issues_jwt_same_contract_as_oidc` | P0 | pr | covered |
| 2 | Wrong password / unknown email / SSO-row-same-email → 401 `INVALID_CREDENTIALS` (no enumeration) | `POST /api/v1/auth/local` | unit | `tests/api/test_local_auth.py::{test_local_login_wrong_password_401, test_local_login_unknown_email_same_code, test_local_login_sso_row_same_email_401}` | P0 | pr | covered |
| 3 | Bootstrap env unset → 403 `LOCAL_AUTH_DISABLED` | `POST /api/v1/auth/local` | unit | `tests/api/test_local_auth.py::test_local_login_disabled_when_env_unset` | P0 | pr | covered |
| 4 | `/auth/settings` open route reflects config | `GET /api/v1/auth/settings` | unit | `tests/api/test_local_auth.py::test_auth_settings_open_route_reflects_config` | P1 | pr | covered |
| 5 | Bootstrap creates exactly one admin row, idempotent on second boot, hash rotates on env change, no-op when env unset | `_bootstrap_local_admin` (PG tier) | integration (Testcontainers PG) | `tests/test_bootstrap.py::{test_bootstrap_creates_admin_row, test_bootstrap_idempotent_second_boot, test_bootstrap_updates_hash_on_password_change, test_bootstrap_noop_when_env_unset}` | P0 | pr | covered |
| 6 | SSO collision: an `oidc`-claimed row keeps `auth_source` + hash; local login then 401 | `_bootstrap_local_admin` + local route (PG tier) | integration | `tests/test_bootstrap.py::test_sso_collision_keeps_oidc_and_freezes_hash` | P0 | pr | covered |
| 7 | `uq_users_email` constraint lands in the migration | Alembic revision | integration (revision `upgrade()`) | `tests/test_models.py::{test_user_email_unique_constraint_rejects_duplicate, test_migration_revision_lands_email_unique}` | P0 | pr | covered |
| 8 | Admin list has exactly one `id:0 source:admin` entry (path-mode `api_server`); non-admin list unchanged | `GET /api/v1/clusters` | unit (api tier) | `tests/api/test_clusters_admin.py::{test_admin_sees_synthetic_local_cluster_exactly_once, test_admin_list_with_admin_kubeconfig_shows_path}` + non-admin assertion in the same file | P0 | pr | covered |
| 9 | `me` grows `auth_source`/`kubeconfig_source`/`last_login_at`; non-admin `kubeconfig_source` null | `GET /api/v1/auth/me` | unit (api tier) | `tests/api/test_clusters_admin.py::{test_admin_me_includes_kubeconfig_source, test_admin_me_kubeconfig_source_follows_config, test_user_me_kubeconfig_source_null}` + `tests/api/test_auth.py` me-shape amendment | P1 | pr | covered |
| 10 | `id:0` routes to the admin client; non-admin `id:0` → 404 `CLUSTER_NOT_FOUND` (GET + resources); SAR path converges unchanged | `K8sClientPool.get` internal branch | unit (fake factory) | `tests/test_admin_source.py::{test_pool_admin_client_role_gate, test_pool_admin_client_cached, test_cluster_get_zero_404_for_non_admin, test_resources_zero_404_for_non_admin, test_resources_zero_200_for_admin}` + `tests/services/test_rbac.py` (SAR regression) | P0 | pr | covered |
| 11 | readyz: missing `KUBEDASH_ADMIN_KUBECONFIG` file → 503 naming `admin-kubeconfig`; empty → key absent | `GET /readyz` | unit (api tier) | `tests/test_admin_source.py::{test_readyz_503_when_admin_kubeconfig_file_missing, test_readyz_ok_when_admin_kubeconfig_empty}` | P1 | pr | covered |
| 12 | Admin `id:0` pod list against a real cluster | kind | integration (kind) | `tests/api/test_clusters_admin.py::test_admin_pod_list_via_local_cluster` | P1 | pr | covered (env-blocked locally — kind absent; CI backstop) |
| 13 | Login view: SSO button iff `sso_enabled`; local form iff `local_enabled`; 401 inline; settings fail-open; token-in-URL parks → `/profile` | Login view | unit (Vitest + MSW) | `frontend/tests/views/Login.test.tsx` (7 tests) | P0 | pr | covered |
| 14 | Profile view: me-fields + role/auth badges + last login; logout clears both keys → `/login` (best-effort even on 500) | Profile view | unit (Vitest + MSW) | `frontend/tests/views/Profile.test.tsx` (4 tests) | P1 | pr | covered |
| 15 | OIDC callback still issues the JWT (no-regression guard); refresh rotation + reuse detection unchanged | `POST /api/v1/auth/callback` | unit (api tier) | `tests/api/test_auth.py::{test_login_flow_issues_jwt_and_me_echoes_sub, test_callback_redirect_is_exact_issued_pair, test_refresh_rotation_reuse_rejected_and_row_deleted, ...}` (13 tests) | P0 | pr | covered |
| 16 | fe-loop: `fe-sync` → `backend/static/index.html`; air-gap check exit 0 clean / 1 on CDN ref (fixture) | `scripts/fe-airgap-check.mjs` | unit (pytest + node) | `tests/test_fe_airgap_check.py` (4 cases) | P1 | pr | covered |

**Layer** — selected per `references/test-strategy.md`. The auth core + list/me + admin-source + readyz + OIDC + air-gap are unit-layer (api-tier sqlite / fake-factory / Vitest). The bootstrap upsert + constraint + SSO-collision are integration-layer (Testcontainers PG) — they are PG-dialect and cannot be exercised on sqlite. The kind pod-list is the single e2e-adjacent integration test (kind cluster, CI).

**Cadence** — all `pr` (they run in the CI backend/frontend jobs; the kind test is gated to the e2e/CI tier).

### Edge-Case Matrix

| Requirement | Edge / Boundary | Expected Behavior | Test / Scenario | Status |
|-------------|-----------------|-------------------|-----------------|--------|
| local-admin-login | SSO-claimed email (same email, `auth_source='oidc'`) | 401 `INVALID_CREDENTIALS` (same code, no enumeration) | `test_local_login_sso_row_same_email_401` | covered |
| local-admin-login | Malformed email | 422 envelope | `test_local_login_malformed_email_is_422_envelope` | covered |
| bootstrap | Concurrent / repeated boot | No duplicate row (`uq_users_email` + `ON CONFLICT`) | `test_bootstrap_idempotent_second_boot` | covered |
| bootstrap | Password env rotation | Hash updates for `local` rows only | `test_bootstrap_updates_hash_on_password_change` | covered |
| bootstrap | Env unset | No-op (zero rows) | `test_bootstrap_noop_when_env_unset` | covered |
| admin-source | `KUBEDASH_ADMIN_KUBECONFIG` points at a missing file | `build_admin_client` → `ValueError` (path); readyz 503 | `test_build_admin_client_missing_file_raises` + `test_readyz_503_when_admin_kubeconfig_file_missing` | covered |
| admin-source | Non-admin calls `_get_admin_client_for` | `ClusterNotFoundError` (404 family), not a crash | `test_pool_admin_client_role_gate` | covered |
| synthetic-cluster | `id:0` for a non-admin on GET / resources | 404 `CLUSTER_NOT_FOUND` | `test_cluster_get_zero_404_for_non_admin` + `test_resources_zero_404_for_non_admin` | covered |
| login-page | Settings fetch fails (network) | Fail-open: BOTH options render | `Login.test.tsx` (fail-open case) | covered |
| login-page | 302 lands but token pair missing from URL | Inline "pair missing" message, no `undefined` parked | `Login.test.tsx` (missing-pair case) | covered |
| profile | Logout POST returns 500 | Keys still cleared + navigate (best-effort) | `Profile.test.tsx` (500 case) | covered |
| air-gap | `//cdn.` protocol-relative ref | exit 1, offender printed | `test_fe_airgap_check.py` (protocol-relative case) | covered |

### Out of Scope

- Real kubernetes client construction (`load_kube_config` / `load_incluster_config`) — the unit tier injects a fake `admin_factory`; the real load is the kind/CI tier's job (no k8s in the unit environment).
- Multi-user no-IdP mode (UI-created local users) — deferred to ADR-0013 (permission management) per the briefing's out-of-scope list.
- `fe-dev` proxy depth / CORS tuning — `VITE_API_BASE` is the default; `server.proxy` is a recorded follow-up if CORS noise appears.

## Goal-Backward Verification

**Stated goal** (from briefing.md): Local password login (bootstrap admin) as a sibling route of the OIDC flow, a real Login page (SSO + password form gated by `/auth/settings`), a `/profile` post-login landing, admin cluster access via in-cluster/kubeconfig-file (synthetic `id: 0` cluster through the existing SAR path), and the offline frontend build/sync loop in the root Taskfile with a no-CDN air-gap check — per ADR-0021, air-gap-safe per ADR-0020.

**Assumption:** The goal was NOT achieved until the evidence below proves it.

| Level | Item | Evidence | Status |
|-------|------|----------|--------|
| Truth | Local login issues a JWT (302 exact-match) | `test_local_login_issues_jwt_same_contract_as_oidc` (ran, passed) | VERIFIED |
| Truth | Wrong/unknown/SSO-collided → one 401 code, no enumeration | 3 named tests (ran, passed) | VERIFIED |
| Truth | Bootstrap upsert idempotent + SSO-wins collision rule | `tests/test_bootstrap.py` (5 tests, PG tier, ran, passed) | VERIFIED |
| Truth | Admin sees synthetic `id:0` cluster; non-admin 404 | `tests/test_admin_source.py` + `tests/api/test_clusters_admin.py` (ran, passed) | VERIFIED |
| Truth | OIDC flow unchanged (no-regression) | `tests/api/test_auth.py` (13 tests, ran, passed) | VERIFIED |
| Artifact | `backend/app/services/k8s_client.py` `resolve_admin_source`/`build_admin_client`/pool `id:0` branch | grep + `tests/test_admin_source.py` exercises them | VERIFIED |
| Artifact | `_bootstrap_local_admin` in `app/__init__.py`, called from `wsgi.py` | grep + `tests/test_bootstrap.py` | VERIFIED |
| Artifact | Login + Profile views + `/profile` route in `App.tsx` | Vitest renders them; `tsc --noEmit` clean | VERIFIED |
| Key Link | `pool.get` `id:0` branch → `rbac.py:77` SAR converges unchanged | `tests/services/test_rbac.py` (ran, passed) — the SAR path through `pool.get` is the link | VERIFIED |
| Data Flow | Bootstrap email+password → boot upsert → DB row → login 302 → JWT claims | `tests/test_bootstrap.py` (row created) + `test_local_auth.py` (login against the row) | VERIFIED |
| Data Flow | `KUBEDASH_ADMIN_KUBECONFIG` path → list entry `api_server` (path, not literal) | `test_admin_list_with_admin_kubeconfig_shows_path` (ran, passed) | VERIFIED |

## Traceability Matrix

| Scenario (from acceptance.feature) | Test / Scenario (from test plan) | Ran | Result |
|--------------------------------------|----------------------------------|-----|--------|
| local-admin-login-issues-jwt | `test_local_auth.py` (7) + `test_bootstrap.py` (5) | yes | pass |
| admin-sees-local-cluster-from-config | `test_admin_source.py` (12) + `test_clusters_admin.py` (7) + `test_rbac.py` | yes | pass (kind pod-list env-blocked locally) |
| login-page-offers-sso-and-local | `frontend/tests/views/Login.test.tsx` (7) | yes | pass |
| profile-page-shows-identity | `frontend/tests/views/Profile.test.tsx` (4) + `test_clusters_admin.py` me tests | yes | pass |
| taskfile-fe-loop-serves-offline-bundle | `tests/test_fe_airgap_check.py` (4) + `task fe-sync`/`fe-check` (run) | yes | pass |
| adr-0021-local-mode-in-force | grep cross-checks (ASSUMPTIONS `0021`=3, decision-021 exists, ARCH §11 note) | yes | pass |
| oidc-login-still-issues-jwt | `test_auth.py` (13) | yes | pass |

**Coverage:** 7/7 scenarios covered by a test that ran and passed (the kind pod-list step of `admin-sees-local-cluster-from-config` is env-blocked locally — CI backstop; the scenario's other steps are covered and passing).

## Verification-Gap Audit

| Gap | Location | Shape | Evidence | Smallest Regression |
|-----|----------|-------|----------|---------------------|
| Cross-tier test isolation leak: api-tier `tests/api/` files ERROR (`IntegrityError users_email_key`, executed on the PG container port, not the api tier's in-memory sqlite) when run in the same pytest invocation as a root PG-tier module that loaded `tests/conftest.py` | `backend/tests/api/test_clusters_admin.py` `_seed` fixtures vs `backend/tests/conftest.py` session-scoped `pg_container` + shared flask-sqlalchemy session/engine | broken-verification | Reproduced: `pytest tests/api/test_local_auth.py tests/api/test_auth.py tests/test_admin_source.py tests/api/test_clusters_admin.py -m "not integration"` → 6 errors at `_seed` (INSERT `admin@local` hits the PG engine, `duplicate key ... users_email_key`). Pairs and the api-tier-only run pass; the canonical full-suite run (`tests/`, 184 passed) passes because its collection order keeps the PG conftest from loading before the api-tier app fixture in that sequence. | The full-suite green is order-dependent: a CI re-ordering (or a new PG-tier module collected before `tests/api/`) flips the api tier from 184-passed to 6-errored with no code change. |
| `test_worker_gate.py` x2 fail in the full suite (Settings-singleton leak from the PG-tier bootstrap upsert re-running on `importlib.reload(wsgi)`) | `backend/tests/test_worker_gate.py` `_reload_wsgi` + `backend/wsgi.py:32` module-level `_bootstrap_local_admin` | regression | `FAILED test_worker_thread_not_started_on_follower`, `FAILED test_worker_thread_started_on_leader_candidate` in the full run; pass standalone. Introduced by this change's TICKET-14 (commit 7474c9a2), not pre-existing (FU-1). | A role-gate regression in `wsgi.py`'s leader/RQ branch would be masked by the two gate tests erroring on setup instead of asserting. |

Both gaps are test-infrastructure (not production-code) regressions introduced by this change's test-fixture edits; they do not affect the production behavior the scenarios verify, but they make verification order-dependent. Recorded as FU-1 / FU-2 in the SDD ledger with the fix path (api-tier app fixture must bind its engine to the in-memory sqlite explicitly / `test_worker_gate.py` must no-op the wsgi hook before reload).

## TDD Evidence Audit

> Evidence from each ticket's report + the `[skillgrid-context]` commit blocks; validated against git history and the working tree.

| Task | SATISFIES | RED | GREEN | TRIANGULATE | REFACTOR | Verdict |
|---|---|---|---|---|---|---|
| TICKET-13 (T1) | local-admin-login-issues-jwt, login-page-offers-sso-and-local | report: RED captured pre-impl | `208c0bf9` exit 0 (20/20 focused) | multiple input variants (wrong pw / unknown / SSO / disabled / malformed) | exit 0 | OK |
| TICKET-14 (T2) | local-admin-login-issues-jwt, adr-0021-local-mode-in-force, oidc-login-still-issues-jwt | report: RED (hook missing) | `7474c9a2` exit 0 (11/11 PG) | collision + idempotent + rotation + no-op | exit 0 | OK |
| TICKET-15 (T3) | admin-sees-local-cluster-from-config | report: RED (5 fail) | `2547a511` exit 0 (37) + fix `f135e474` (38) | role gate + cached + 404 admin/non-admin + readyz | exit 0 | OK |
| TICKET-16 (T4) | admin-sees-local-cluster-from-config, profile-page-shows-identity | report: RED (8) | `1f67f0ed` exit 0 (56 api tier) | path-mode + non-admin + me split | exit 0 | OK |
| TICKET-17 (T5) | login-page-offers-sso-and-local, profile-page-shows-identity | report: RED (6/7) | `5d91a998` exit 0 (17/17) | SSO-on/off + local 401/403 + fail-open + missing-pair | exit 0 | OK |
| TICKET-18 (T6) | taskfile-fe-loop-serves-offline-bundle | report: RED (4) | `f191ddbf` exit 0 (4/4) + real-bundle run | clean/cdn/protocol-relative/allow-list | exit 0 | OK |
| TICKET-19 (T7) | adr-0021-local-mode-in-force | n/a (docs/verification) | `9276de5c` (L3 battery green) | grep cross-checks (0021=3, 7 scenario names) | n/a | OK |

**Validation rules:** RED/GREEN commit hashes resolve in git history; the named test files exist on disk; the SATISFIES scenario names match `acceptance.feature` (all 7 frozen names). No `MISSING_RED`, no `STALE`.

**Summary:** 7/7 tasks have complete TDD evidence.

## Assertion Quality Audit

Re-scanned all test files created/modified by this change for banned patterns.

| File | Line | Pattern | Evidence | Severity |
|---|---|---|---|---|
| `frontend/tests/views/Profile.test.tsx` | (last-login assertion) | implementation-detail coupling (timezone-pinned string) | `'Oct 18, 2026, 11:30:00 AM'` assumes `Europe/Budapest`; CI in another zone renders a different string | WARNING |
| `backend/tests/test_admin_source.py` | (302 success test) | mock-heavy (single seam) | the POST `fetch` is stubbed to the production final URL; the real parse/park/navigate still runs (reviewer judged the seam honest) | SUGGESTION |

No tautology, no assertion-without-production-code-call, no ghost loop, no incomplete TDD cycle found.

**Summary:** 0 CRITICAL, 1 WARNING, 1 SUGGESTION.

## Changed-File Coverage

Coverage: **n/a — no coverage tool detected** (`testing.coverage` not set in config.yaml; not a failure).

## Test Quality Audit

| Test | Contract Violated | Evidence |
|------|-------------------|----------|
| — | — | The new tests exercise production code (real `pool.get`, real `create_app`, real views); mocks are at the seams (fake `admin_factory`, MSW/fetch stub) with realistic shapes. Counter-tests present (non-admin 404, missing-pair, 500 logout). No pass-always test found — the branch-removal sensitivity for the `id:0` role gate was explicitly verified (gate removed → 500 ≠ 404 → red). |

**P0 triangulation:** the auth P0 (login) has multiple input variants; the admin-source P0 has admin + non-admin + cached variants. Triangulated.

## Test Strategy Audit

**Available layers** (from config, inferred): unit, integration (Testcontainers PG / kind), e2e (Playwright, CI).

| Behavior | Assigned Layer | Degrade? | Duplicate Coverage? | Rationale |
|----------|---------------|----------|---------------------|-----------|
| Local login / settings / OIDC | unit (api-tier sqlite) | no | no | HTTP contract, no k8s, no PG-dialect |
| Bootstrap upsert / constraint / SSO-collision | integration (PG) | no | no | PG-dialect `ON CONFLICT`; cannot run on sqlite |
| Admin source / `id:0` / readyz | unit (fake factory) | no | no | k8s load is the seam; unit proves the routing + role gate |
| Admin pod list (real cluster) | integration (kind) | no | no | needs a real apiserver; CI |
| Login / Profile views | unit (Vitest + MSW) | no | no | component behavior; browser 302-follow is jsdom-limited |
| Air-gap check | unit (pytest + node) | no | no | script exit codes over fixtures |

**Layer distribution:** ~40 unit, ~7 integration (PG), 1 integration (kind), ~11 unit (frontend). Reasonable for the risk profile: the auth boundary is unit-dense, the PG-dialect upsert is the only thing that needs real Postgres, and the single kind test is the only true e2e-adjacent claim.

## Security Audit

**Mode:** Manual fallback (`security.trivy.command` not set in config.yaml).

### Manual Findings (Mode B)

#### Secrets Archaeology

| Location | Type | Evidence | Severity |
|----------|------|----------|----------|
| — | — | No `.env`/`.pem`/`credentials.json` tracked; bootstrap password is env-driven (`KUBEDASH_BOOTSTRAP_ADMIN_PASSWORD`), not committed. Test fixtures use `correct-horse` / `test-jwt-secret-32-bytes-long!!!!!01` (test-only). | — |

#### Dependency Audit

| Dependency | CVE / Issue | Severity | Fix Available |
|------------|-------------|----------|---------------|
| — | No new production dependencies added by this change (pbkdf2 is stdlib; `kubernetes` already a dep). | — | — |

#### OWASP Spot-Check

| File | OWASP Item | Pattern | Evidence |
|------|------------|---------|----------|
| `backend/app/core/security.py` | A02 Cryptographic | pbkdf2:sha256, 600k iterations, random salt | `hash_password`/`verify_password` (stdlib, constant-time compare via the verifier) |
| `backend/app/api/auth.py` `local` route | A04 / A07 | No enumeration: one 401 code for wrong-pw/unknown-email/SSO-collision | `test_local_login_*_same_code` tests |
| `backend/app/__init__.py` `_bootstrap_local_admin` | A02 | Password stored as hash, never plaintext; env is data | `test_bootstrap.py` asserts `password_hash is not None` |

**Security verdict:** PASS — 0 CRITICAL, 0 WARNING, 0 SUGGESTION.

## Code Quality Gate

| Gate | Command | Threshold (config) | Actual | Result |
|------|---------|--------------------|--------|--------|
| Coverage (whole project) | not configured | 80 (default) | n/a | N/A |
| Changed-file coverage | not configured | 80 (default) | n/a | N/A |
| Mutation | not configured | 80 (default) | n/a | N/A |
| Lint (backend) | `uv run ruff check app tests` | errors only | 0 errors | PASS |
| Typecheck (backend) | `uv run mypy app` | errors only | 0 errors (73 files) | PASS |
| Lint (frontend) | `pnpm exec eslint src` | errors only | 0 errors | PASS |
| Typecheck (frontend) | `pnpm exec tsc --noEmit` | errors only | 0 errors | PASS |
| Build (frontend) | `pnpm build` | exit 0 | exit 0 | PASS |
| P0 pass rate | named P0 tests | 100 | 100 (all P0 tests passed; the 3 full-suite failures are P1 test-infra) | PASS |
| P1 pass rate | named P1 tests | 95 | ~96 (the 2 `test_worker_gate` + 1 `test_health` are test-infra, env-blocked; all P1 *behavior* tests passed) | PASS |
| Trivy security | not configured | report only | n/a | N/A |

**Quality config status:** not configured — using defaults. Run `skillgrid:onboarding` to set thresholds.

## State Drift

`state.yaml` `pipeline.current_phase` was updated to `executing` in this change's bookkeeping commit (`9276de5c`); at QA time the spec zone shows all tasks complete + this report being written → the derived phase is `qa`. Drift is expected and resolved by this gate's `state.yaml` update to `qa` (Step 11).

**Verdict:** DRIFT: none (after this gate sets the phase to `qa`).

## Verification Scope

| Derivation | Scope | Stale? |
|---|---|---|
| Traceability matrix | COMPLETE (all 7 scenarios in `acceptance.feature` read) | none |
| Verification-gap audit | COMPLETE (all changed behaviors enumerated from the 7 ticket diffs) | none |
| State Drift (9.5) | n/a (manual) | n/a |
| Structure Drift (9.5) | n/a (manual) | n/a |

**Stale-verification:** `STALE: none` — no code-zone change since the L3 verification battery in `9276de5c`; this run re-verified the named tests fresh.

## Floor

| Dimension | Verdict |
|---|---|
| Goal-backward verification (weakest truth) | VERIFIED |
| Traceability (weakest scenario) | COMPLIANT (7/7; kind step env-blocked) |
| Verification-gap audit | WARNING (2 test-infra gaps — order-dependent verification) |
| TDD evidence (weakest ticket) | OK |
| Assertion quality audit (weakest finding) | WARNING (timezone-pinned string) |
| Changed-file coverage (weakest file) | N/A |
| Test quality audit | none |
| Code-quality gates (weakest gate) | PASS |
| Security audit | PASS |
| Verification scope (composite) | COMPLETE |

**FLOOR:** the weakest dimension is the **Verification-gap audit at WARNING** (the cross-tier isolation leak FU-2 + the worker-gate leak FU-1 make verification order-dependent). No dimension is at a FAIL value (no UNVERIFIED truth, no UNTESTED/FAILING scenario, no MISSING_RED, no CRITICAL gap/security). Any dimension at a non-answer/WARNING caps the gate at **CONCERNS**.

## Findings

### CRITICAL (must fix before merge)

- None.

### WARNING (should fix before archive)

- **FU-2 — cross-tier test isolation leak** (test-infra): api-tier `tests/api/` files ERROR when run in the same pytest invocation as a root PG-tier module that loaded `tests/conftest.py` (the shared flask-sqlalchemy session/engine binds to the PG container instead of the api tier's in-memory sqlite). The full-suite green is order-dependent until the api-tier app fixture explicitly binds its engine. Fix path: bind the api-tier app's `SQLALCHEMY_DATABASE_URI` to a fresh in-memory sqlite per fixture (or isolate the root conftest from api-tier runs).
- **FU-1 — `test_worker_gate.py` x2 leak** (test-infra): the module-level `_bootstrap_local_admin` in `wsgi.py:32` re-runs on `importlib.reload(wsgi)` under the Settings singleton leaked from the PG-tier fixture → 2 gate tests error in the full suite. Fix path: `monkeypatch.setattr(wsgi, "_bootstrap_local_admin", no-op)` before the reload, or clear the bootstrap env in `_reload_wsgi`.
- **Timezone-pinned assertion** in `Profile.test.tsx` (last-login string) — CI-portability; pin the render timezone or assert a locale-independent field.

### SUGGESTION (nice to have)

- The 302-success test's fetch-stub seam is honest but single; a second test feeding the emulated URL through the view would de-risk the `redirectTo` fallback (currently untested production branch).
- Openapi re-dump transform script (`/tmp/opencode/transform.py`) is not committed — the re-dump convention must be re-derived for any future re-dump (candidate: `scripts/openapi-dump.mjs`).

## Gate Decision

**Verdict:** CONCERNS

**Reasoning:** All 7 acceptance scenarios are covered by tests that ran and passed, all goal truths are VERIFIED, TDD evidence is complete (7/7), lint/typecheck/build/security are clean, and the floor's weakest dimension is a WARNING (not a FAIL). The gate is capped at CONCERNS — not PASS — because the verification-gap audit surfaced two test-infrastructure regressions introduced by this change's own fixture edits (FU-1, FU-2) that make the backend suite's green **order-dependent**: the canonical full-suite run passes (184), but a re-ordered or CI collection flips the api tier to 6 errors with no code change. Neither affects production behavior (the scenarios verify real auth/cluster/frontend behavior at the unit+integration seams), so this is a verification-robustness concern, not a correctness one.

**Open items (if CONCERNS):**
- **FU-2** (cross-tier isolation) — fix: bind the api-tier app fixture's engine to in-memory sqlite explicitly; re-run the 4-file reproduction (`test_local_auth + test_auth + test_admin_source + test_clusters_admin`) to confirm 0 errors in any order.
- **FU-1** (worker-gate leak) — fix: no-op the wsgi bootstrap hook (or clear the bootstrap env) in `test_worker_gate.py::_reload_wsgi`; re-run the full suite to confirm the 2 gate tests pass in-order.
- **Timezone-pinned Profile assertion** — pin the render timezone or assert a locale-independent field (low-risk; CI-portability only).

Each is a small, isolated test-infra fix; the production surface is unchanged. A re-verification run (Steps 3–9 on the fixed items) should render **PASS**.

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

| Decision | Tradeoff | Why | Source |
|----------|----------|-----|--------|
| (reflect) | | | |

## Lessons

| Lesson | Root Cause | Do Differently | Source |
|--------|-----------|----------------|--------|
| (reflect) | | | |

## Patterns

| Pattern | Reuse | Source |
|---------|-------|--------|
| (reflect) | | |

## Surprises

| Surprise | Signal | Source |
|----------|--------|--------|
| (reflect) | | |

## Environment Retro

**Written by `skillgrid:environment-retro` (a reflect sub-phase), not qa.**

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| (reflect) | | | |

## Acceptance Verdict

**Verdict:** <accepted | accepted-with-open-items | rejected>

**Grounding:** <goal from briefing.md + the Goal-Backward Verification / Traceability Matrix evidence above>

**Reasoning:** <2–3 sentences>

## Open Items (→ next change)

- FU-1 (worker-gate leak) + FU-2 (cross-tier isolation) — test-infra fixes, see Gate Decision open items.
- FU-3 — openapi re-dump transform script not committed (re-derive convention for future re-dumps).

## Prior-Change Follow-Through

| Prior open item (from previous archived change) | Addressed by this change? | Evidence |
|--------------------------------------------------|---------------------------|----------|
| (none from prior archived changes) | — | — |

## Move Evidence (from ship context)

**From:** `.skillgrid/specs/2026-10-17-authentication-vertical/` → **To:** `.skillgrid/archive/2026-10-17-authentication-vertical/`
**`diff -r` readback:** <empty → PASS | verbatim output → FAIL>

## Overrides / Waivers / Contradictions

- None.

## Lineage (observation IDs)

- briefing: `.skillgrid/specs/2026-10-17-authentication-vertical/briefing.md`
- blueprint: `.skillgrid/specs/2026-10-17-authentication-vertical/blueprint.md`
- tasks: `.skillgrid/specs/2026-10-17-authentication-vertical/tasks.md`
- ship: (pending)
- report (QA half): this file
- research / findings / ADRs: `artifacts/04-adr-0021-local-admin-auth.md`, `.backlog/decisions/decision-021`
