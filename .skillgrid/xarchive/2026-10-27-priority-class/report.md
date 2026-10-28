# Report — Priority Classes (4.1 parity list + detail, moved to Other Resources)

> Change: `.skillgrid/specs/2026-10-27-priority-class/`
> Generated: 2026-10-28T11:15:00+01:00 (qa)
> Gate: **PASS**
>
> Tier: T2 (briefing + blueprint headers) — floor L2 (full backend unit suite +
> `corepack pnpm test` + `task fe-build` + `task fe-check`) + runtime backstops.
> Change classification: `standard` (additive R4 kind row; no trust boundary, no
> migration, no new dependency).
> quality: not configured in config.yaml — using defaults (coverage_min 80,
> mutation disabled, trivy disabled, duplication advisory). Run `skillgrid:onboarding`
> to set thresholds.

## Test Plan

### Risk Ranking

The single risk surface is the R4 kind string (one new key on a shared route: a
`priority-class` singular drift or a leaked `namespace` param would be invisible
until e2e) and the view↔API seam (the list/detail fetch URLs must carry no
namespace for this cluster-scoped kind). The plan pins the kind string at the API
tier (FakeK8s + the kind backstop) and the seam at the view tier (MSW exact-path
capture); the SAR/binding machinery is reused, not rebuilt, so its risks are
regression risks covered by the full suite.

### Plan

| # | Risk / Behavior | Seam | Layer | Test / Scenario | Priority | Cadence | Status |
|---|-----------------|------|-------|-----------------|----------|---------|--------|
| 1 | `priorityclasses` list 200 (R4 route, to_dict shape) | API `/clusters/<id>/resources/priorityclasses` | unit | `tests/api/test_resources.py::test_list_priorityclasses_200` | P0 | pr | covered |
| 2 | `?namespace=` accepted and ignored (cluster-scoped) | same route | unit | `tests/api/test_resources.py::test_list_priorityclasses_ignores_namespace` | P0 | pr | covered |
| 3 | `?name=` 1-item / `[]` on 404 (get_secret contract) | same route | unit | `tests/api/test_resources.py::test_get_priority_class_by_name` | P0 | pr | covered |
| 4 | SAR gate BEFORE read; ns `None`; group `scheduling.k8s.io` (ADR-0004) | `rbac.can` | unit | `tests/api/test_resources.py::test_list_priorityclasses_sar_denied` | P0 | pr | covered |
| 5 | Binding gate 404 CLUSTER_NOT_FOUND | `_cluster_for` | unit | `tests/api/test_resources.py::test_priorityclasses_binding_404` | P0 | pr | covered |
| 6 | Singular `priorityclass` is NOT a kind (4.1 route name) | `_KINDS` | unit | `tests/api/test_resources.py::test_priorityclass_kind_singular_rejected` | P0 | pr | covered |
| 7 | `K8sClient.list_priority_classes` ignores namespace; 502 on transport | `K8sClient` | unit | `tests/services/test_k8s_client_priorityclasses.py::test_list_priority_classes_ignores_namespace` + `::test_list_priority_classes_maps_500_to_unreachable` | P1 | pr | covered |
| 8 | `K8sClient.get_priority_class` `[]` on 404; 502 otherwise | `K8sClient` | unit | `tests/services/test_k8s_client_priorityclasses.py::test_get_priority_class_404_returns_empty_list` + `::test_get_priority_class_other_api_error_maps_to_unreachable` | P1 | pr | covered |
| 9 | List view: columns, exact URL, no namespace, name link | view fetch URL | unit (Vitest+MSW) | `tests/views/priority_classes.test.tsx::list-renders-priority-classes` | P0 | pr | covered |
| 10 | List view: no cluster → "No cluster selected." + no fetch | store | unit | `tests/views/priority_classes.test.tsx::list-no-cluster-state` | P1 | pr | covered |
| 11 | List view: RBAC error line, never blank | query.error | unit | `tests/views/priority_classes.test.tsx::list-error-state` | P1 | pr | covered |
| 12 | Detail view: exact `?name=` URL (no namespace), metadata + full-object YAML | view fetch URL | unit | `tests/views/priority_class_data.test.tsx` (detail-renders-priority-class-yaml) | P0 | pr | covered |
| 13 | Detail view: empty items → not-found state (pinned copy) | items == [] | unit | `tests/views/priority_class_data.test.tsx` (detail-not-found-state) | P1 | pr | covered |
| 14 | Detail view: missing name → NO fetch + error line | `enabled` guard | unit | `tests/views/priority_class_data.test.tsx` (detail-missing-name-client-error) | P1 | pr | covered |
| 15 | Nav move: leaf under Other Resources at the new path; old path a real route (not stub) | `_nav.tsx` + routes | unit | `tests/nav.test.tsx` (4.1 contract order, updated) + `tests/views/Stub.test.tsx` (real-view path set, updated) + `priority_classes.test.tsx` render | P0 | pr | covered |
| 16 | Old path `/security/priorityclass` resolves to nothing | route table | unit | `tests/views/Stub.test.tsx` (stub route set has no `/security/priorityclass`) | P0 | pr | covered |
| 17 | e2e smoke path moved, title byte-identical | `ui-smoke.spec.ts` | e2e (CI kind) | `frontend/e2e/ui-smoke.spec.ts` entry at the new path | P1 | pr (CI) | covered (runs in `e2e.yaml`) |
| 18 | Real client list on a live cluster (backstop) | R4 route → real `K8sClient` | integration (kind) | `tests/api/test_resources.py::test_list_priorityclasses_on_kind` | P0 | pr (CI kind) + local (run 2026-10-28) | covered |
| 19 | No regression in the R4 machinery / full backend | full suite | unit | `uv run pytest -m "not integration"` (460 passed) | P0 | pr | covered |
| 20 | Air gap: no external refs in the bundle | built bundle | build check | `task fe-check` (exit 0, 2026-10-28) | P0 | pr | covered |

**Layer selection:** API contract at the unit tier (FakeK8s pins routing/SAR/error
mapping without a cluster); the kind-gated integration test is the held-out
real-client backstop the blueprint names; view seam at the Vitest+MSW tier
(exact-path capture — a kind-string drift fails there, not in a browser); e2e
smoke in CI. No layer degradation; no duplicate coverage (the unit list test and
the kind test assert different seams — the table dispatch vs the real client).

### Edge-Case Matrix

| Requirement | Edge / Boundary | Expected Behavior | Test / Scenario | Status |
|-------------|-----------------|-------------------|-----------------|--------|
| R1 | `?namespace=team-a` on a cluster-scoped kind | 200, same items, namespace ignored | `test_list_priorityclasses_ignores_namespace` + view URL assertion (no `namespace` substring) | covered |
| R1 | `?name=ghost` (no such class) | 200 with `items == []` (not 404) | `test_get_priority_class_by_name` | covered |
| R1 | SAR denied `list priorityclasses` | 403 RBAC_DENIED, read never attempted | `test_list_priorityclasses_sar_denied` (asserts the SAR record; FakeK8s list would 200) | covered |
| R1 | Unbound user / unknown id | 404 CLUSTER_NOT_FOUND (before the SAR) | `test_priorityclasses_binding_404` | covered |
| R1 | `priorityclass` (singular, 4.1 route name) | 404 RESOURCE_KIND_NOT_SUPPORTED | `test_priorityclass_kind_singular_rejected` | covered |
| R2 | Row with missing `value`/`preemption_policy`/`description` | `'—'` degradation, no crash | view `toRow` (pinned in the render test's item shape; the network-policy sibling test pins the identical pattern) | covered |
| R2 | `global_default: false` (falsy, not null) | renders `false`, not `'—'` | `priority_classes.test.tsx` (asserts the text `false` for the `global_default: false` item) | covered |
| R2 | No cluster selected | "No cluster selected.", zero fetches | `list-no-cluster-state` | covered |
| R3 | `items == []` upstream | "not found" state, pinned copy, not an error | `detail-not-found-state` (asserts no `Error` in the DOM) | covered |
| R3 | Missing `name` param | NO fetch + error line | `detail-missing-name-client-error` (catch-all MSW handler asserts zero hits) | covered |
| R4 | Mid-migration route gap | stub deletion + nav move + real route same commit | same-commit invariant (Task 2 commit `1bd5afab`; caveat: the App.tsx hunk rode in the concurrent `fcc40567` — see Ground Truth note) | covered |
| R4 | kind image drift (built-in policy differs) | fallback clause: assert the live built-in's actual policy | `test_list_priorityclasses_on_kind` RED→GREEN (the `PreemptLowerPriority` pin) | covered |

### Out of Scope

- **Pod → PriorityClass cross-linking** (4.1 had it on the Pods page) — the Pods
  page is still a stub; the briefing's Owed-Decision Gate names this explicitly out
  of scope (the value would have no rendering surface this change ships).
- **PriorityClass mutations** (create/delete) — 4.1-parity is read-only; the R4
  table's write surface is a separate change.
- **Informer cache interposition** (ADR-0010) — the cache lands at the pool seam
  later; per the blueprint this change reads through the seam without the cache.
- **e2e UI flow of the detail page** — the e2e smoke covers the list route's
  title; the detail page is Vitest-tier (the MSW seam is the view↔API contract).
  The kind e2e job runs the smoke.

## Ground Truth

- Backend suite: `cd backend && uv run pytest -m "not integration"` → **460 passed,
  10 deselected, 8 warnings** (2026-10-28, exit 0). Baseline pre-change: 450 passed.
  The 10 new are this change's (4 service + 6 API).
- Kind backstop: `cd backend && uv run pytest tests/api/test_resources.py -m
  integration -k priorityclasses -v` → **1 passed, 63 deselected** (exit 0,
  2026-10-28, live kind cluster `kubedash-test`).
- Frontend full suite: `corepack pnpm test` → **13 failed | 175 passed (34 files,
  188 tests)** (2026-10-28). The 13 failures are in 4 files
  (`users.test.tsx` 7, `groups.test.tsx` 4, `node.test.tsx` 1,
  `admin_permissions.test.tsx` 1) — all pre-existing at the baseline (the dirty
  tree before any priority-class commit had 17 red; 4 of those 17 cleared as the
  concurrent network-policy change completed). This change's view tests
  (`priority_classes.test.tsx` 3/3, `priority_class_data.test.tsx` 4/4) pass;
  the failure set contains no priority-class test.
- Typecheck: `task fe-build` → exit 0 (tsc + eslint + vite build, 2026-10-28).
- Air gap: `task fe-check` → exit 0 (2026-10-28).
- Lint (backend, changed files): `uv run ruff check` on the 4 changed backend
  files → 10 E501, ALL pre-existing lines (none inside this change's hunks —
  verified against the diff; several are inside the network-policy change's
  unformatted scaffold, a known follow-up). The repo lint step (`task fe-build`
  covers the frontend; backend ruff is not in the L2 floor command).
- Duplication (jscpd, advisory — `duplication.command` not configured): scoped to
  `src/views/OtherResource/` + `src/lib/types.ts` → 1 clone, 1.56% tokens (the
  labels/annotations CTable pair in `PriorityClassData.tsx`, parked Task 3 Minor 2).

## Goal-Backward Verification

**Stated goal** (briefing.md): replace the `/security/priorityclass` stub with the
4.1 Priority Classes list + detail at `/other-resource/priorityclass`, backed by
one new R4 kind (`priorityclasses`, cluster-scoped, SAR-gated), retiring the stub
and moving the nav leaf + e2e smoke path + ADR-0022 parity row in the same change.

**Assumption:** The goal was NOT achieved until the evidence below proves it.

| Level | Item | Evidence | Status |
|-------|------|----------|--------|
| Truth | List returns `ResourceListOut` (kind `priorityclasses`, to_dict items) on a cluster | `test_list_priorityclasses_200` (PASSED) + `test_list_priorityclasses_on_kind` (PASSED, live kind) | VERIFIED |
| Truth | `?namespace=` accepted and ignored | `test_list_priorityclasses_ignores_namespace` (PASSED); view URL assertion `not.toContain('namespace')` (PASSED) | VERIFIED |
| Truth | `?name=` → 1 item; `[]` on 404 upstream | `test_get_priority_class_by_name` (PASSED) | VERIFIED |
| Truth | SAR denied → 403 RBAC_DENIED naming the resource; read never attempted; SAR carries ns `None` + group | `test_list_priorityclasses_sar_denied` (PASSED — asserts the exact `(list, priorityclasses, None, None, scheduling.k8s.io)` record) | VERIFIED |
| Truth | Unbound/unknown id → 404 CLUSTER_NOT_FOUND | `test_priorityclasses_binding_404` (PASSED) | VERIFIED |
| Truth | Singular `priorityclass` → 404 RESOURCE_KIND_NOT_SUPPORTED | `test_priorityclass_kind_singular_rejected` (PASSED) | VERIFIED |
| Truth | List view renders name/value/preemption/default/description/created(local) + name link without namespace | `list-renders-priority-classes` (PASSED) | VERIFIED |
| Truth | List view: no cluster → "No cluster selected." + zero fetches; RBAC error → error line, no blank table | `list-no-cluster-state` + `list-error-state` (PASSED) | VERIFIED |
| Truth | Card/section title EXACTLY `Priority Classes` | `priority_classes.test.tsx` heading-scoped assertion (PASSED); e2e smoke entry title byte-identical (ui-smoke.spec.ts diff) | VERIFIED |
| Truth | Detail: single `?name=` read (no namespace), metadata + full object as YAML containing the class name | `detail-renders-priority-class-yaml` (PASSED) | VERIFIED |
| Truth | Detail: empty items → "not found" state; missing name → no fetch + error line | `detail-not-found-state` + `detail-missing-name-client-error` (PASSED) | VERIFIED |
| Truth | Nav shows "Priority Classes" under Other Resources (last leaf) and NOT under Security; old path resolves to no route | `tests/nav.test.tsx` (PASSED, contract order updated) + `tests/views/Stub.test.tsx` (PASSED) + `git grep priorityclass frontend/src` (only the intended files) | VERIFIED |
| Truth | e2e smoke entry at the new path, title unchanged | `ui-smoke.spec.ts` diff (path-only move); suite runs in CI's e2e job (kind) | VERIFIED (CI) |
| Truth | ADR-0022 parity row amended (new path, 5.0 group, implemented, ratified-deviation note) | the row in `04-adr-0022-sidebar-nav-4-1-parity.md` (diff: 1 line, 2026-10-28) | VERIFIED |
| Artifact | `K8sClient.list_priority_classes` / `get_priority_class` / `self._scheduling` | files present (k8s_client.py); service tests 4/4 PASSED; deletion test: the R4 handler dispatches by table method name — removing a method AttributeErrors the route (pinned by the API tests) | VERIFIED |
| Artifact | `_KINDS["priorityclasses"]` + `_GETTERS["priorityclasses"]` rows | resources.py diff (2 lines); `test_list_priorityclasses_200` would 404 without them | VERIFIED |
| Artifact | `views/OtherResource/PriorityClass.tsx` + `PriorityClassData.tsx` + `PriorityClassItem` type | files present (105 / 194 lines / 16-line interface); the view tests import and render them | VERIFIED |
| Key Link | table row method names ↔ `K8sClient` method names (byte-for-byte) | the API tests exercise `getattr(pool.get(cluster), method)` end-to-end (PASSED) | VERIFIED |
| Key Link | list view URL ↔ kind string ↔ nav leaf ↔ e2e smoke (four strings that must agree) | Vitest exact-path capture (PASSED) + `nav.test.tsx` + `ui-smoke.spec.ts` diff | VERIFIED |
| Key Link | detail view URL carries `name` only (no namespace, no kind enum) | `detail-renders-priority-class-yaml` (PASSED — asserts `?name=high` + no `namespace` substring) | VERIFIED |
| Data Flow | cluster read → `_KINDS` dispatch → `K8sClient` (real) → `ResourceListOut` → view rows | `test_list_priorityclasses_on_kind` (live kind, real client, PASSED) | VERIFIED |

## Traceability Matrix

| Scenario (acceptance.feature) | Test / Scenario (test plan) | Ran | Result |
|--------------------------------|------------------------------|-----|--------|
| priorityclasses-list-200 | `test_list_priorityclasses_200` + `test_list_priorityclasses_on_kind` | yes | pass |
| priorityclasses-list-ignores-namespace | `test_list_priorityclasses_ignores_namespace` + view URL assertion | yes | pass |
| priorityclasses-get-by-name | `test_get_priority_class_by_name` | yes | pass |
| priorityclasses-sar-denied | `test_list_priorityclasses_sar_denied` | yes | pass |
| priorityclasses-binding-404 | `test_priorityclasses_binding_404` | yes | pass |
| priorityclasses-kind-singular-rejected | `test_priorityclass_kind_singular_rejected` | yes | pass |
| list-renders-priority-classes | `priority_classes.test.tsx::list-renders-priority-classes` | yes | pass |
| list-no-cluster-state | `priority_classes.test.tsx::list-no-cluster-state` | yes | pass |
| list-error-state | `priority_classes.test.tsx::list-error-state` | yes | pass |
| detail-renders-priority-class-yaml | `priority_class_data.test.tsx` (detail renders) | yes | pass |
| detail-not-found-state | `priority_class_data.test.tsx` (not-found) | yes | pass |
| detail-missing-name-client-error | `priority_class_data.test.tsx` (missing name) | yes | pass |
| stub-route-retired-and-moved | `nav.test.tsx` + `Stub.test.tsx` + `priority_classes.test.tsx` render + ui-smoke diff | yes | pass |
| priorityclasses-list-on-kind | `test_list_priorityclasses_on_kind` (live kind) | yes | pass |

**Totals: 14 scenarios, 14 covered, 0 pending.**

## TDD Evidence

| Ticket | RED command + signature | GREEN command + result | Commit |
|--------|-------------------------|------------------------|--------|
| Task 1 (kind) | `uv run pytest tests/services/test_k8s_client_priorityclasses.py -v` → AttributeError (no `_scheduling`) before implementation (report task-1-report.md) | `uv run pytest tests/api/test_resources.py tests/services/test_k8s_client_priorityclasses.py -v` → 62 passed; full unit 460 passed | `77d3bcbe` |
| Task 2 (list view + nav) | `corepack pnpm test tests/views/priority_classes.test.tsx` → module not found before the view existed (report task-2-report.md) | same command → 3 passed; fe-build + fe-check exit 0 | `1bd5afab` (+ fix `b5243e13`) |
| Task 3 (detail view) | `corepack pnpm test tests/views/priority_class_data.test.tsx` → module not found before the view existed (report task-3-report.md) | same command → 4 passed; fe-build + fe-check exit 0 | `049fd05d` |
| Task 4 (kind backstop) | first live-kind run RED at the `namespace` shape assertion (real apiserver emits `namespace: None`; the unit fake asserted absence) — route/item assertions already passing (report task-4-report.md) | `uv run pytest tests/api/test_resources.py -m integration -k priorityclasses -v` → 1 passed, 63 deselected | `88622fed` |

Commit hashes resolve in `git log`; all named test files exist on disk. No
MISSING_RED, no STALE.

## Verification-Gap Audit

| Behavior (from code, not scenarios) | Covered by | Gap? |
|--------------------------------------|-----------|------|
| `list_priority_classes` 502 → `ClusterUnreachableError` (transport) | `test_list_priority_classes_maps_500_to_unreachable` | no |
| `get_priority_class` 404 → `[]`, 500 → 502 | service tests 2/4 | no |
| `_unreachable` mapping shared helper | pre-existing (get_secret/get_crd tests) | no |
| `?namespace=` on the DETAIL URL is ignored server-side | the handler's single dispatch covers it; the view test pins the view sends none; the list-level API test pins the server ignores it — the detail uses the same handler path (`_GETTERS` branch) | no (named: a `?namespace=` on the detail URL reaches the same `_GETTERS` call that ignores it — pinned at the shared seam) |
| Detail view YAML block = full fetched object (not a projection) | `detail-renders-priority-class-yaml` pins `<pre>` contains the class name + `preemption_policy` | no |
| Air gap (no new dependency) | `task fe-check` exit 0 + the diff's import list (all pre-existing) | no |
| Rollback unit integrity | the App.tsx hunk for the list route lives in the concurrent `fcc40567` (network-policy Task 4 committed the shared working tree during the Task 2 window) — reverting `1bd5afab` alone leaves the route without a stub at the old path but WITH a live route at the new path (no gap; the gap direction is safe) | WARNING W006 (recorded; no functional gap at any commit boundary) |

**PRESENT_BEHAVIOR_UNVERIFIED: none.** Every behavior in the diff has a named
covering test that ran.

## Assertion Quality Audit

| Test file | Pattern checked | Finding |
|-----------|-----------------|---------|
| `test_k8s_client_priorityclasses.py` | tautology / ghost loop / no-code-call | none — each test calls the real `K8sClient` method on a `SimpleNamespace` double and asserts the returned shape (or the raised error type) |
| `test_resources.py` (new tests) | same + SAR record shape | none — `test_list_priorityclasses_sar_denied` asserts the exact 5-tuple record (ns `None`, group present) and the 403 body; the FakeK8s double would 200 if the read were attempted, so "no read attempted" is discriminating |
| `priority_classes.test.tsx` | same + exact-string pin | none after the Task 2 fix commit (the heading-scoped title assertion replaced a `>= 1` count that a reviewer flagged as weak; the dead `capturePaths` helper was deleted) |
| `priority_class_data.test.tsx` | same + no-fetch proof | none — the missing-name and no-cluster tests register a catch-all MSW handler and assert zero hits (a stray fetch to ANY path fails them) |

No CRITICAL pattern. No WARNING.

## Security Audit

The change adds two read-only cluster-resource endpoints through the EXISTING
binding gate + SAR gate (ADR-0004) — no new trust boundary, no new input surface
beyond the `name` string (URL-encoded client-side; the server passes it to
`read_priority_class`, which 404s on unknown). No user-input handling beyond the
existing contract, no secrets, no new dependency (air gap enforced). Trivy: not
configured (`security.trivy.command` empty) — N/A. No CRITICAL.

## Code Quality Audit

| Gate | Threshold | Result | Verdict |
|------|-----------|--------|---------|
| Backend unit suite | all pass | 460 passed, 10 deselected, exit 0 | PASS |
| Frontend suite (this change's files) | all pass | priority_class(s) 7/7 passed | PASS |
| Frontend suite (whole) | P0 ≥ 100 / P1 ≥ 95 (defaults) | 175/188 passed; the 13 failures are pre-existing (4 files, none in this change) — see Ground Truth. P0 tests in this change: all pass. | PASS (with WARNING: whole-tree red is not this change's; tracked under the network-policy change's close-out) |
| Typecheck (`task fe-build`) | exit 0 | exit 0 | PASS |
| Lint (`task fe-build` eslint + backend ruff on changed files) | no NEW errors | fe-build exit 0; backend ruff: 10 E501, all pre-existing lines (verified against the diff) | PASS (with the pre-existing E501 noted) |
| Air gap (`task fe-check`) | exit 0 | exit 0 | PASS |
| Changed-file coverage | 80% (default) | no coverage command configured (`testing.coverage` empty) | N/A (gate disabled — do not FAIL) |
| Mutation | (disabled) | no command configured | N/A |
| Trivy | (disabled) | no command configured | N/A |
| Duplication (jscpd, advisory) | `fail_on` 0 → advisory | 1 clone in `PriorityClassData.tsx` (labels/annotations CTable pair), 1.56% tokens; parked Task 3 Minor 2 (the brief mandates mirroring SecretData's shape, which has the same pair) | ADVISORY (SUGGESTION, never blocks) |

## Floor

| Audit | Weakest dimension | Verdict earned |
|-------|-------------------|----------------|
| Goal-backward | all 14 truths VERIFIED by named tests (2 live-kind) | PASS |
| Traceability | 14/14 covered, 0 pending | PASS |
| TDD evidence | no MISSING_RED / no STALE; 4/4 rows with resolvable commits | PASS |
| Verification gap | 0 gaps; 1 WARNING (rollback unit split across a concurrent commit) | PASS (caps at CONCERNS if the WARNING were load-bearing — it is not: no route gap at any boundary) |
| Assertion quality | no CRITICAL, no WARNING after the Task 2 fix commit | PASS |
| Security | N/A (no new trust boundary) | PASS |
| Code quality | strongest gate PASS; whole-frontend-tree red is pre-existing (named, non-load-bearing) | PASS |

**Floor verdict: PASS.** No dimension earns below PASS; the two WARNINGs
(rollback-unit split; pre-existing frontend red) are non-answers about THIS
change's correctness with named resolution paths (ship the network-policy
change's close-out; revert units documented in the ledger), so they cap at most
at CONCERNS — and the floor caps the verdict at the weakest dimension, which is
PASS.

## Gate Decision

### Verdict: **PASS**

1. All truths VERIFIED (14/14, named tests; the real-client backstop ran live on
   kind). 2. All 14 scenarios covered by a test that ran and passed. 3. No
   CRITICAL findings from any audit. 4. TDD table: no MISSING_RED, no STALE.
   5. Code-quality gates: PASS or N/A. 6-7. P0/P1 in this change: 100% pass.
   8-10. Coverage/mutation/Trivy: N/A (disabled). 11. Duplication 1.56% ≤
   advisory (fail_on 0). 12. Verification scope: COMPLETE (every changed file
   read in full; the two subagent reviews read the full diffs; the controller
   re-ran every oracle named in the Ground Truth section).

### WARNING

- **W006 (rollback unit split):** the list route's `App.tsx` hunk landed in
  `fcc40567` (the concurrent network-policy change's Task 4 committed the shared
  working tree during this change's Task 2 window). Reverting `1bd5afab` alone
  leaves the new route live (safe direction — no 404 window), but the clean
  rollback unit for Task 2 is `fcc40567..1bd5afab` + one hunk. Resolution path:
  ship/archive both changes together (same branch, no release cut between them).
- **Pre-existing frontend red (13 tests, 4 files)** — owned by the in-flight
  users/groups/node pages and the network-policy close-out, not this change.
  The user ruled "execute on top as-is" at pre-flight; the set shrank 17 → 13
  during the run as the concurrent change completed.

### Human Override

(none — the machine verdict stands)

## Final-State Facts

Completed by `reflect` 2026-10-28 (after ship; the folder is in `xarchive/`).

### Integration

- **Base branch / strategy:** `rebase` work branch, keep-branch (user decision at
  ship; the repo VERIFIED assumption — ship does not merge `main` by default).
  No merge commit, no PR; the branch (41 commits ahead of `origin/rebase`) is
  the deliverable and the rollback unit.
- **Integrated-tree evidence (fresh run at ship, 2026-10-28):**
  `cd backend && uv run pytest -m "not integration"` → **461 passed, 10
  deselected** (green); `corepack pnpm test` → 177 passed / 13 failed — all 13
  in the pre-existing W007 set (users/groups/node/admin_permissions), none in
  this change's files; `task fe-build` → exit 0; `task fe-check` → exit 0.
- **Worktree:** the main working tree (`/Users/paladm/git/kubedash_4`), branch
  `rebase` — preserved (keep-branch). No worktree cleanup.
- **Archive move:** `specs/` → `xarchive/` mechanical (`git mv`), `diff -r`
  readback against the pre-move snapshot EMPTY. The move was absorbed into the
  concurrent session's commit `27137670` window (verified: 4 zero-change
  renames in that commit's stat); the state pointer landed as `733ea3ec`.

### Decisions (retro)

- **Keep-branch integration** — the work branch is the rollback unit; merging
  into `main` stays a separate deliberate act (ASSUMPTIONS.md VERIFIED).
- **JSON, not YAML, for the detail block** (final-review Important fix,
  `b02c2ef9`): the block is `JSON.stringify` of the `to_dict` item; the `yaml`
  hljs grammar was a misclassification of JSON lines; no YAML emitter exists in
  the dependency tree (ADR-0020 air gap). Ratified delta recorded in the view
  doc — the briefing's R3 "YAML" wording is intent, JSON is the shipped shape.
- **ADR-0022 parity row keeps the 4.1-provenance group column**; the 5.0 group
  is stated in the Status cell (ratified-deviation note).
- **Kind backstop pins the live image's actual built-in** (`PreemptLowerPriority`,
  `value 2000000000`) per the blueprint's fallback clause — the blueprint's
  `Never`/`exempt` constants were image-stale (annotated in the blueprint).

### Lessons

- **Concurrent sessions on one working tree interleave at the commit boundary.**
  Twice this run, the parallel network-policy session swept or rebase-replayed
  the shared tree (the `App.tsx` hunk absorption → W006; the archive move
  landing in `27137670`). Both were safe by direction, but the clean rollback
  unit for Task 2 is now `fcc40567..1bd5afab` + one hunk. When two agents share
  a tree, prefer explicit-path staging (done) and verify each commit's stat
  immediately after committing.
- **A "YAML" requirement on a JSON-shaped payload needs the serialization
  named in the spec.** The final review caught it in 3 minutes; a spec line
  ("rendered via `JSON.stringify`, json highlighter") would have caught it at
  plan time.
- **Blueprint constants about live cluster state go stale.** Kind base images
  change; the fallback clause is what makes the backstop honest.

### Patterns (reusable)

- **Cluster-scoped R4 kind = 2 table rows + 2 `K8sClient` methods + 0 handler
  changes** — binding gate, SAR gate (ns `None` in the ADR-0004 cache key), and
  `ResourceListOut` all come from the shared machinery. Template for the five
  remaining Other-Resources stubs. (Saved to mnemonic:
  `architecture/r4-resource-kinds`.)
- **View↔API seam pinning:** exact-fetch-path capture + `not.toContain('namespace')`
  in the MSW handler, so a kind-string drift or a leaked namespace param fails
  in Vitest, not in a browser.
- **No-fetch proof** via a catch-all MSW handler asserting zero hits (stronger
  than a specific-path handler).

### Surprises

- **The kind image disagrees with the blueprint** (`PreemptLowerPriority` vs
  `Never`, no `exempt`) — expected-ish, but it turned Task 4's RED into a
  shape fix (the real apiserver emits `metadata.namespace: None`, which the
  unit fake's absence-shape assertion did not model).
- **The mnemonic store was down** (FK constraint on session rows) for both the
  session-summary and ship saves — the in-repo ledger + archive carried the
  record; no data lost.
- **`git commit` timed out twice at 120–180 s** (hook pipeline: gitleaks +
  skillgrid checkpoint guards) — the commits landed; raise the shell timeout
  for commits in this repo.

## Environment Retro

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| Automated checks | **Unwired repo hook:** `.git/hooks/commit-msg` is a shim that `exec`s `$root/git-hooks/commit-msg` — a directory that does not exist in this repo (`git config core.hooksPath` points at `~/.skillgrid/git-hooks`, whose `commit-msg.js` has no `skillgrid-context` check). Result: the context-block discipline is unenforced — ~1 of the 30 recent commits (`27137670`) ships without a `[skillgrid-context]` block. The AGENTS.md promise "The git hooks enforce the guards" is stale for this checkout. | wire a pre-commit/commit-msg guard into the live hooksPath (`~/.skillgrid/git-hooks/`) — e.g. a `precommit-context-block.js` in `~/.skillgrid/hooks/` called from `checkpoint-state.js guard` — or restore the repo-local `git-hooks/` dir the shim expects | session: `git log -30` context-block audit; `.git/hooks/commit-msg` (shim); missing `git-hooks/` dir |
| Automated checks | **ruff E501 is selected (`select = ["E", ...]`, `line-length = 100`) but no backend lint gate exists** — no `task backend-lint`, no ruff step in `ci.yaml`, and the pre-commit pipeline (gitleaks + skillgrid guards) never runs it. 10 pre-existing E501s sit in the four files this change touched. | add `task backend-lint` (`uv run ruff check`) + a CI job step; optionally a pre-commit hook running it on staged python files | `backend/pyproject.toml:53,49`; `.github/workflows/ci.yaml` (no ruff); session: `uv run ruff check` on changed files |
| Navigation | **The kind cluster's live state is invisible to the agent.** The backstop's expected constants (`Never`, `exempt`) had to be discovered by running `kubectl` mid-task; the blueprint's "NOTE 2026-10-28" annotation is the durable record, but the next change writing kind-gated expectations will rediscover it. | add a `task kind-state` (or a line in `AGENTS.md` Testing) that prints `kubectl get priorityclass,crd -o name \| grep -E 'priorityclass\|cilium'` — the live built-ins the backstops assert against | session: Task 4 RED→GREEN; `blueprint.md:702-713` annotation |
| Tool economy | **Shell 120 s default timeout < commit duration.** Two `git commit` calls (this run) exceeded the default timeout while the hook pipeline (gitleaks + checkpoint guards) ran; the commits still landed, so the tool result misreports failure. | raise the default shell timeout for `git commit` in this repo to 300 s (or run commits with an explicit `timeout: 300000`) | session: two timed-out commit tool calls (`b5243e13`, `b02c2ef9` wave) |
| Information access | **The mnemonic store's FK failure mode is silent-ish.** `mem_save` with `session_id: "current"` failed with a raw `FOREIGN KEY constraint failed (787)` — no hint that the session row was missing; the `mem_session_start` row itself then collided (`UNIQUE constraint failed: sessions.id`). The in-repo ledger covered for it, but the store needs a health check. | report to the mnemonic tooling owner: `mem_save` should surface "session row missing — call mem_session_start" instead of the raw FK error; add a `mem_status`/health probe | session: two failed `mem_save` calls (session summary + ship) |

*Clean categories:* **Coding standards** (the final reviewer caught the
json/yaml misclassification and the stale comment — no standard to add; the
mechanical parts are already lint-covered once ruff is wired) and
**Steering-file no-ops** (AGENTS.md stayed accurate; the one stale line — "the
git hooks enforce the guards" — is the unwired-hook finding above, not a no-op
to delete).

### Offered follow-ups (not implemented here)

1. **Wire the `[skillgrid-context]` block guard** into the live hooksPath
   (small: one guard script + one line in `checkpoint-state.js guard`).
2. **Add `task backend-lint` + CI ruff step** (small: Taskfile + ci.yaml).
3. **Add `task kind-state`** for live-cluster expectation discovery (trivial).
