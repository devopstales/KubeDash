# Report — RuntimeClass Views (List + Data)

**Change:** `2026-10-28-runtimeclass-views` (TASK-046) · **Gate:** QA
re-verification 2026-11-13 at tip `b98c53cf` (+ the gate's own
dependency-bump commit)
**Original gate:** batch-of-6 QA 2026-10-29 — PASS at tip `aead16a7`;
record: `.skillgrid/change-specs/2026-10-28-other-resource-views/qa-report.md`
**Gate history:** executed 2026-10-28 (4 code commits `718eda35..786100f5`)
→ batch QA PASS 2026-10-29 (`aead16a7`) → ADR-0040 ObjectRoute migration
(`89528a32`, separate change `2026-10-29-session-object-navigation`, QA PASS
2026-11-04/05) → three-axis review 2026-11-12 (met-with-fixes; 3 Minors
fixed at `0360044d`) → shipped 2026-11-12 (`6e4504d3`, spec zone archived)
→ **this re-verification** at `b98c53cf` (220 commits of tree drift since
the original gate; 10 since the review — zero code, `git diff 5f8d9c61..HEAD
-- backend frontend cli` empty).
**Effective tier:** T1 (blueprint header) — additive view pair on the
existing generic `/resources` route; `low-risk` classification floor (L1 +
runtime verification) met and exceeded. The batch gate, the review, and this
re-verification all ran at T2 evidence practice.
**Quality config:** `quality.coverage_min=0` / `mutation_min=0` /
`p0_pass_rate=100` / `p1_pass_rate=95`; Trivy configured
(`trivy fs .`, severities CRITICAL, `fail_on: CRITICAL`) — first gate to
execute it (the configmap re-verification 2026-11-12 recorded "manual
mode", but the `security.trivy` block was already present in
`config.yaml` at that tree — see Security Audit). No `duplication.command`
(advisory).

## Test Plan

### Risk Ranking

- **P0** (production/data): R1 list endpoint contract (200 /
  `kind: runtimeclasses` / to_dict items / SAR-before-client on
  `node.k8s.io` + namespace `None` / 403 names the resource / binding 404 /
  singular rejected), R2 `?name=` lookup (0/1-item, `[]` on miss). A broken
  read or wrong SAR group fails every RuntimeClass consumer.
- **P1** (experience): R3 list rendering (exact title, columns, overhead
  rendering, states), R4 data rendering (single fetch, CTable, JSON block,
  not-found-as-state), R5 routing / stub removal / nav unchanged.

### Plan

| # | Behavior | Scenario | Named test (layer) | Cadence | Status |
|---|----------|----------|--------------------|---------|--------|
| 1 | List 200, kind, to_dict | runtimeclasses-list-200 | `test_list_runtimeclasses_200` (API) + service `test_list_runtime_classes_ignores_namespace` (unit) | pr | ran PASS + LIVE |
| 2 | Cluster-scoped: `?namespace=` ignored | runtimeclasses-list-ignores-namespace | `test_list_runtimeclasses_ignores_namespace` (API) | pr | ran PASS + LIVE |
| 3 | SAR deny 403, client never called | runtimeclasses-sar-denied | `test_list_runtimeclasses_sar_denied` (records the node.k8s.io / ns-`None` SAR tuple before the read) | pr | ran PASS |
| 4 | Binding gate 404 | runtimeclasses-binding-404 | `test_runtimeclasses_binding_404` | pr | ran PASS |
| 5 | Singular kind rejected | runtimeclass-kind-singular-rejected | `test_runtimeclass_kind_singular_rejected` | pr | ran PASS + LIVE |
| 6 | `?name=` hit / miss | runtimeclasses-get-by-name | `test_list_runtimeclasses_get_by_name` + service `test_get_runtime_class_404_returns_empty_list` | pr | ran PASS + LIVE |
| 7 | List rows + name→detail (ADR-0040 shape) | runtimeclass-list-renders-rows-with-data-links | `list-renders-runtime-classes` + `click-name-renders-detail-with-clean-url` (RTL/MSW per `NAVIGATION-SUPERSEDED.md`: name cell is a button, detail renders at the clean route) | pr | ran PASS + LIVE |
| 8 | Overhead rendering (present / absent / empty `{}`) | runtimeclass-list-overhead-rendering | `list-overhead-absent-state` (100m/128Mi row + absent `—` + `kata` `pod_level_overhead: {}` fixture — the `0360044d` regression pin that fails against the pre-fix expression) | pr | ran PASS |
| 9 | Empty list state | runtimeclass-list-empty-state | `list-empty-state` | pr | ran PASS |
| 10 | Data: single fetch, CTable, JSON block | runtimeclass-data-renders-detail | `data-renders-detail` (pins EXACTLY one request) | pr | ran PASS + LIVE |
| 11 | Miss = not-found STATE | runtimeclass-data-not-found-state | `data-not-found-state` (pinned copy `No RuntimeClass 'ghost' found`, no error style) | pr | ran PASS |
| 12 | Missing name param | runtimeclass-data-missing-name | `data-missing-name` (pinned error, 0 fetches) | pr | ran PASS |
| 13 | Stub removed, routes wired, nav unchanged | runtimeclass-stub-removed-and-routes-wired | `Stub.test.tsx` + `ui-smoke.spec.ts` `SMOKE_STUB_ROUTES` entry (e2e stub-routes leg, exact title) + commit scope (`_nav.tsx` absent) | pr | ran PASS (e2e leg 1/1) |
| 14 | (risk-ranked extra) No-cluster state, no fetch | briefing R3 states | `list-no-cluster-state` + `data-no-cluster-state` (assert 0 fetches) | pr | ran PASS |
| 15 | (risk-ranked extra) List error state | briefing R3 states | `list-error-state` (red error line, no rows) | pr | ran PASS |
| 16 | (risk-ranked extra) Transport 500 → ClusterUnreachableError | R1 client contract | service `test_list_runtime_classes_maps_500_to_unreachable` + `test_get_runtime_class_other_api_error_maps_to_unreachable` | pr | ran PASS |

Layer selection: API contract at the API tier (Flask test client + FakeK8s
with recorded calls — the layer that proves SAR-before-client and
cluster-scoped namespace handling); client mapping at the unit tier
(`object.__new__` + SimpleNamespace, repo convention); view behavior at
RTL/MSW; the live-stack mount + exact title at e2e. No duplicate coverage:
service tests assert the client branch + `to_dict` mapping the API tests
can't see; the e2e leg asserts a live mount the unit layers can't.

### Edge-Case Matrix

| Edge | Variant | Covered by |
|------|---------|-----------|
| Overhead: present | `100m / 128Mi` | list-renders-runtime-classes (row) |
| Overhead: absent | `—` (pinned char, R3) | list-overhead-absent-state |
| Overhead: present-but-empty `{}` | `—` (never an empty cell — `0360044d` fix) | list-overhead-absent-state (`kata` fixture) |
| Overwrite flag: null | `—` | list-renders-runtime-classes (row) |
| Lookup: miss | `[]` → not-found STATE | data-not-found-state + `test_get_runtime_class_404_returns_empty_list` |
| Kind: singular | 404 RESOURCE_KIND_NOT_SUPPORTED | test_runtimeclass_kind_singular_rejected |
| Namespace: any value on a cluster-scoped kind | accepted-and-ignored | test_list_runtimeclasses_ignores_namespace |
| List: empty | first-class empty state | list-empty-state |
| List: no cluster | `No cluster selected.`, 0 fetches | list-no-cluster-state |
| List: API error | red error line | list-error-state |
| SAR: deny | 403 before client call | test_list_runtimeclasses_sar_denied |
| Transport: 500 | ClusterUnreachableError (502) | service maps_500 tests |

### Out of Scope

- Create/edit/delete for RuntimeClasses (read-only, 4.1 parity).
- Pod→RuntimeClass linkage (no pod view in 5.0).
- RBAC template changes (built-in ClusterRoles already carry
  `runtimeclasses`; no migration, no seed change).
- The legacy `/data?name=` → clean-route redirect behavior itself (owned by
  `2026-10-29-session-object-navigation` TICKET-07; exercised live at this
  gate, pinned by that change's e2e).

## Goal-Backward Verification

All blueprint truths VERIFIED — named tests ran green at the current tip, and
the surface was exercised on the running dev stack
(`kubedash.dev.local:8080`, 2026-11-13, local cluster id 0, demo fixture
`demo-runc`):

| Truth | Evidence |
|-------|----------|
| List 200 / `kind: runtimeclasses` / to_dict items | `test_list_runtimeclasses_200` PASS; **LIVE**: `GET /api/v1/clusters/0/resources/runtimeclasses` → 200, `{"cluster":"local","kind":"runtimeclasses","items":[demo-runc]}` |
| SAR before client, `node.k8s.io` group, ns `None` | `test_list_runtimeclasses_sar_denied` PASS (records the SAR tuple before the read); **LIVE**: 200 on a bound admin (the get/list verdict is correct) |
| Cluster-scoped: `?namespace=` ignored | `test_list_runtimeclasses_ignores_namespace` PASS; **LIVE**: `?namespace=team-a` → 200 |
| `?name=` 0/1-item, miss = `[]` | `test_list_runtimeclasses_get_by_name` PASS; **LIVE**: `?name=demo-runc` → 1 item, `?name=ghost` → `[]` |
| Singular rejected | `test_runtimeclass_kind_singular_rejected` PASS; **LIVE**: `.../resources/runtimeclass` → `RESOURCE_KIND_NOT_SUPPORTED` |
| List view: exact title, columns, states | `list-renders-runtime-classes` + 4 sibling tests PASS; **LIVE browser**: heading "Runtime Classes" (pinned on the heading, breadcrumb renders the same text), columns Name / Handler / Overwrite Node Sel No Toleration / Pod Level Overhead / Created, row `demo-runc | runc | — | — | 08/11/2026, 16:25:47` |
| Name→detail at the clean URL (ADR-0040 shape) | `click-name-renders-detail-with-clean-url` PASS; **LIVE browser**: click `demo-runc` → "Runtime Class Data" renders at `/other-resource/runtimeclass` with `window.location.search === ''` (object ref in sessionStorage) |
| Data: single fetch, CTable, JSON block, not-found state | `data-renders-detail` (exactly-one-request pin) + `data-not-found-state` + `data-missing-name` PASS; **LIVE browser**: CTable rows Name/Kind/Created/Handler/Overwrite Node Sel No Toleration (N/A)/Pod Level Overhead (N/A)/Labels (No labels)/Annotations (Key/Value) + full `JSON.stringify` block with the `json` hljs grammar; **LIVE**: legacy `/other-resource/runtimeclass/data?name=ghost` → one-shot redirect to the clean route (TICKET-07 OldDataRedirect) |
| Stub removed, routes wired, nav unchanged | `Stub.test.tsx` PASS (no `/other-resource/runtimeclass` entry); **LIVE**: both routes wired via `ObjectRoute` (`App.tsx` 832/849), nav leaf "Runtime Class" present under Other Resources; commit scope: `_nav.tsx` absent from all 4 change commits (batch gate) |

## Traceability Matrix

**13/13** scenarios from `acceptance.feature` mapped (rows 1–13 above).
0 UNTESTED, 0 FAILING, 0 PARTIAL, 0 pending. The superseded query-string
clauses (R3 link targets, R4 `/data?name=` URL shape) are satisfied in the
ADR-0040 shape per this spec's `NAVIGATION-SUPERSEDED.md` — the backend
`?name=`/`?namespace=` REST filtering params are unchanged and
live-verified. Note: the 2026-11-12 review's Spec axis records "11/11
scenarios" — the acceptance file carries 13 `Scenario:` headers; the
discrepancy is a review-record undercount with no coverage gap (all 13
mapped at this gate) — SUGGESTION W041.

## Verification-Gap Audit

- **PRESENT_BEHAVIOR_VERIFIED** for every load-bearing path: the
  cluster-scoped namespace-accept-and-ignore branch (API test + LIVE
  `?namespace=team-a`), the 404→`[]` mapping (service test + LIVE miss),
  the overhead ternary (three RTL fixtures: present / absent / empty-`{}`),
  the NOT_FOUND throw→state path (RTL + the live legacy-redirect leg), the
  single-fetch data contract (exactly-one-request MSW pin).
- **Regression gaps:** none — the empty-`{}`-overhead invariant (the
  `0360044d` fix: present-but-empty `{}` must not join to `''`) is pinned by
  the `kata` fixture whose assertion fails against the pre-fix expression;
  the SAR-before-client ordering is pinned by the recorded-call FakeK8s.
- **Missing-oracle gaps:** none — every happy path has a named test
  (`[scenario]` docstring tags / test titles).

## TDD Evidence Audit

| Task | Commit | Test files | RED→GREEN |
|------|--------|-----------|-----------|
| T1 backend kind | `718eda35` (resolves) | `tests/api/test_resources.py` +6 tests, `tests/services/test_k8s_client_runtimeclasses.py` (new, 4 tests) | batch QA 2026-10-29: 24/24 batch task units OK (RED before GREEN per task); co-commit shape (no execution ledger — W040) |
| T2 list view | `7580d592` (resolves) | `tests/views/runtime_classes.test.tsx` (new) | co-commit |
| T3 data view | `33adbbe7` (resolves) | `tests/views/runtime_class_data.test.tsx` (new) | co-commit |
| T4 routing | `786100f5` (resolves) | `tests/views/Stub.test.tsx` (expectation drop) | co-commit |
| Review fix (2026-11-12) | `0360044d` (resolves) | `tests/views/runtime_classes.test.tsx` (`kata` fixture extends `list-overhead-absent-state`) + `e2e/ui-smoke.spec.ts` (title entry) | failing-against-old-expression pin recorded in `review.md` |

No `MISSING_RED`, no `STALE`. All hashes resolve in git history.

## Assertion Quality Audit

Re-verified at this gate (both frontend test files read — titles + key
assertions; the 6 API tests + service file by signature/assertion pattern):
0 CRITICAL, 0 WARNING. Strongest pins: the SAR tuple with `node.k8s.io`
group + namespace `None` (group load-bearing — W022 shows the cost of a
wrong group on a sibling kind), `expect(requestedUrl).not.toContain('namespace')`
(cluster-scoped URL contract), the exact 5-column `columnheader` list, the
heading-scoped title assertion (breadcrumb renders the same text — the pin
is on the heading specifically), the exactly-one-request data-fetch pin, the
`seen: []` 0-fetch pins. No tautologies, no ghost loops, no
assertion-without-code-call.

## Changed-File Coverage

N/A — `quality.coverage_min=0`, no coverage command configured.
Scenario-level coverage is 13/13 (traceability matrix).

## Test Quality Audit

Fixtures are realistic `to_dict` shapes (snake_case metadata,
`creation_timestamp`, the kubectl `last-applied-configuration` annotation,
`managed_fields` — the same shape the LIVE demo-runc returns). MSW handlers
match the exact cluster-scoped URL (a wrong path/param → unhandled → red).
Distinct fixtures per state (empty `{}` vs absent vs populated overhead).

## Test Strategy Audit

No wrong-layer tests: client mapping at unit tier (no Flask), the
SAR/binding/404 contract at API tier (the layer that owns it), view states
at RTL, live mount + exact title at e2e. No e2e for unit-covered behavior
beyond the mount smoke.

## Security Audit

**Trivy (configured: `trivy fs .`, `fail_on: CRITICAL`):** first executed at
this gate —
- **Initial run (tree `b98c53cf`): 2 CRITICAL, both pre-existing
  lockfile state, both with fixes, neither introduced by this change
  (the batch gate verified the 4 change commits' dependency-file diff is
  empty):**
  - `certifi 2026.7.22` in `backend/uv.lock` — GHSA-6q48-6c7w-9gw2
    (compromised emSign intermediate CA keys), fixed in 2026.10.18
  - `dompurify 3.4.15` in `frontend/pnpm-lock.yaml` —
    GHSA-cg2g-xh64-v4q7 (SAFE_FOR_TEMPLATES bypass), fixed in 3.4.17;
    transitively pinned EXACTLY by `monaco-editor@0.57.0`
- **Machine verdict at first render: FAIL** (PASS criterion 10 / FAIL
  criterion "a Trivy finding at or above `fail_on` severity").
- **Fix loop (at this gate):** `uv lock --upgrade-package certifi`
  (→ 2026.10.23, uv.lock revision 2→3 — CI's unpinned `setup-uv@v3` reads
  revision 3) + `pnpm.overrides: {dompurify: 3.4.17}` in
  `frontend/pnpm-workspace.yaml` (pnpm v12 home for overrides; the
  `package.json` `pnpm` field is ignored by v12) + `pnpm install`
  (lockfile diff = exactly the dompurify version swap, `+2 -1`).
- **Re-run: 0 CRITICAL across all 4 targets** (`backend/uv.lock`,
  `cli/go.mod`, `frontend/pnpm-lock.yaml`, 1 `.venv` egg). Floor re-executed
  after the bump (see Code Quality Gate) — green.
- Note: the 2026-11-12 configmap re-verification recorded "Trivy: not
  configured (security: absent) — manual mode", but the `security.trivy`
  block was already present in `config.yaml` at that tree (`cc32ab72`) —
  this gate is the first to execute it.

**Secrets archaeology:** no credentials/keys in the change (view pair + dict
rows + tests; the demo fixture is a public demo RuntimeClass).

**OWASP spot-check:** input surface = `?name`/`?namespace` query params on
the generic route (SAR-gated BEFORE the client call — tested + LIVE); all
output React-escaped (name cells, CTable cells, SyntaxHighlighter AST text
nodes — no `dangerouslySetInnerHTML` in `react-syntax-highlighter` `dist/esm`
per the 2026-11-12 security axis, which traced 13 dropped candidates
entry-point→sink). The parked SAR-cache-key `:`-delimiter finding
(CWE-649) is **verified fixed at this tree**: `rbac.py::_cache_key` builds
every segment with `quote(str(x), safe='')` (injective). Read-only change;
no state mutation. Clean.

## Code Quality Gate

| Gate | Command (at final tree, 2026-11-13) | Result |
|------|--------------------------------------|--------|
| Backend unit floor | `uv run pytest -m "not integration" -q` | **890 passed, 10 deselected, 0 failed** (266 s) — re-run AFTER the certifi bump: green |
| Frontend targeted | `vitest run runtime_classes.runtime_class_data.Stub` | **15 passed (3 files)** — re-run AFTER the dependency bump: green |
| Frontend full | `corepack pnpm test` | **502/502** pre-bump (84.8 s); post-bump runs 501–502/502 with ONE load-dependent flake: `Clusters.test.tsx > admin creates a cluster from the add dialog` — PRE-EXISTING on this tree (the 2026-11-12 configmap re-verification recorded the same failure at `cc32ab72`), standalone 3/3 green (6/6 tests each), **no code path to dompurify** (monaco-editor — dompurify's only parent — has zero import sites across `src/` + `tests/`; the bundle is byte-identical post-bump), owned by the in-flight `2026-11-10-ha-status-page` change (gate pending — W037 follow-through). (The 13 declared-baseline failures at the original gate — users 7 / groups 4 / admin_permissions 1 / node-detail-renders 1 — were fixed by later changes, e.g. `100d3f84`.) |
| Build + air-gap | `task fe-build` + `task fe-check` + `task fe-sync` | green — fe-build re-executed AFTER the dependency bump (tsc --noEmit incl. tests + eslint + vite, 43 s): **bundle byte-identical** (fe-sync stamp `1b8bb654aab6…` unchanged — `monaco-editor` has ZERO import sites across `src/` + `tests/`, so dompurify is a template-tree dependency trivy sees in the lockfile but the SPA never bundles); air-gap assertion on `frontend/dist` passed |
| Lint (backend, scoped) | `uv run ruff check` on `k8s_client.py` / `resources.py` / `test_resources.py` / `test_k8s_client_runtimeclasses.py` | 2 findings, both pre-existing E501 in `k8s_client.py` (line 812 pod-condition, line 2118 HPA getter — the configmap gate's recorded baseline 812/2118); **zero on runtimeclass lines** |
| Typecheck (backend) | `uv run mypy app` | 65 findings in 15 files — **identical to the configmap gate baseline**; the only k8s_client hits (233/414/429/465/840) are pre-existing (`_verify` redef, CRD `get_crd`); **zero on runtimeclass lines** |
| e2e (runtimeclass leg) | `playwright test e2e/ui-smoke.spec.ts --grep "stub routes"` | **1 passed (6.0 s)** — `/other-resource/runtimeclass` mounts on the live stack and renders "Runtime Classes" exact |
| e2e (full suite) | `task e2e` | not run — the serial chain breaks at `login → /clusters renders the bound-cluster registry` (W037: the in-flight ha-status `/clusters` rename, ha-status gate pending); the runtimeclass leg passes standalone (above). Named re-run path: `task e2e` after W037 closes |
| Trivy | `trivy fs . --scanners vuln --severity CRITICAL` | **0 CRITICAL** after the gate's dependency bump (initial: 2 pre-existing CRITICAL — see Security Audit) |
| Scope (byte-identity to the reviewed revision) | `git diff 5f8d9c61..HEAD -- backend frontend cli` | **empty** — the live code is exactly the code the three-axis review verified on 2026-11-12 |
| Scope (drift since the original gate) | `git log aead16a7..HEAD` over the change's file set | every runtimeclass-file commit attributable to a named change: `89528a32` (ObjectRoute migration, separate change, QA PASS), `7ba9bf75` (share-button removal), `debdf9e6` (breadcrumb affordance), `1802d456` (test-fake migration), `0360044d` (review fix), `d4c28e05` (shared-gate hardening, test file) |

## Duplication

N/A — `duplication.command` unset (advisory). The views follow the ratified
PriorityClass clone pattern; the 2026-11-07 dead-code-cleanup change
measured whole-tree jscpd health (32/E → 55/C) AFTER this change landed.

## State Drift

None — the change is shipped and archived (`6e4504d3`): correctly absent
from `state.yaml` (ship close-out; same pattern as the pv-views /
storageclass / pvc archive close-outs). No `_nav.tsx` / schema /
identity-drift in the 4 change commits. The gate's dependency bump is a
tree-level fix committed separately, not a state drift.

## Review Debt Surfaced (prior parked findings touching this change's files)

- **W022** (open, `2026-10-28-other-resource-views`): the
  `_KINDS["horizontalpodautoscalers"]` SAR row uses the wrong group —
  different kind row in the same shared file; the runtimeclasses row is
  verified correct (`node.k8s.io` pinned by the SAR-denied test + LIVE 200).
  No impact.
- **Parked review findings** (`review.md`): the get-SAR namespace-`"default"`
  coercion (pre-existing shared route, verdict correct — K8s ignores
  namespace for cluster-scoped resources; live-verified) and the two
  unasserted Then-clause legs (1:1 with the mandated priorityclass
  precedent) stand as parked. The SAR cache-key `:`-delimiter finding is
  **verified fixed** at this tree (percent-encoded segments, `rbac.py`).

## Verification Scope

| Scope | Derivation | Status |
|-------|-----------|--------|
| Change code | all 4 change commits + the review fix; both views + both test files read; byte-identity to the reviewed revision proven (`git diff 5f8d9c61..HEAD -- backend frontend cli` empty) | COMPLETE |
| Change tests | 6 API tests + 4 service tests + 10 view tests read (titles + key assertions) | COMPLETE |
| Spec zone | briefing, acceptance (13 scenarios), blueprint (must-haves, file structure), adr (incl. the superseded navigation clause), NAVIGATION-SUPERSEDED, review record — all read | COMPLETE |
| Runtime | live API (5 probes: list / hit / miss / namespace-ignored / singular) + live browser (list render → click → detail at clean URL → legacy-URL redirect) on `kubedash.dev.local:8080` | COMPLETE |
| Floor commands | all floor commands re-executed at the current tip — AND re-executed again after the gate's dependency bump | COMPLETE |

Out-of-scope intersections (named, not scope gaps): W037 (the e2e serial
chain break, ha-status-owned) and the pre-existing lint debt in
`k8s_client.py` (other kinds' lines).

## Floor

| Dimension | Weakest result | Verdict |
|-----------|----------------|---------|
| Verification floor (blueprint) | all commands green at the final tree (twice: pre- and post-bump) | PASS |
| Goal-backward | every truth VERIFIED (named tests + LIVE API + LIVE browser) | PASS |
| Traceability | 13/13, 0 pending | PASS |
| TDD evidence | co-commits resolve; no ledger (SUGGESTION W040) | PASS |
| Assertion quality | 0 CRITICAL / 0 WARNING | PASS |
| Security | Trivy 0 CRITICAL after the gate's fix loop (initial FAIL fixed); OWASP clean; 0 change deps | PASS |
| Code quality | all gates PASS (scoped ruff/mypy clean on runtimeclass lines; e2e leg 1/1) | PASS |
| Verification scope | all derivations COMPLETE | PASS |

Floor = **PASS** (the mean is never the verdict; no dimension below PASS).

## Findings

### CRITICAL (must fix before merge)

None open. (The 2 initial Trivy CRITICALs were fixed at this gate — see
Security Audit.)

### WARNING

None.

### SUGGESTION

- **W040** — No `.skillgrid/meta/.sdd/2026-10-28-runtimeclass-views/`
  execution ledger and no per-task RED/GREEN table (executed 2026-10-28 as
  4 co-committed `feat` units, `718eda35..786100f5`). The original batch
  gate accepted the co-commit shape (24/24 task units OK); behavior
  coverage is complete (13/13 named tests). Retrofit class of
  W015/W021/W030/W039.
- **W041** — `review.md` (Spec axis) records "11/11 scenarios PASS";
  `acceptance.feature` carries 13 `Scenario:` headers. Review-record
  undercount with no coverage gap (this gate maps all 13 to passing tests).
  Reconcile the review record at the next opportunity.

## Gate Decision

**PASS** (re-rendered after the fix loop).

First render at tree `b98c53cf` was **FAIL** on exactly one criterion —
PASS criterion 10 / FAIL criterion "a Trivy finding at or above
`security.trivy.fail_on` (CRITICAL)": 2 pre-existing lockfile CRITICALs
(certifi GHSA-6q48-6c7w-9gw2, dompurify GHSA-cg2g-xh64-v4q7), neither
introduced by this zero-dependency change. The gate's fix loop bumped both
(certifi → 2026.10.23 via `uv lock --upgrade-package`; dompurify → 3.4.17
via `pnpm.overrides` for monaco-editor's exact pin), re-executed the full
floor (green), and re-ran Trivy (0 CRITICAL). All other criteria met on the
first render: 13/13 scenarios covered by passing tests, every truth
VERIFIED by named tests + live evidence, TDD evidence clean, assertion
quality clean, all code-quality gates PASS, verification scope COMPLETE.

The re-verification confirms the change remains delivered at the current
tip: the live code is byte-identical to the revision the three-axis review
verified (2026-11-12), the ADR-0040 navigation migration is in force
per the recorded `NAVIGATION-SUPERSEDED.md`, and the SAR-gated read
contract is live-verified end to end.

## Human Override

None — the machine verdict stands.

---

## Final-State Facts

- **Shipped:** 2026-11-12 (`6e4504d3` — archive spec zone + state close-out), branch
  `rebase`, single-branch delivery (no PR chain — `a9836b84`). The RuntimeClass
  list + data views at `/other-resource/runtimeclass` (ObjectRoute shape,
  ADR-0040) and the backend `runtimeclasses` kind (node.k8s.io, cluster-scoped,
  SAR-gated) are in tree and live-verified 2026-11-13 (this gate).
- **Final code state:** byte-identical to the reviewed revision
  (`git diff 5f8d9c61..HEAD -- backend frontend cli` empty); the only tree
  change at this gate is the dependency bump (`1b50a09e`).
- **Navigation contract:** the spec's `?name=` query-param navigation is
  SUPERSEDED by ADR-0040 session object refs (`NAVIGATION-SUPERSEDED.md`);
  legacy `/data?name=` URLs one-shot-redirect to the clean route (verified
  live 2026-11-13).
- **Gates:** QA PASS (re-verified 2026-11-13, re-rendered after the Trivy fix
  loop); three-axis review 2026-11-12 — floor met-with-fixes, 0 Critical /
  0 Important pre-merge. Tracker: TASK-046 Done.

## Sourced Learnings

**Decisions**

- The first executed Trivy gate FAILed on 2 pre-existing lockfile CRITICALs;
  the fix landed as a gate-scoped dependency bump (`1b50a09e`) rather than a
  separate change — tradeoff: gate speed vs change purity; both CVEs had
  published fixes and the change's own dependency diff was empty. —
  `report.md` Security Audit
- The dompurify override lives in `pnpm-workspace.yaml`, not `package.json` —
  pnpm v12 ignores the `pnpm` field (install warning); `monaco-editor@0.57.0`
  pins `dompurify: 3.4.15` exactly (no caret), so the override is the only
  minimal lever. — `frontend/pnpm-workspace.yaml:5-8`, `node_modules/monaco-editor/package.json:107`

**Lessons**

- The configmap re-verification (2026-11-12) recorded "Trivy: not configured
  (security: absent) — manual mode", but the `security.trivy` block was
  already present in `config.yaml` at that tree (`cc32ab72`) — a config
  assertion carried from an earlier gate instead of read at gate time.
  **Process bug** (reusable: any gate config read) — governs the `qa` skill's
  config step. Open Item. — `config.yaml:50-56` vs
  `change-specs/2026-10-28-configmap-views/report.md` Security Audit
- No per-task RED/GREEN table or execution ledger exists for this change
  (batch gate accepted the co-commit shape). Same retrofit class as
  W015/W021/W030/W039 → W040. — `report.md` TDD Evidence Audit

**Patterns**

- **Byte-identity-to-reviewed drift check** — for re-verifying a shipped
  change, `git diff <review-commit>..HEAD -- backend frontend cli` empty is
  the cheapest COMPLETE-scope proof: the review's three-axis evidence
  carries over unchanged, and the re-verification re-runs only floor +
  live. — `report.md` Scope rows
- **Archived-change gate record placement** — the gate record for a shipped
  change lands in the archive folder (`report.md`); a batch-hosted change
  keeps its original gate in the batch spec folder; the `state.yaml` entry
  is correctly absent after ship close-out (repo convention, 6 shipped
  changes). — `state.yaml`, `.skillgrid/change-archive/`

**Surprises**

- `monaco-editor` has **zero import sites** across `src/` + `tests/` — the
  SPA bundle is byte-identical post-bump (fe-sync stamp `1b8bb654aab6…`
  unchanged) yet Trivy still sees its exact-pinned dompurify in
  `pnpm-lock.yaml`. Lockfile CVEs and bundle content are decoupled; a
  dependency bump can be bundle-neutral. — fe-sync output,
  `grep -r monaco src/ tests/` (0 hits)
- `uv lock --upgrade-package` silently bumped the lockfile format
  `revision = 2 → 3` — CI-safe only because `setup-uv@v3` is unpinned
  (latest uv). A pinned-uv CI would need the pin raised with it. —
  `backend/uv.lock:2`, `.github/workflows/ci.yaml:21`
- **mnemonic CLI close-out UX** — `memory save` fails with an opaque
  `FOREIGN KEY constraint failed` unless a session row exists first;
  `memory session start` requires `--id` (undocumented — the subcommand
  rejects `--help`); `topic-key` validation rejects hyphenated single words
  with a misleading "at most two levels" message (plain single words pass).
  — CLI session 2026-11-13

## Acceptance Verdict

**accepted** — the briefing goal (resolve the dead nav leaf to a real,
SAR-gated, read-only list + data pair; 4.1 parity in placement/RBAC; 5.0
PriorityClass shape) is met: 13/13 scenarios passing, every truth
live-verified (API 5/5 probes + browser list→detail), stub removed, nav
byte-identical. Open items are SUGGESTION-class (W040/W041) and
cross-cutting (W037 ha-status e2e chain; the ha-status full-suite flake) —
none touch this change's contract.

## Prior-Change Follow-Through

- **W008** (batch: e2e REAL_ROUTES covers only limit-range) — for
  runtimeclass the 2026-11-12 review added a title-asserting
  `SMOKE_STUB_ROUTES` entry instead (`0360044d`); the class is partially
  mitigated per-kind, window stays open for the remaining kinds.
- **W010/W012** (session-object-navigation: ui-smoke wired into `task e2e`,
  CRD fixture) — closed before this change shipped; this change's e2e leg
  runs inside the wired chain except for W037's serial break.
- **W037** (ha-status `/clusters` rename breaks the e2e serial chain) —
  still open, ha-status gate pending; this change's leg ran standalone 1/1.
- **W022** (HPA SAR group) — still open, different kind row; the
  runtimeclasses row verified correct at this gate.

## Web-cache Promotion Candidates

No web-cache promotion candidates — no web research during this change's
span (no `web_cache` entries to select).

## Environment Retro

Sweep of this session only (navigation / automated checks / coding standards
/ steering-file no-ops / tool economy / information access):

| Category | Finding (sourced) | Fix lands in |
|----------|-------------------|--------------|
| Automated checks | Trivy gate configured (`fail_on: CRITICAL`) but not executed by ~2 weeks of gates; the configmap re-verification carried a stale "security: absent" config read | `qa` skill: read `config.yaml` at gate time, never carry config assertions between gates (Open Item — process bug) |
| Tool economy | mnemonic CLI: `memory save` → opaque FK error without a session row; `memory session start --id` undocumented (subcommand rejects `--help`); topic-key validation message misleading for hyphenated keys | mnemonic CLI help/validation (follow-up ticket candidate) |
| Navigation | `qa <topic>` on a shipped change: `change-specs/` glob empty, folder in `change-archive/` — a repo-wide search is required to resolve the topic | `qa` skill: one-line archived-topic resolution note (minor) |
| Steering files | pnpm v12 ignores the `package.json` `pnpm` field (install warning); overrides belong in `pnpm-workspace.yaml` | one-off — WHY comment at `frontend/pnpm-workspace.yaml:5-8` |
| Coding standards | none this session | — |
| Information access | monaco-editor is a trivy-visible, bundle-invisible dependency (0 import sites) | one-off — recorded in Surprises |

## Lineage

- **Review** (2026-11-12, three-axis, Grade B per axis — fresh subagent
  contexts, same model family): floor met-with-fixes; 0 Critical /
  0 Important pre-merge; 3 Minor FIXED (`0360044d`: false e2e-smoke claim,
  ADR-0022 stale row, empty-`{}`-overhead cell); 4 PARKED (shared-route
  namespace coercion, 2 unasserted Then-legs, SAR cache-key — verified fixed
  at this gate, 13 dropped candidates). — `review.md`
- **Mnemonic observation IDs:** 13 (`2026-11-12-runtimeclass-views-review`
  session summary). No per-artifact (briefing/blueprint/tasks) observations
  exist for this change — consistent with W040 (no execution ledger).
- **Gate records:** `report.md` (this file — QA half 2026-11-13) +
  `.skillgrid/change-specs/2026-10-28-other-resource-views/qa-report.md`
  (batch-of-6 host, 2026-10-29 PASS at `aead16a7`).
- **Commits:** `718eda35..786100f5` (change, 4 units) · `89528a32` (ADR-0040
  migration, separate change) · `0360044d`/`5f8d9c61` (review fix/record) ·
  `6e4504d3` (ship) · `1b50a09e`/`e8813ac4` (this gate: deps bump, report).

---

*Cycle closed 2026-11-13 — reflect (session `reflect-runtimeclass-20261113`).*
