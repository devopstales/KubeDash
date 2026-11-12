# Report — ConfigMap Views (List + Data)

**Change:** `2026-10-28-configmap-views` · **Gate:** QA 2026-11-12
**Effective tier:** T1 (blueprint header) — additive view pair on the existing
generic `/resources` route; `low-risk` classification floor (L1 + runtime
verification) met.
**Quality config:** `quality:` / `testing:` / `security:` / `duplication:`
absent from `.skillgrid/config.yaml` — gates run per the blueprint
Verification Floor + AGENTS.md commands (repo QA practice 2026-10-29 →
2026-11-11; coverage % untracked by repo convention, no coverage command
configured).
**Tree note:** gate ran at tip `ebf93a5f` + uncommitted
`2026-11-10-ha-status-page` WIP (clusters.py / Clusters views + tests /
useCluster.ts / types.ts / ClusterStatus) — that WIP is a separate change
and is named wherever it intersects this gate's evidence.

## Test Plan

### Risk Ranking

- **P0** (production/data): R1 list endpoint contract (200/to_dict/data NOT
  stripped/SAR-before-client/403/binding-404/singular-reject), R2 name
  lookup (0/1-item, `[]` on miss). A broken read or wrong SAR group fails
  every ConfigMap consumer and the Data Keys column.
- **P1** (experience): R3 list rendering (title, columns, Data Keys
  semantics, states), R4 data rendering (metadata table, per-key `<pre><code>`,
  JSON block, not-found-as-state), R5 routing/stub removal.

### Plan

| # | Behavior | Scenario | Named test (layer) | Cadence | Status |
|---|----------|----------|--------------------|---------|--------|
| 1 | List 200, to_dict, data present | configmaps-list-200 | `test_list_configmaps_200_in_namespace` + service `test_list_configmaps_namespaced_keeps_data` (API/unit) | pr | ran PASS (888-run) |
| 2 | All-namespaces branch | configmaps-list-all-namespaces | `test_list_configmaps_all_namespaces_without_param` + service `test_list_configmaps_all_namespaces_without_namespace` | pr | ran PASS |
| 3 | SAR deny 403, client never called | configmaps-sar-denied | `test_list_configmaps_sar_denied` (asserts `("list","configmaps","team-a",None,"")` recorded before read) | pr | ran PASS |
| 4 | Binding gate 404 | configmaps-binding-404 | `test_configmaps_binding_404` | pr | ran PASS |
| 5 | Singular kind rejected | configmap-kind-singular-rejected | `test_configmap_kind_singular_rejected` | pr | ran PASS |
| 6 | Name lookup hit/miss | configmaps-get-by-name | `test_list_configmaps_get_by_name` + service 404/hit tests | pr | ran PASS |
| 7 | List rows + name→detail | configmap-list-renders-rows-with-data-links | `list-renders-configmap-rows-with-data-links` + `click-name-renders-detail-with-clean-url` + `click-name-carries-row-namespace` (RTL/MSW, ADR-0040 shape per NAVIGATION-SUPERSEDED.md) | pr | ran PASS (18-run) |
| 8 | Data Keys count semantics | configmap-list-data-keys-column | `list-data-keys-column` (2 → "2", {} → "0", absent → "—") | pr | ran PASS |
| 9 | binaryData not counted | configmap-list-never-counts-binarydata | `list-never-counts-binarydata` | pr | ran PASS |
| 10 | Empty state | configmap-list-empty-state | `list-empty-state` | pr | ran PASS |
| 11 | No-cluster state, no fetch | configmap-list-no-cluster | `list-no-cluster-state` (asserts 0 fetches) | pr | ran PASS |
| 12 | Data detail render | configmap-data-renders-detail | `data-renders-detail` (single fetch, CTable rows, T2-trimmed annotations, per-key rows, JSON block) | pr | ran PASS |
| 13 | Plain `<pre><code>` value | configmap-data-value-is-plain-pre | `data-value-is-plain-pre` (pre-wrap, no svg/button toggle) | pr | ran PASS |
| 14 | Missing data field | configmap-data-missing-data | `data-missing-data` ("No data", no `.text-danger`) | pr | ran PASS |
| 15 | Miss = not-found state | configmap-data-not-found-state | `data-not-found-state` (pinned copy, no error style) | pr | ran PASS |
| 16 | Missing name param | configmap-data-missing-name | `data-missing-name` (pinned error, 0 fetches) | pr | ran PASS |
| 17 | Stub removed, routes wired | configmap-stub-removed-and-routes-wired | `Stub.test.tsx` viewPaths + `ui-smoke` REAL_ROUTES (e2e real-routes leg) + `_nav.tsx` byte-identity (commit scope) | pr | ran PASS (real-routes 1/1, 2026-11-12) |

Layer selection: API contract at the API tier (Flask test client + FakeK8s
with recorded calls — the layer that proves SAR-before-client and namespace
forwarding); client-mapping at the unit tier (`object.__new__` +
SimpleNamespace, repo convention); view behavior at RTL/MSW (the highest
layer that fits without a live backend; e2e adds the live-stack mount
smoke). No duplicate coverage: the service tests assert the client branch
+ `to_dict` mapping the API tests can't see; the e2e real-routes leg
asserts live mount, which the unit layers can't.

### Edge-Case Matrix

| Edge | Variant | Covered by |
|------|---------|-----------|
| Data Keys: `data == {}` | "0" not "—" | list-data-keys-column |
| Data Keys: `data` absent | "—" | list-data-keys-column |
| Data Keys: binaryData-only | "—" (data-only count) | list-never-counts-binarydata |
| List: empty | first-class empty state | list-empty-state |
| List: no cluster | "No cluster selected.", no fetch | list-no-cluster-state |
| List: API error | red error line, no rows | list-error-state |
| SAR: deny | 403 before client call | test_list_configmaps_sar_denied |
| Transport: 500 | ClusterUnreachableError (502) | service maps_500/other_api_error tests |
| Lookup: miss | `[]` → not-found STATE | data-not-found-state |
| Data: absent | "No data" | data-missing-data |
| Kind: singular | 404 RESOURCE_KIND_NOT_SUPPORTED | test_configmap_kind_singular_rejected |
| Row namespace ≠ store namespace | ref follows the row (ADR-0040 R8) | click-name-carries-row-namespace |

### Out of Scope

- `binaryData` first-class display (briefing non-goal; covered by the JSON
  block).
- Create/edit/delete (read-only change).
- All-namespaces LIST mode on the page (API branch only, tested at API tier).
- The ha-status `/clusters` page rewrite (uncommitted WIP, separate change).

## Goal-Backward Verification

All blueprint truths VERIFIED — named tests ran green at the current tip, and
the surface was exercised on the running dev stack
(`kubedash.dev.local:8080`, 2026-11-12):

| Truth | Evidence |
|-------|----------|
| List 200 / kind / to_dict / data NOT stripped | `test_list_configmaps_200_in_namespace` PASS; LIVE: `GET /api/v1/clusters/0/resources/configmaps?namespace=kubedash-demo` → `kind: configmaps`, demo-config `data` present (3 keys), `creation_timestamp` snake_case |
| All-namespaces branch | `test_list_configmaps_all_namespaces_without_param` PASS (FakeK8s records `None`) |
| SAR before client, core group `""` | `test_list_configmaps_sar_denied` PASS (`("list","configmaps","team-a",None,"")` recorded) |
| `?name=&namespace=` 0/1-item | `test_list_configmaps_get_by_name` PASS; LIVE: hit → 1 item w/ data, miss → `[]`, singular → 404 |
| List view: exact title, columns, fetch ns | `list-renders-configmap-rows-with-data-links` PASS; LIVE browser: "Configmaps List" heading, Name/Data Keys/Created, demo-config row |
| Data Keys semantics | `list-data-keys-column` + `list-never-counts-binarydata` PASS; LIVE: demo-config cell = "3" (three real data keys) |
| Data view: single fetch, CTable, per-key `<pre><code>`, JSON block, not-found state | `data-renders-detail` + 4 sibling tests PASS; LIVE: click → "Configmap Data" card at clean URL (`?name=`/`token=` absent), log-level:/feature-flags:/app-config: rows, JSON block contains `"log-level"` |
| Stub removed, routes wired, nav unchanged | `Stub.test.tsx` PASS; e2e real-routes leg 1/1 PASS (includes `/storage/configmap`); commit scope: `_nav.tsx` absent from all 4 commits |

## Traceability Matrix

17/17 scenarios mapped (table above). 0 UNTESTED, 0 FAILING, 0 PARTIAL, 0
pending. The data-link scenarios of the superseded query-string contract are
satisfied in the ADR-0040 shape per this spec's `NAVIGATION-SUPERSEDED.md`
(name cell opens the object ref; detail renders at the clean list route) —
the `/data` URL never shipped for this kind, so no R7 redirect exists. The
`configmap-data-renders-detail` annotations clause (verbatim) is satisfied as
amended by the recorded 2026-11-05 T2 override (adr.md OVERRIDE note; the
test pins the trim).

## Verification-Gap Audit

- **PRESENT_BEHAVIOR_VERIFIED** for every load-bearing path: the
  `list_configmaps` all-namespaces branch (the API test records `None`
  against the FakeK8s, so the branch is exercised, not merely present); the
  404→`[]` mapping (service test + live miss); the Data Keys ternary (three
  RTL fixtures covering both branches + the binaryData edge); the NOT_FOUND
  throw→state path (RTL + live not-found check pattern).
- **Regression gaps:** none found — the `data`-NOT-stripped invariant (the
  blueprint's named future-breaker: a `list_secrets`-style strip would
  silently break Data Keys to all "—") is pinned at BOTH tiers (service test
  asserts `data` in the result; API test asserts it in the body), and the
  docstring states why.
- **Missing-oracle gaps:** none — every happy path has a named `G`-equivalent
  (the `[scenario]` docstring tags / test names).

## TDD Evidence Audit

| Task | Commit | Test files | RED→GREEN |
|------|--------|-----------|-----------|
| T1 backend kind | `41620987` (resolves) | `tests/api/test_resources.py` +150, `tests/services/test_k8s_client_configmaps.py` +105 (new) | co-commit (W015 precedent); RED from the execution session (no ledger — SUGGESTION, W039) |
| T2 list view | `373e7042` (resolves) | `tests/views/configmaps.test.tsx` +346 (new) | co-commit |
| T3 data view | `b08f2bb8` (resolves) | `tests/views/configmap_data.test.tsx` +243 (new) | co-commit |
| T4 routing | `c966685e` (resolves) | `tests/views/Stub.test.tsx` +4, `e2e/ui-smoke.spec.ts` (REAL_ROUTES move) | co-commit |

No `MISSING_RED`, no `STALE`. 2026-11-05 T2 amendment (trimAnnotations,
`f7c8223d`-wave, verified at the pv-views gate) updated the data view + the
`data-renders-detail` assertions together — current.

## Assertion Quality Audit

All 18 frontend tests + 12 backend tests read in full:
- No tautologies, no ghost loops, no assertion-without-code-call: every
  assertion binds a production observable (MSW-requested URL/params,
  `fetchCount`, rendered text/role, recorded FakeK8s calls, response
  envelope codes).
- Strongest pins verified: `("list","configmaps","team-a",None,"")` SAR
  tuple (group + namespace load-bearing), `configmap_ns_calls == [None]`
  branch discrimination, `seen: [] = 0 fetches` in the no-name/no-cluster
  tests, `dataKeysOf` exact-cell reads, `inTable(...)` scoping (value
  repeats in the JSON block — the tests scope to `<table>` to avoid
  false-positive matches).
- One stale COMMENT (not an expectation) in `configmap_data.test.tsx` above
  `appConfig` ("trimAnnotations is NOT replicated") contradicted the T2
  assertions below it — **fixed at the gate** (comment-only, no behavior).

## Changed-File Coverage

N/A — no coverage command configured; repo QA practice (2026-10-29 →
2026-11-11 gates) tracks the suite + named scenarios, not %. Scenario-level
coverage is 17/17 (traceability matrix).

## Test Quality Audit

Fixtures are realistic `to_dict` shapes (snake_case metadata, `resource_version`,
the kubectl noise annotation that exercises the T2 trim). The FakeK8s
`list_configmaps` uses a DISTINCTLY-named all-namespaces item (team-b) so
branch tests can't pass against the namespaced branch (the
`list_network_policies` precedent). MSW handlers assert the exact
`?name=&namespace=` params (a wrong URL → 500 → red).

## Test Strategy Audit

No wrong-layer tests: the client branch mapping lives at unit tier (no Flask
needed), the SAR/binding/404 contract at API tier (the layer that owns it),
view states at RTL, and the live mount at e2e. No e2e for unit-covered
behavior beyond the mount smoke.

## Security Audit

**Trivy:** not configured (`security:` absent) — manual mode.
- **Secrets archaeology:** no credentials/keys in the change (view pair +
  dict rows + tests; the demo fixture values are non-secret demo config).
- **Dependency audit:** zero new dependencies — `git show --stat` over the 4
  commits touches no `package.json`/`pnpm-lock.yaml`/`pyproject.toml`/
  `uv.lock` (ADR-0020; `react-syntax-highlighter` already vendored via
  SecretData).
- **OWASP spot-check:** input surface = `?name`/`?namespace` query params on
  the generic route (SAR-gated BEFORE the client call — tested); all output
  is React-escaped (name cells, `<pre><code>` text nodes, SyntaxHighlighter
  tokens); no `dangerouslySetInnerHTML`, no `atob` on untrusted data, no
  `innerHTML`. Read-only change; no state mutation. Clean.

## Code Quality Gate

| Gate | Command (at tip 2026-11-12) | Result |
|------|------------------------------|--------|
| Backend unit floor | `uv run pytest -m "not integration" -q` | **888 passed, 10 deselected** (includes all 12 configmap tests) |
| Frontend targeted | `vitest run configmaps.configmap_data.Stub` | **18 passed (3 files)** |
| Frontend full | `vitest run` | 500 passed / 2 failed — both triaged OUT of this change's scope: `Clusters.test.tsx > admin edits a cluster…` is a NEW test in the uncommitted ha-status WIP (0 occurrences at HEAD, +6 tests in the working diff); `network_policies.test.tsx > route-consumes-incoming-meta…` is a timing flake (8/8 on two standalone re-runs, 11s/9s) |
| Build + air-gap | `task fe-build` + `task fe-check` | green (build 15.9s; air-gap check passed) |
| Lint (backend) | `uv run ruff check .` | 62 findings, all pre-existing debt in OTHER kinds' files (k8s_client 812/2118, crds/gateway_api/limitranges test files); **zero in configmap files** (resources.py / test_resources.py / configmap lines) |
| Typecheck (backend) | `uv run mypy app` | 65 findings; **zero in configmap lines** (k8s_client hits at 233/414/429/465/840 are pre-existing: `_verify` redef, CRD `get_crd`) |
| Typecheck + lint (frontend) | via `task fe-build` (tsc --noEmit incl. tests + eslint) | green |
| e2e (configmap leg) | `playwright test e2e/ui-smoke.spec.ts -g "real routes"` | **1 passed (7.3s)** — every REAL_ROUTES incl. `/storage/configmap` mounts without JS crash on the live stack |
| e2e (full suite) | `task e2e` | 3 passed / 1 failed / 16 not run — the failure is `login → /clusters renders the bound-cluster registry` (the uncommitted ha-status `/clusters` rewrite renamed "Bound clusters" → "Kubernetes Server List"; the spec expectation belongs to that change) which breaks the serial chain. Named re-run path: `task e2e` after the ha-status change updates the expectation |
| Scope | commit `--stat` over `41620987..c966685e` | `_nav.tsx` absent ✓; files = File Structure list + `dev/scripts/demo-data.sh` (demo-config fixture) + `e2e/ui-smoke.spec.ts` (REAL_ROUTES move) — see SUGGESTION W038 |

## Duplication

N/A — `duplication.command` unset (advisory). The views follow the ratified
namespaced-kind pattern (Secret/SecretData clone with the plain-`<pre>`
delta); the 2026-11-07 dead-code-cleanup change verified whole-tree jscpd
health (32/E → 55/C) AFTER this change landed.

## State Drift

None — no `state.yaml`/`_nav.tsx`/schema/dependency drift in the 4 commits.
`state.yaml` phase pointer updated by this gate (executed → qa).

## Verification Scope

| Scope | Derivation | Status |
|-------|-----------|--------|
| Change code | all 4 commits' `--stat` read in full; every changed file read (service methods, both views, wiring, fixture, e2e delta) | COMPLETE |
| Change tests | all 18 frontend + 12 backend tests read in full | COMPLETE |
| Spec zone | briefing, acceptance (17 scenarios), blueprint (must-haves, floor, tasks), adr (incl. T2 OVERRIDE), NAVIGATION-SUPERSEDED read in full | COMPLETE |
| Runtime | live API (list/all-ns/hit/miss/singular via authenticated curl) + live browser (login → cluster → namespace → list → click → detail, real demo-config data) on `kubedash.dev.local:8080` | COMPLETE |
| Floor commands | all blueprint-floor commands re-executed at the current tip (not carried from 2026-11-05) | COMPLETE |

Out-of-scope intersections (named, not scope gaps): the uncommitted
ha-status WIP (its Clusters test failure + the e2e /clusters expectation)
and the pre-existing lint debt in other kinds' files.

## Floor

| Dimension | Weakest result | Verdict |
|-----------|----------------|---------|
| Verification floor (blueprint) | all 4 commands green at tip | PASS |
| Goal-backward | every truth VERIFIED (tests + live) | PASS |
| Traceability | 17/17, 0 pending | PASS |
| TDD evidence | co-commits, hashes resolve; no ledger (SUGGESTION) | PASS |
| Assertion quality | 0 CRITICAL/WARNING; 1 stale comment fixed at gate | PASS |
| Security | manual mode clean; 0 deps | PASS |
| Code quality | all gates PASS (2 full-vitest fails triaged out-of-scope) | PASS |
| Verification scope | all derivations COMPLETE | PASS |

Floor = **PASS** (the mean is never the verdict; no dimension below PASS).

## Findings

### CRITICAL (must fix before merge)

(none)

### WARNING (should fix before archive)

- **W037 (ha-status-owned):** `task e2e` ui-smoke serial chain is broken at
  `login → /clusters renders the bound-cluster registry` — the uncommitted
  ha-status `/clusters` rewrite ("Kubernetes Server List" parity) dropped
  the "Bound clusters" heading the spec still expects; the 16 downstream
  serial tests (incl. every other real/stub route) don't run in a full
  `task e2e`. Configmap's own e2e leg (real-routes) passes standalone. The
  ha-status change must update the expectation (and its own Clusters.test)
  before its gate.

### SUGGESTION (nice to have)

- **W038:** blueprint File Structure drift — `c966685e` also touched
  `dev/scripts/demo-data.sh` (demo-config fixture: the multi-line value that
  exercises the `<pre><code>` wrap) and `e2e/ui-smoke.spec.ts` (stub→real
  REAL_ROUTES move) beyond the blueprint's file list. Both load-bearing;
  reconcile the blueprint at archive time.
- **W039:** no `.skillgrid/sdd/2026-10-28-configmap-views/` execution ledger
  and no per-task RED/GREEN table for the TASK-064 execution (2026-11-04,
  on-demand storage-batch slicing) — retrofit class of W015/W021/W030;
  behaviour coverage is complete (17/17 named tests, 4 co-commit hashes
  resolve).

## Gate Decision

**PASS** (machine) — all truths VERIFIED; 17/17 scenarios covered by tests
that ran and passed at the current tip; e2e real-routes leg (incl.
`/storage/configmap`) re-run green standalone 2026-11-12; no CRITICAL
findings; no MISSING_RED/STALE; code-quality gates PASS; P0/P1 100%;
verification scope COMPLETE. Findings: 0 CRITICAL / 1 WARNING (out-of-scope,
ha-status-owned) / 2 SUGGESTION + 1 SUGGESTION fixed at the gate (stale
comment).

## Human Override

(none)

---
## Final-State Facts

(reflect)

## Gates

(reflect)

## Decisions

(reflect)

## Lessons

(reflect)

## Patterns

(reflect)

## Surprises

(reflect)

## Environment Retro

(reflect)

## Acceptance Verdict

(reflect)

## Open Items (→ next change)

(reflect)

## Web-cache promotion candidates

(reflect)

## Prior-Change Follow-Through

(reflect)

## Move Evidence (from ship context)

(reflect)

## Overrides / Waivers / Contradictions

(reflect)
