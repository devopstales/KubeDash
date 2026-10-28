# QA Report — 2026-10-26-network-policy

**Tier:** T2 (briefing.md) → verification floor L2: full backend unit suite +
`corepack pnpm test` + `task fe-build` + `task fe-check`. The kind-gated
backstops (Task 5) ran on the live `kubedash-test` cluster.
**Executed:** 2026-10-28 on `rebase`, in place (user-confirmed).
**HEAD:** 98497d24 (Task 5 commit; the branch later gained priority-class
commits from a sibling spec — out of scope here).

## Test Plan

Layer per behavior: backend API/service = unit (FakeK8s + `object.__new__`
pattern, the established seam); live-apiserver shape = integration (kind,
`-m integration`); frontend views = unit (Vitest + RTL + MSW); bundle =
`fe-build`/`fe-check`. No e2e-browser layer was added — the existing
`ui-smoke.spec.ts` already covers the `/security/network-policy` path
(R5), and the view tests pin the rendered output at the component seam.

| # | Scenario (acceptance.feature) | Test(s) | Layer | Cadence | Priority | Status |
|---|---|---|---|---|---|---|
| 1 | networkpolicies-list-namespaced | `test_list_networkpolicies_200` (tests/api/test_resources.py) + `test_list_network_policies_namespaced_hits_namespaced_api` (tests/services/test_k8s_client_networkpolicies.py) | unit | pr | P0 | covered — ran, passed |
| 2 | networkpolicies-list-all-namespaces | `test_list_networkpolicies_all_namespaces` (distinct all-namespaces branch in FakeK8s) + `test_list_network_policies_no_namespace_lists_all` | unit | pr | P0 | covered — ran, passed |
| 3 | networkpolicies-get-by-name | `test_get_network_policy_by_name` (1-item hit + `[]` miss) + service 404→`[]` / 500→unreachable | unit | pr | P0 | covered — ran, passed |
| 4 | networkpolicies-sar-denied | `test_list_networkpolicies_sar_denied` (403 + SAR tuple `("list","networkpolicies","team-a",None,"networking.k8s.io")` recorded) | unit | pr | P0 | covered — ran, passed |
| 5 | networkpolicies-binding-404 | `test_networkpolicies_binding_404` (404 CLUSTER_NOT_FOUND) | unit | pr | P1 | covered — ran, passed |
| 6 | networkpolicies-kind-singular-rejected | `test_kind_singular_network_policy_rejected` (404 RESOURCE_KIND_NOT_SUPPORTED) | unit | pr | P1 | covered — ran, passed |
| 7 | cilium-list-uses-served-version | `test_get_crd_served_resolves_served_version_and_scope` (v2alpha1 fixture, not v2) + `test_list_cilium_network_policies_full_items` (`call["version"]=="v2alpha1"`) + `test_list_ciliumnetworkpolicies_200` | unit | pr | P0 | covered — ran, passed |
| 8 | cilium-crds-absent-empty | `test_get_crd_served_absent_returns_none` + `test_list_cilium_network_policies_absent_crds_empty` (`custom_paths == []`) + `test_cilium_absent_crds_empty_200` (API, both kinds) | unit | pr | P0 | covered — ran, passed |
| 9 | cilium-crds-error-502 | `test_cilium_custom_error_500_maps_to_unreachable` (live `(body,500,{})` tuple) + `test_cilium_custom_401_raised_maps_to_unreachable` | unit (service tier) | pr | P1 | covered — ran, passed. ⚠️ API-tier 502 mapping not exercised (FakeK8s never raises) — pre-existing convention from Task 1; service tier is the mapping seam |
| 10 | cilium-clusterwide-ignores-namespace | `test_list_cilium_clusterwide_ignores_namespace` (`"namespace" not in call`) + `test_list_ciliumclusterwidenetworkpolicies_200_ignores_namespace` + `test_ciliumclusterwidenetworkpolicies_name_lookup_not_supported` | unit | pr | P0 | covered — ran, passed |
| 11 | cilium-get-by-name | `test_get_cilium_network_policy_*` (hit / 404→`[]` / CRD-absent→`[]`) + API `test_get_cilium_network_policy_by_name` + `test_get_cilium_network_policy_absent_crds_empty` | unit | pr | P0 | covered — ran, passed |
| 12 | cilium-sar-gated | `test_cilium_sar_gated` (403 + `("list","ciliumnetworkpolicies","team-a",None,"cilium.io") in asked`) | unit | pr | P0 | covered — ran, passed |
| 13 | list-renders-namespace-policies | `list-renders-namespace-policies` (tests/views/network_policies.test.tsx — exact fetch paths, columns, local-time created, name link href, exact `Network Policies` title) | unit (RTL+MSW) | pr | P0 | covered — ran, passed |
| 14 | list-cilium-section-shown-when-present | `list-cilium-section-shown-when-present` (both rows, kind in hrefs, `—` for Policy Types) | unit (RTL+MSW) | pr | P0 | covered — ran, passed |
| 15 | list-cilium-section-hidden-when-empty | `list-cilium-section-hidden-when-empty` (exactly 1 table) | unit (RTL+MSW) | pr | P1 | covered — ran, passed |
| 16 | list-no-cluster-state | `list-no-cluster-state` (`No cluster selected.`, zero fetches) | unit (RTL+MSW) | pr | P1 | covered — ran, passed |
| 17 | list-error-state | `list-error-state` (error line, no rows) | unit (RTL+MSW) | pr | P1 | covered — ran, passed |
| 18 | detail-renders-policy-yaml | `detail-renders-policy-yaml` (tests/views/network_policy_data.test.tsx — URL params, metadata, `<pre>` with name + policy_types) | unit (RTL+MSW) | pr | P0 | covered — ran, passed |
| 19 | detail-not-found-state | `detail-not-found-state` (pinned copy `No NetworkPolicy 'ghost' found`, no `Error` substring) | unit (RTL+MSW) | pr | P1 | covered — ran, passed |
| 20 | detail-bad-kind-client-error | `detail-bad-kind-client-error` (exact error string, zero fetches) | unit (RTL+MSW) | pr | P1 | covered — ran, passed |
| 21 | detail-clusterwide-omits-namespace | `detail-clusterwide-omits-namespace` (`searchParams.get('namespace') === null`) | unit (RTL+MSW) | pr | P1 | covered — ran, passed |
| 22 | stub-route-retired | Stub.test.tsx (`viewPaths` + removed stub title) + `App.tsx` route + live route render in the view tests; e2e `ui-smoke.spec.ts` path (existing) | unit + e2e (existing) | pr | P1 | covered — ran, passed |
| 23 | networkpolicies-list-on-kind | `test_list_networkpolicies_on_kind` (`-m integration`) | integration (kind) | pr (e2e job) | P0 | covered — ran on live `kubedash-test`, passed |
| 24 | cilium-absent-on-live-cluster-empty | `test_cilium_absent_degrades_to_empty_on_kind` (`-m integration`, both Cilium kinds, 200 + `[]`) | integration (kind) | pr (e2e job) | P0 | covered — ran on live `kubedash-test`, passed. ⚠️ local cluster HAS Cilium (the present-empty leg); the CRD-absent leg is pinned by the same assertions and holds on a bare CI cluster |

**Out of Scope (named):** the e2e browser flow for the detail page (the
component seam pins the rendered output; the smoke spec pins the list path —
a full Playwright detail pass is the e2e job's concern, not this change's);
the 13 pre-existing frontend test failures (node 1, users 7, groups 4,
admin_permissions 1 — verified identical to the pre-change baseline).

## Goal-Backward Verification

**Goal (briefing.md):** replace the `/security/network-policy` stub with a
4.1-parity list + detail backed by three new R4 kinds.

- **L1 (units):** every service method's contract (namespaced/all-namespaces
  branch, 404→`[]`, 502 mapping, CRD-absent→`[]`, served-version
  autodetection) is pinned by a named unit test that ran green.
- **L2 (API surface):** the R4 handler's gate order (kind → binding → SAR →
  read) is exercised for all three kinds by the API tests; the response
  envelope (`kind`, `items`) and the SAR cache-key tuple are asserted.
- **L3 (UI):** the list and detail views render real output through the MSW
  seam — the fetch URLs are pinned byte-for-byte, so a kind-string drift
  fails in Vitest, not in a browser.
- **L4 (live system):** the two held-out backstops ran against the real kind
  apiserver on `kubedash-test` and passed (a real NetworkPolicy round-trips;
  both Cilium kinds return 200 + `[]` with no 502).

**Every truth in the briefing's Success criteria is VERIFIED by a named
test, not a grep.** The one nuance: the briefing's "cluster with Cilium
(any served version)" truth is verified by the unit fakes (v2alpha1
fixture) + the live cluster's Cilium-present leg; a live cluster on a
non-v2 served version is not separately exercised (the unit fake pins the
version-resolution logic at the wire level — `call["version"] ==
"v2alpha1"`).

## Traceability

24/24 scenarios → covered (table above). 0 pending. The matrix matches the
actual `grep -c "Scenario:" acceptance.feature` = 24.

## TDD Evidence (validated against git)

| Task | RED evidence | GREEN | Commit | Verdict |
|---|---|---|---|---|
| 1 | 5 service + 4 API failures (`AttributeError`, `404 == 200` assertions) — report task-1-report.md | 50/50 focused, 432/432 suite | 8f6bdbb9 | present, commit resolves |
| 2 | 11 service failures (`AttributeError` on the four new methods) — task-2-report.md | 68/68 focused, 450/450 suite | 3e6dc041 | present, commit resolves |
| 3 | 2 module-resolution failures (`Failed to resolve import`) — task-3-report.md | 12/12 focused, 159/172 full (13 pre-existing) | 2a93c006 | present, commit resolves |
| 4 | 2 module-resolution failures — task-4-report.md | 9/9 focused, 168 passed / 13 pre-existing | fcc40567 | present, commit resolves |
| 5 | harness wiring failures (ScopeMismatch → 401 → 500 → `None == []`) — task-5-report.md | 2/2 integration on live kind; unit loop 58 passed / 5 deselected | 98497d24 | present, commit resolves |

No MISSING_RED, no STALE.

## Verification-Gap Audit

- **API-tier 502 (cilium-crds-error-502):** the scenario's "API responds
  502" is pinned at the service tier (the `ClusterUnreachableError` mapping
  seam); the API-tier `ClusterUnreachableError → 502` response mapping is
  shared, pre-existing handler code exercised by other kinds' tests.
  WARNING (pre-existing convention; not introduced by this change).
- **CRD-absent leg on a bare cluster:** the local kind cluster has Cilium,
  so the live run exercised the present-empty leg. The test's assertions
  (200 + `[]`, never 502) hold on both legs; a CI bare-cluster run would
  confirm the exact door-check backstop. WARNING (named re-run path: the
  e2e job's kind cluster).
- **Detail-page browser e2e:** component seam + smoke spec cover it; a full
  Playwright detail pass is the e2e job's concern. SUGGESTION.
- **Pre-existing frontend failures (13):** identical to baseline (verified
  by stash A/B in Task 3/4 reports). Not this change's debt.

## Assertion-Quality Audit

All changed test files audited: no tautologies, no ghost loops, no
assertion-without-production-call. The MSW view tests assert real rendered
output (scoped table cells, `<pre>` content, hrefs), not mock call counts
alone. The API tests assert the response body + the recorded SAR tuple.
The integration tests assert the live apiserver's response body. Clean.

## Test-Quality + Security + Code Quality

- **Test quality:** cleanup in `finally` (integration); no leaked
  NetworkPolicy (verified by post-run `kubectl get`); fixture state is
  function-scoped or auto-restored (monkeypatch) — no leak into the unit
  loop.
- **Security:** no new trust boundary (briefing.md Tier T2); the change is
  read-only on cluster resources behind the existing binding + SAR gates;
  no user input enters the backend beyond the existing route params. No
  Trivy config in `.skillgrid/config.yaml` (gate N/A).
- **Code quality gates:**
  - Backend unit: **460 passed, 10 deselected** (exit 0; the 10 deselected
    are integration-marked, incl. this change's 2).
  - Frontend: **175 passed, 13 pre-existing failures** (identical to
    baseline).
  - `task fe-build`: tsc + eslint + vite build **exit 0** (rebuilt fresh).
  - `task fe-check`: air-gap assertion **exit 0** (no `https?://` or
    `//cdn.` in the bundle).
  - `ruff check .` (backend): 94 errors at HEAD — **all pre-existing**
    (stash A/B: identical count at the pre-change commit); the four
    changed files carry 10 pre-existing E501s, 0 new.
  - Coverage / mutation: not configured in `.skillgrid/config.yaml` → N/A
    (thresholds 0).
  - Duplication: the two Cilium list methods share ~90% of their body —
    plan-mandated per-kind shape (reviewer, Task 2). SUGGESTION (advisory;
    `duplication.fail_on` not configured).

## Floor

| Dimension | Weakest verdict |
|---|---|
| Goal-backward (L1–L4) | PASS (L4 live backstop has a named nuance — present-empty leg, not CRD-absent leg — WARNING) |
| Traceability | PASS (24/24) |
| TDD Evidence | PASS (no MISSING_RED / STALE) |
| Assertion quality | PASS |
| Code-quality gates | PASS (all exit 0; pre-existing debt named) |
| Security | N/A (no new boundary) |

**Floor verdict: CONCERNS** (capped by two WARNING-level non-answers: the
API-tier 502 seam is service-tier-pinned only, and the live CRD-absent leg
is exercised on a Cilium-present cluster).

## Gate Decision

### CONCERNS

No CRITICAL findings; all hard gates pass. Open items (each with a path):

1. **WARNING — API-tier 502 for the Cilium kinds** is pinned at the service
   tier only. Path: add a `FakeK8s` branch that raises
   `ClusterUnreachableError` + an API test asserting 502 (or accept: the
   mapping is shared handler code, pre-existing convention).
2. **WARNING — live CRD-absent leg** exercised on a Cilium-present cluster.
   Path: the e2e job's bare kind cluster confirms it; or add a CI assertion
   that the dev cluster's Cilium state is accounted for.
3. **SUGGESTION — detail-page browser e2e** (Playwright pass) — the e2e
   job's concern.
4. **SUGGESTION — Cilium list-method duplication** (plan-mandated shape) —
   refactor to a shared `_cilium_list(plural, namespace, scope)` helper if
   a third Cilium kind lands.
5. **SUGGESTION — `policyUrl`'s dead `ns` param** on the clusterwide branch
   (plan-mandated verbatim signature) — the `detail-clusterwide-omits-namespace`
   test is the guard.

Human override: none exercised.

## Human Override

(none)
