---
id: TASK-075
title: 'TICKET-03: cutover CRD batch (12 kinds)'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies:
  - TASK-074
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/briefing.md
priority: high
type: feature
ordinal: 71000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 3: add the 12 wire-form (camelCase) fixture entries (all new data — the fake drifted; shape reference: the real methods' wire dicts + API-tier assertions) for ciliumnetworkpolicies, ciliumclusterwidenetworkpolicies, verticalpodautoscalers, gateways, httproutes, referencegrants, volumesnapshotclasses, volumesnapshots, clusterissuers, issuers, certificaterequests, certificates; add the per-kind `test_<kind>_crd_absent_returns_empty` tests + one transport-failure negative control; flip the 12 rows to `method=None`; delete the 12 list + 11 get methods from `k8s_client.py` + matching fake methods; rewrite the batch's service tests against the engine (Task 2 pattern).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `uv run pytest -m "not integration"` green; each of the 12 kinds: list route → 200 wire-shape items, `crd_absent={kind}` → 200 `items: []`, transport failure → 502 `CLUSTER_UNREACHABLE`; the 23 batch methods are gone from `k8s_client.py`; `uv run ruff check . && uv run mypy app` clean.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: crd-kinds-catalog; crd-absent-degrade; engine-transport-failure-502
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 3: add the 12 wire-form (camelCase) fixture entries (all new data — the fake drifted; shape reference: the real methods' wire dicts + API-tier assertions) for ciliumnetworkpolicies, ciliumclusterwidenetworkpolicies, verticalpodautoscalers, gateways, httproutes, referencegrants, volumesnapshotclasses, volumesnapshots, clusterissuers, issuers, certificaterequests, certificates; add the per-kind `test_<kind>_crd_absent_returns_empty` tests + one transport-failure negative control; flip the 12 rows to `method=None`; delete the 12 list + 11 get methods from `k8s_client.py` + matching. 2: verify per Acceptance: `uv run pytest -m "not integration"` green; each of the 12 kinds: list route → 200 wire-shape items, `crd_absent={kind}` → 200 `items: []`, transport failure → 502 `CLUSTER_UNREACHABLE`; the 23 batch methods are gone from `k8s_client.py`; `uv run ruff check . && uv run mypy app` clean.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
