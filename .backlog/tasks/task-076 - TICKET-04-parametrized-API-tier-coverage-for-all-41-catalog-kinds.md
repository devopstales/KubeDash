---
id: TASK-076
title: 'TICKET-04: parametrized API-tier coverage for all 41 catalog kinds'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies:
  - TASK-075
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
ordinal: 72000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 4: the held-out parametrized suite in `backend/tests/api/test_resources.py` — iterate every `KINDS` row (registry keys as ids): list 200 + items == expected (projector applied when set; the 4 LB method rows excluded from list/namespace cases), cluster-scoped rows ignore `namespace=kube-system`, gettable rows `?name=present` → 1 item / `?name=absent` → `[]`, non-gettable rows `?name=` → 404 `RESOURCE_KIND_NOT_SUPPORTED`, per-row SAR attribute assertion, CRD rows additionally the CRD-absent case; the meta test `test_every_catalog_row_has_fixture_data` (LB overrides exempt with an empty-list sentinel + `provider` marker); provider-detection tests for the 4 external-LB overrides (MetalLB-present wins, MetalLB-absent → Cilium fallback, both absent → `[]`) ported from the existing tests.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `uv run pytest -m "not integration"` green; the parametrized suite covers all 41 rows (deleting any `FIXTURES` entry makes the meta test or that row's case fail — the drift gate); the 3 LB provider-detection behaviours assert as specified.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: every-kind-covered; get-name-semantics; unknown-kind-404
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 4: the held-out parametrized suite in `backend/tests/api/test_resources.py` — iterate every `KINDS` row (registry keys as ids): list 200 + items == expected (projector applied when set; the 4 LB method rows excluded from list/namespace cases), cluster-scoped rows ignore `namespace=kube-system`, gettable rows `?name=present` → 1 item / `?name=absent` → `[]`, non-gettable rows `?name=` → 404 `RESOURCE_KIND_NOT_SUPPORTED`, per-row SAR attribute assertion, CRD rows additionally the CRD-absent case; the meta test `test_every_catalog_row_has_fixture_data` (LB overrides exempt with an . 2: verify per Acceptance: `uv run pytest -m "not integration"` green; the parametrized suite covers all 41 rows (deleting any `FIXTURES` entry makes the meta test or that row's case fail — the drift gate); the 3 LB provider-detection behaviours assert as specified.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
