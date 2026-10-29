---
id: TASK-060
title: >-
  TICKET-06: migrate other-resource views (hpa, vpa, pdb, resource-quota,
  limit-range) + runtimeclass
status: To Do
assignee: []
created_date: '2026-10-29 16:37'
labels: []
milestone: m-2
dependencies:
  - TASK-056
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 56000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): migrate OtherResource/HorizontalPodAutoscaler{,Data}.tsx, VerticalPodAutoscaler{,Data}.tsx, PodDisruptionBudget{,Data}.tsx, ResourceQuota{,Data}.tsx, LimitRange{,Data}.tsx, RuntimeClass{,Data}.tsx (12 files) to the ObjectRoute contract. Widest batch (10 namespaced + 2 cluster-scoped kinds) but mechanical once the template kind (TASK-056) is proven. SATISFIES: opening an object from a list leaves the URL clean; refreshing the tab keeps the open object; the ref's namespace wins over the header selector.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every name cell in the 6 list views opens the matching data view via ref with location.search === ''
- [ ] #2 data pages read namespace from the ref (R8 - no '|| selectedNamespace' fallback)
- [ ] #3 pnpm test tests/views/horizontal_pod_autoscaler* tests/views/vertical_pod_autoscaler* tests/views/pod_disruption_budget* tests/views/resource_quota* tests/views/limit_range* tests/views/runtime_class* exits 0
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test over the 12 test files green
- [ ] #7 no migrated data view still calls useSearchParams for identity
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - re-point the 12 view test files. 2: migrate the 12 views per the proven template (TASK-056). 3: App.tsx additive ObjectRoute wraps.
<!-- SECTION:PLAN:END -->
