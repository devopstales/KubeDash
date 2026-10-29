---
id: TASK-056
title: 'TICKET-02: ObjectRoute + ShareObjectButton + priorityclass template kind'
status: To Do
assignee: []
created_date: '2026-10-29 16:36'
labels: []
milestone: m-2
dependencies:
  - TASK-055
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 52000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): implement src/components/ObjectRoute.tsx (kind-matched list/detail render, mount-time consumeIncoming + sweepRelay, navigate-seam registration) + src/components/ShareObjectButton.tsx, migrate OtherResource/PriorityClass.tsx (link producer -> openObject click) and PriorityClassData.tsx (useSearchParams -> props from ObjectRoute), and wire both routes in App.tsx ALONGSIDE the existing /other-resource/priorityclass/data route (expand, not contract). Add tests/components/object_route.test.tsx and re-point tests/views/priority_classes.test.tsx + priority_class_data.test.tsx. SATISFIES: opening an object from a list leaves the URL clean; one route per kind (detail only for matching ref); share action POSTs a token with no name=/namespace= in the URL.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 clicking a priorityclass name renders the data view with window.location.search === ''
- [ ] #2 a ref for kind secret on the priorityclass route renders the list
- [ ] #3 share button submits a hidden form POST whose action URL contains no name= or namespace=
- [ ] #4 pnpm test tests/components tests/views/priority_class* exits 0; task fe-build green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test tests/components tests/views/priority_class* green
- [ ] #7 task fe-build + task fe-check green
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - re-point priority_class tests to assert location.search === '' + ref-driven render. 2: ObjectRoute + ShareObjectButton per blueprint sections 2-3. 3: migrate the priorityclass pair + additive App.tsx routes. 4: verify KubeDataTable click-cell assumption (small prop addition if needed - lands here).
<!-- SECTION:PLAN:END -->
