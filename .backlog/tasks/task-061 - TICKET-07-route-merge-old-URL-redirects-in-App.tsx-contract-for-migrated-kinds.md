---
id: TASK-061
title: >-
  TICKET-07: route merge + old-URL redirects in App.tsx (contract for migrated
  kinds)
status: To Do
assignee: []
created_date: '2026-10-29 16:37'
labels: []
milestone: m-2
dependencies:
  - TASK-057
  - TASK-058
  - TASK-059
  - TASK-060
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 57000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): in App.tsx replace the expanded list+data route pairs with single ObjectRoute entries (drop the /data suffix routes as primary) and add the OldDataRedirect routes (R7): read legacy ?name=/?namespace= (+?kind=/?type= where applicable), hydrate the ref with origin: 'link', Navigate to the clean route replace. Apply to ALL kinds migrated in TASK-056..060 (21 routes). Decision (blueprint open decision 1): the redirect layer is KEPT as the permanent bookmark-compat layer. SATISFIES: an old data URL redirects to the clean route with the ref hydrated; back from the detail returns to the list.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the routes table has no /.../data primary entry for a migrated kind
- [ ] #2 opening /security/secret/data?name=db-creds&namespace=team-a lands on the data page at the clean URL with ref origin link
- [ ] #3 back/forward still moves list<->detail
- [ ] #4 task fe-build green; pnpm test (full frontend suite) green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test full suite green
- [ ] #7 task fe-build + task fe-check green
- [ ] #8 no /.../data primary route remains for a migrated kind
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - new tests/App.test.tsx for the redirect scenarios. 2: App.tsx contract pass (21 route pairs -> single entries + redirect routes). 3: full frontend suite + fe-build.
<!-- SECTION:PLAN:END -->
