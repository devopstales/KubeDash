---
id: TASK-062
title: 'TICKET-08: in-flight spec views + e2e + docs (contract close)'
status: To Do
assignee: []
created_date: '2026-10-29 16:37'
labels: []
milestone: m-2
dependencies:
  - TASK-061
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 58000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): (a) verify 2026-10-29-statefulsets-daemonsets-replicasets-views executed to the NEW contract per its NAVIGATION-SUPERSEDED.md note (migrate its 6 views only if they landed with query params); (b) e2e/ui-smoke.spec.ts: drop the 14 /data entries from the route list, add the deep-link scenario (share -> new tab renders the object, location.search === '') + the old-URL redirect scenario; (c) ARCHITECTURE.md routing section update; (d) ADR-0040 status flip proposed -> accepted + ASSUMPTIONS.md row In force: yes; (e) residual sweep: grep -r 'useSearchParams' src/views shows only genuine-filter usages; grep -r 'data?name=' src/ returns nothing. SATISFIES: no new endpoint serves the object selection; e2e-level proof of the redirect + deep-link scenarios.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 grep -rn 'data?name=' frontend/src -> 0 matches
- [ ] #2 grep -rln 'useSearchParams' frontend/src/views lists only files with a genuine filter param
- [ ] #3 e2e deep-link + redirect scenarios pass under kind + Helm
- [ ] #4 ADR-0040 file status: accepted; ASSUMPTIONS.md row In force: yes; task fe-build + task fe-check green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 residual grep sweep: data?name= -> 0 matches
- [ ] #7 e2e scenarios green under kind + Helm
- [ ] #8 ADR-0040 accepted and indexed in-force
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: check the in-flight spec's landed shape; migrate only if needed. 2: e2e route-list drop + 2 new scenarios. 3: docs (ARCHITECTURE.md) + ADR-0040 flip + ASSUMPTIONS row. 4: residual grep sweep to zero.
<!-- SECTION:PLAN:END -->
