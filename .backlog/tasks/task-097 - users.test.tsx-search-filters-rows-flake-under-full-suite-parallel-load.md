---
id: TASK-097
title: users.test.tsx search-filters-rows flake under full-suite parallel load
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 20:46'
labels: []
dependencies: []
priority: low
ordinal: 93000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
frontend/tests/views/users.test.tsx (the one view test using the REAL DataTables, not the shared fake) intermittently fails search-filters-rows with TypeError: Cannot redefine property: relatedTarget - datatables.net 3.1.4 x jsdom 25 event-wrapper bug, triggered under full-suite parallel load. Verified pre-existing on the pristine tree (stash-verified) during change D T05 (2026-11-07); unrelated to the KubeDataTable test-fake migration. Investigate: upgrade path for datatables.net/jsdom, or isolate the real-DataTables test file from parallel load (singleThread/sequence for that file), or pin the event-wrapper. Until fixed, treat a lone relatedTarget failure in users.test.tsx on a full-suite run as the known flake (re-run once to confirm).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 users.test.tsx passes in 10 consecutive full-suite runs (or isolation documented in the file header)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
