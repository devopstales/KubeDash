---
id: TASK-083
title: 'TICKET-04: batch C - storage kinds without legacy data redirects'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-5
dependencies:
  - TASK-080
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-frontend-kind-registry/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-frontend-kind-registry/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-frontend-kind-registry/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-frontend-kind-registry/briefing.md
priority: high
type: refactor
ordinal: 79000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Frontend Kind Registry (2026-11-07-frontend-kind-registry): blueprint Task 4 — the 5 fully-standard pairs `StorageClass{,Data}`, `ConfigMap{,Data}`, `SnapshotClass{,Data}`, `VolumeSnapshot{,Data}`, `Pvc{,Data}` → thin wrappers; `Pv.tsx` stays hand-rolled (claim filter + `/metrics/pvcs` join + status/usage cells — the row's `list` factory points at the hand-rolled view; the shared component is not involved), `PvData.tsx` → shared data wrapper; all 6 rows carry `legacyData: false` → the generator emits no `/data` route for any of them; delete the 6 hand blocks from `App.tsx`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test && task fe-build && task fe-check` green; the 6 kinds render via the generated routes with **no** `/data` redirect route for any; the PV usage-join tests (the faithful `KubeDataTable` fake in `pvs.test.tsx`) pass; zero title-assertion edits.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: batch C storage kinds render without legacy data redirects; custom-rendered sides keep their hand-rolled behaviour
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 4 — the 5 fully-standard pairs `StorageClass{,Data}`, `ConfigMap{,Data}`, `SnapshotClass{,Data}`, `VolumeSnapshot{,Data}`, `Pvc{,Data}` → thin wrappers; `Pv.tsx` stays hand-rolled (claim filter + `/metrics/pvcs` join + status/usage cells — the row's `list` factory points at the hand-rolled view; the shared component is not involved), `PvData.tsx` → shared data wrapper; all 6 rows carry `legacyData: false` → the generator emits no `/data` route for any of them; delete the 6 hand blocks from `App.tsx`.. 2: verify per Acceptance: `corepack pnpm test && task fe-build && task fe-check` green; the 6 kinds render via the generated routes with **no** `/data` redirect route for any; the PV usage-join tests (the faithful `KubeDataTable` fake in `pvs.test.tsx`) pass; zero title-assertion edits.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
