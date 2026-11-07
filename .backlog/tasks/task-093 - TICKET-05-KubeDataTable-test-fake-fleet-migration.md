---
id: TASK-093
title: 'TICKET-05: KubeDataTable test-fake fleet migration'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-3
dependencies: []
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/briefing.md
priority: high
type: chore
ordinal: 89000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): extract the faithful init-time-capture fake (the DataTables init-time prop capture the PV/PVC usage-join tests depend on) from `pvs.test.tsx` into `frontend/tests/components/kube-data-table.test-utils.tsx`; re-point every inline `KubeDataTable` fake in `frontend/tests/views` (`grep -rln 'KubeDataTable' frontend/tests/views` is the authoritative list — the ~20 tests, three variants: simple, slot-renderer, faithful; where the variants conflict the faithful variant wins) at the shared fake, each test keeping its own canned data; a behaviour change is a stop-and-report, not a silent adaptation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no inline `KubeDataTable` fake remains in `frontend/tests/views` (all tests import the shared fake); test expectations unedited; `corepack pnpm test && task fe-build` green.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: test-fake-fleet-migrated
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: extract the faithful init-time-capture fake (the DataTables init-time prop capture the PV/PVC usage-join tests depend on) from `pvs.test.tsx` into `frontend/tests/components/kube-data-table.test-utils.tsx`; re-point every inline `KubeDataTable` fake in `frontend/tests/views` (`grep -rln 'KubeDataTable' frontend/tests/views` is the authoritative list — the ~20 tests, three variants: simple, slot-renderer, faithful; where the variants conflict the faithful variant wins) at the shared fake, each test keeping its own canned data; a behaviour change is a stop-and-report, not a silent adaptation.. 2: verify per Acceptance: no inline `KubeDataTable` fake remains in `frontend/tests/views` (all tests import the shared fake); test expectations unedited; `corepack pnpm test && task fe-build` green.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
