---
id: TASK-089
title: 'TICKET-01: verification pass - the deletion list'
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
ordinal: 85000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): re-generate the jscpd findings (`npx jscpd --dead-code --reporters json .`); verify each candidate file is import-free by grep on the import specifier/module path (not the bare basename — the collision-magnet: `DataTables` ⊃ `Tables`, CoreUI `C*` names, `Cluster/Dashboard` vs the template `Dashboard`, live `store/` zustand hits vs `store.js`); verify the unused-symbol candidates; record the verified list (no own commit — the list lands in TICKET-02's first commit body).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every file in the deletion list carries a recorded zero-hit grep (pass-with-note or recorded exception annotated; a hit from a live file is an exclusion); the wsgi `_rq_worker_main`/`_build_worker_app` pair is recorded live-dynamic (the spawn string at `wsgi.py:179`), not as an exception; the verified list is on hand for TICKET-02.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: deletion-list-verified
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: re-generate the jscpd findings (`npx jscpd --dead-code --reporters json .`); verify each candidate file is import-free by grep on the import specifier/module path (not the bare basename — the collision-magnet: `DataTables` ⊃ `Tables`, CoreUI `C*` names, `Cluster/Dashboard` vs the template `Dashboard`, live `store/` zustand hits vs `store.js`); verify the unused-symbol candidates; record the verified list (no own commit — the list lands in TICKET-02's first commit body).. 2: verify per Acceptance: every file in the deletion list carries a recorded zero-hit grep (pass-with-note or recorded exception annotated; a hit from a live file is an exclusion); the wsgi `_rq_worker_main`/`_build_worker_app` pair is recorded live-dynamic (the spawn string at `wsgi.py:179`), not as an exception; the verified list is on hand for TICKET-02.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
