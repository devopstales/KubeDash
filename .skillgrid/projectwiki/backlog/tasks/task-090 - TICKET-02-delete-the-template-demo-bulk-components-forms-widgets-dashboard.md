---
id: TASK-090
title: 'TICKET-02: delete the template demo bulk (components/forms/widgets/dashboard)'
status: Done
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
updated_date: '2026-11-08 08:51'
labels: []
milestone: m-3
dependencies:
  - TASK-089
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
ordinal: 86000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): delete the verified `views/components/**`, `views/forms/**`, `views/widgets/**`, `views/dashboard/**` files (the files that passed TICKET-01); the verified list goes into this ticket's first commit body; commit `chore: delete CoreUI template demo files (components/forms/widgets/dashboard)`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `git status` matches the verified list exactly; no import specifier for a deleted file remains in `frontend/src`, `frontend/tests`, or `frontend/e2e`; `corepack pnpm test && task fe-build && task fe-check` green at this commit.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: template-bulk-deleted
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: delete the verified `views/components/**`, `views/forms/**`, `views/widgets/**`, `views/dashboard/**` files (the files that passed TICKET-01); the verified list goes into this ticket's first commit body; commit `chore: delete CoreUI template demo files (components/forms/widgets/dashboard)`.. 2: verify per Acceptance: `git status` matches the verified list exactly; no import specifier for a deleted file remains in `frontend/src`, `frontend/tests`, or `frontend/e2e`; `corepack pnpm test && task fe-build && task fe-check` green at this commit.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-11-08 08:22
---
Execution started 2026-11-08 (subagent-execution, wave 2, ImplD02 flint; gate artifact task-01-report.md restored + fixed, 39 files/11,439 lines)
---

created: 2026-11-08 08:51
---
Executed 2026-11-08: commit b9156319 (39 files / 11,439 deletions, pure deletion, commit body carries the verified list); review Approved (ReviewD02) 0C/0I/1M - minor: WidgetsDropdown.jsx orphaned by the deletion, added to T03 batch via task-01-report.md addendum (row 59). Parent re-verify: 39/39 set match, zero spot-grep hits. SATISFIES: template-bulk-deleted.
---
<!-- COMMENTS:END -->
