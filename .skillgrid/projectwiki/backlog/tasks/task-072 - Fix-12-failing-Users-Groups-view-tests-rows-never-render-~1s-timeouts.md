---
id: TASK-072
title: 'Fix 12 failing Users/Groups view tests (rows never render, ~1s timeouts)'
status: To Do
assignee: []
created_date: '2026-11-07 09:29'
labels:
  - frontend
  - tests
dependencies: []
type: bug
ordinal: 68000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Verified at HEAD d5dd2d4a in a clean worktree (pre-existing, not a regression): 7 tests in tests/views/users.test.tsx, 4 in tests/views/groups.test.tsx, 1 in tests/views/admin_permissions.test.tsx (unbind-deletes-a-binding-row) all fail with TestingLibraryElementError after ~1050ms (e.g. 'Unable to find an element with the text: Alice'). The DOM renders breadcrumb + toolbar but no table rows. Root cause unknown — investigate the users/groups data fetch + row render path (MSW handlers vs view).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 corepack pnpm test passes the full frontend suite with 0 failures
- [ ] #2 root cause documented in the task notes (view bug vs test/MSW bug)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
