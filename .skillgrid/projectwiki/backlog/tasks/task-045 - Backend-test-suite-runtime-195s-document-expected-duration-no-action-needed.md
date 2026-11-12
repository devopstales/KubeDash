---
id: TASK-045
title: 'Backend test suite runtime 195s - document expected duration, no action needed'
status: To Do
assignee: []
created_date: '2026-10-27 15:33'
updated_date: '2026-10-28 13:04'
labels: []
dependencies: []
modified_files:
  - AGENTS.md
priority: low
type: docs
ordinal: 41000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The full backend unit test suite (`pytest -m 'not integration'`) takes ~195s (3:15) to complete 421 tests. This is not a hang — it's uniformly slow due to Testcontainers session startup, leader election timing tests, and permission API tests. The earlier 'timeout at 3 minutes' observation was because the CI/IDE timeout was set to 180s. No test is hanging. The suite passes cleanly (421 passed, 7 deselected). If a future developer sets a 3-minute timeout, they'll see a false timeout. The expected duration should be documented in AGENTS.md or the Taskfile so future agents don't misdiagnose it as a hang.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 AGENTS.md or Taskfile.yaml documents that the backend unit suite takes ~3:15 to complete
- [ ] #2 No timeout set to 180s or less for the full suite
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
