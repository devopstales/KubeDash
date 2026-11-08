---
id: TASK-098
title: 'Backend lint debt: 93 ruff + 76 mypy errors at D base (CI floor red)'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-08 09:48'
labels: []
dependencies: []
priority: medium
ordinal: 94000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Pre-existing at 2026-11-07-dead-code-cleanup base (verified via worktree at b9156319 == 866bae7f backend state): uv run ruff check . (backend/) = 103 errors before change D's T04 (T04 removed 10 F401s, added none -> 93); uv run mypy app = 76 errors in 15 files (unchanged by T04). Rule mix: E501, F811, I001, F821 (incl. tests/api/conftest.py pathlib - annotation-only, masked by from __future__ import annotations), SIM105, B018; mypy: no-any-return, no-untyped-def etc. Because the floor is red, CI's ruff/mypy gate cannot catch regressions and new deletions leave the noise behind (change D tickets T04/T07 carried the red as verified pre-existing). Plan: ruff check --fix --unsafe-fixes for the mechanical bulk, then triage the rest (F811 test_groups admin_headers redefinitions, F821 conftest pathlib import, E501 wrap/ignore list, mypy annotations) to zero. Gate: uv run ruff check . && uv run mypy app green in backend/.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 uv run ruff check . exits 0 in backend/
- [ ] #2 uv run mypy app exits 0 in backend/
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
