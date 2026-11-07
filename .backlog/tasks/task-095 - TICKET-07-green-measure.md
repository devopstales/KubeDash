---
id: TASK-095
title: 'TICKET-07: green + measure'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-3
dependencies:
  - TASK-090
  - TASK-091
  - TASK-092
  - TASK-093
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
ordinal: 91000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): the full verification floor (`corepack pnpm test`, `task fe-build`, `task fe-check`, `task e2e`, `uv run pytest -m "not integration"`, `uv run ruff check .`, `uv run mypy app`); `npx jscpd --health --reporters ai .` re-measure; record the new dead-code % + overall health vs the 2026-11-07 baseline (dead-code 22 / 16.6%, 187 findings) in the commit body.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 every floor command green including `task e2e` (the held-out live-surface check); the re-run shows the 58 deleted files + `Pods.tsx` + the 79 unused imports gone from the findings; the dead-code % drops from 16.6% toward ~1%; no clone pairs in `views/components|forms|widgets`; the numbers are in the commit body.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: dead-code-measured
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: the full verification floor (`corepack pnpm test`, `task fe-build`, `task fe-check`, `task e2e`, `uv run pytest -m "not integration"`, `uv run ruff check .`, `uv run mypy app`); `npx jscpd --health --reporters ai .` re-measure; record the new dead-code % + overall health vs the 2026-11-07 baseline (dead-code 22 / 16.6%, 187 findings) in the commit body.. 2: verify per Acceptance: every floor command green including `task e2e` (the held-out live-surface check); the re-run shows the 58 deleted files + `Pods.tsx` + the 79 unused imports gone from the findings; the dead-code % drops from 16.6% toward ~1%; no clone pairs in `views/components|forms|widgets`; the numbers are in the commit body.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
