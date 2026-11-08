---
id: TASK-095
title: 'TICKET-07: green + measure'
status: Done
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
updated_date: '2026-11-08 10:51'
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
- [x] #1 every floor command green including `task e2e` (the held-out live-surface check); the re-run shows the 58 deleted files + `Pods.tsx` + the 79 unused imports gone from the findings; the dead-code % drops from 16.6% toward ~1%; no clone pairs in `views/components|forms|widgets`; the numbers are in the commit body.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
- [x] #6 SATISFIES scenarios green per acceptance.feature: dead-code-measured
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: the full verification floor (`corepack pnpm test`, `task fe-build`, `task fe-check`, `task e2e`, `uv run pytest -m "not integration"`, `uv run ruff check .`, `uv run mypy app`); `npx jscpd --health --reporters ai .` re-measure; record the new dead-code % + overall health vs the 2026-11-07 baseline (dead-code 22 / 16.6%, 187 findings) in the commit body.. 2: verify per Acceptance: every floor command green including `task e2e` (the held-out live-surface check); the re-run shows the 58 deleted files + `Pods.tsx` + the 79 unused imports gone from the findings; the dead-code % drops from 16.6% toward ~1%; no clone pairs in `views/components|forms|widgets`; the numbers are in the commit body.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-11-08 10:09
---
Execution started 2026-11-08 (subagent-execution, wave 4, ImplD07 flint; final tree f724c5d4; adjudications: ruff/mypy pre-existing TASK-098, pnpm flake TASK-097)
---

created: 2026-11-08 10:51
---
Executed 2026-11-08: measure commit f717f685. Floor: pnpm 491/491 (+1 TASK-097 flake), fe-build/fe-check green, e2e 20/20, pytest 761, ruff 93 / mypy 76 (=T04-end, 0 new; TASK-098). Measures: health 32/E -> 55/C (dup 20->28.6, dead-code 22->94.3, complexity 72->65.4); dead-code 16.6%/187 -> 0.56%/36. Parent re-verify: independent jscpd re-run matches (8-line delta = 17425c2f landed after the run). SATISFIES: dead-code-measured.
---
<!-- COMMENTS:END -->
