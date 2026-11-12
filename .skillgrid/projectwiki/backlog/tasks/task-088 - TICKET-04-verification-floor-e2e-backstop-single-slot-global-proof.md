---
id: TASK-088
title: 'TICKET-04: verification floor + e2e backstop + single-slot global proof'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-6
dependencies:
  - TASK-086
  - TASK-087
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/briefing.md
priority: high
type: refactor
ordinal: 84000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Navigation Seam (2026-11-07-navigation-seam): full floor (`corepack pnpm test` + `task fe-build` + `task fe-check` + `uv run pytest -m "not integration"`) + `task e2e` green (re-scoped per criticC: covers the three converted routes as list-title mounts only; the sole relay-consumption e2e is the single-kind `crd` deep link; the sole old-URL-redirect e2e is `/security/secret/data`; `kindFromParam` is unit-only; row-click→detail has no e2e — unit-only by design) + proof the single-slot global is gone: `grep -rn "registeredNavigate\|getRegisteredNavigate" frontend/src` → zero hits, recorded in the commit body.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 all four floor commands exit 0, `task e2e` is green, and the grep prints zero hits.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: the single-slot navigate global is gone; object-navigation e2e is green
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: full floor (`corepack pnpm test` + `task fe-build` + `task fe-check` + `uv run pytest -m "not integration"`) + `task e2e` green (re-scoped per criticC: covers the three converted routes as list-title mounts only; the sole relay-consumption e2e is the single-kind `crd` deep link; the sole old-URL-redirect e2e is `/security/secret/data`; `kindFromParam` is unit-only; row-click→detail has no e2e — unit-only by design) + proof the single-slot global is gone: `grep -rn "registeredNavigate\|getRegisteredNavigate" frontend/src` → zero hits, recorded in the commit body.. 2: verify per Acceptance: all four floor commands exit 0, `task e2e` is green, and the grep prints zero hits.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
