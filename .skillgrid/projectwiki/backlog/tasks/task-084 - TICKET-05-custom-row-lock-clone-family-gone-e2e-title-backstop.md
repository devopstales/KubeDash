---
id: TASK-084
title: 'TICKET-05: custom row lock + clone family gone + e2e title backstop'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-5
dependencies:
  - TASK-081
  - TASK-082
  - TASK-083
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
ordinal: 80000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Frontend Kind Registry (2026-11-07-frontend-kind-registry): blueprint Task 5 — in `App.tsx`, the 3 custom route blocks (ingress, ingress-class, network-policy dispatchers) read their path strings from their registry rows (path literals → row lookups; the list views' `LIST_ROUTE` constants stay untouched — change C rewires the dispatcher routes); jscpd clone check (`npx jscpd --reporters ai --summary` over `frontend/src/views`) — the per-view clone family among shared-rendered kinds (~104L `*Data.tsx` pairs, 13 standard + 2 list-find) is gone; `vite build` chunk list diff for ALL converted kinds (one chunk per view file); full floor: `corepack pnpm test` (all 8 unit title pins unedited) + `task fe-build` + `task fe-check` + `task e2e` (the 5 view-derived strings unedited); record both jscpd and chunk before/afters in the commit body.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 jscpd shows the clone family gone among shared-rendered kinds (the 8 custom-rendered sides remain by design); the chunk list shows one chunk per converted view file; `grep -c '<ObjectRoute' src/App.tsx` + `grep -c '<OldDataRedirect' src/App.tsx` count only the named out-of-scope blocks (cert-manager/ELB dispatchers, role-binding/cluster-role-binding) — no standard kind; `task e2e` green with the 5 strings unedited; `App.tsx` < ~700 lines.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: the custom dispatcher routes read their paths from the registry; the per-view clone family is gone among shared-rendered kinds; the hand-unrolled standard route blocks are gone from App.tsx; the e2e view title strings stay green unedited
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 5 — in `App.tsx`, the 3 custom route blocks (ingress, ingress-class, network-policy dispatchers) read their path strings from their registry rows (path literals → row lookups; the list views' `LIST_ROUTE` constants stay untouched — change C rewires the dispatcher routes); jscpd clone check (`npx jscpd --reporters ai --summary` over `frontend/src/views`) — the per-view clone family among shared-rendered kinds (~104L `*Data.tsx` pairs, 13 standard + 2 list-find) is gone; `vite build` chunk list diff for ALL converted kinds (one chunk per view file); full floor: `corepack pnpm test. 2: verify per Acceptance: jscpd shows the clone family gone among shared-rendered kinds (the 8 custom-rendered sides remain by design); the chunk list shows one chunk per converted view file; `grep -c '<ObjectRoute' src/App.tsx` + `grep -c '<OldDataRedirect' src/App.tsx` count only the named out-of-scope blocks (cert-manager/ELB dispatchers, role-binding/cluster-role-binding) — no standard kind; `task e2e` green with the 5 strings unedited; `App.tsx` < ~700 lines.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
