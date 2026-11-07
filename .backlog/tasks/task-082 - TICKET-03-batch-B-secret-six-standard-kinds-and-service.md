---
id: TASK-082
title: 'TICKET-03: batch B - secret six standard kinds and service'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-5
dependencies:
  - TASK-080
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
ordinal: 78000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Frontend Kind Registry (2026-11-07-frontend-kind-registry): blueprint Task 3 — `Secret.tsx` → shared list wrapper (`SecretData.tsx` stays hand-rolled: reveal/clipboard, no JSON, red not-found; takes `spec` for its fetch) + the 6 fully-standard pairs `PriorityClass{,Data}`, `RuntimeClass{,Data}`, `ResourceQuota{,Data}`, `PodDisruptionBudget{,Data}`, `VerticalPodAutoscaler{,Data}`, `HorizontalPodAutoscaler{,Data}` → thin wrappers + **`Service{,Data}.tsx` → thin wrappers (folded in here — see Slicing Notes: the blueprint's batch lists omit `service` although the registry locks it and Task 5 asserts all 13 fully-standard pairs converted)** + delete the 8 hand blocks from `App.tsx` (secret, priorityclass, runtimeclass, resourcequota, poddisruptionbudget, verticalpodautoscaler, horizontalpodautoscaler, service).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test && task fe-build && task fe-check` green; secret renders the shared list + hand-rolled data via the generated route; the 7 fully-standard pairs (incl. service) render shared list + data; legacy `/data` redirects for these routes behave as today; zero title-assertion edits.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: batch B kinds render through the generated registry; custom-rendered sides keep their hand-rolled behaviour
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 3 — `Secret.tsx` → shared list wrapper (`SecretData.tsx` stays hand-rolled: reveal/clipboard, no JSON, red not-found; takes `spec` for its fetch) + the 6 fully-standard pairs `PriorityClass{,Data}`, `RuntimeClass{,Data}`, `ResourceQuota{,Data}`, `PodDisruptionBudget{,Data}`, `VerticalPodAutoscaler{,Data}`, `HorizontalPodAutoscaler{,Data}` → thin wrappers + **`Service{,Data}.tsx` → thin wrappers (folded in here — see Slicing Notes: the blueprint's batch lists omit `service` although the registry locks it and Task 5 asserts all 13 fully-standard pairs converted)** + delete the 8 h. 2: verify per Acceptance: `corepack pnpm test && task fe-build && task fe-check` green; secret renders the shared list + hand-rolled data via the generated route; the 7 fully-standard pairs (incl. service) render shared list + data; legacy `/data` redirects for these routes behave as today; zero title-assertion edits.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
