---
id: TASK-085
title: >-
  TICKET-01: kind-keyed navigate registry + ObjectRoute kinds (breaking prop,
  all call sites migrated)
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-6
dependencies: []
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
ordinal: 81000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Navigation Seam (2026-11-07-navigation-seam): kind-keyed registry in `src/lib/objectRef.ts` (`NavigateFn`, `registerNavigate(kinds, fn)`, `unregisterNavigate(kinds, fn)` removing only entries still pointing at your own fn, `getNavigateFor(kind)`) + `ObjectRoute` takes `kinds: string[]`, kind-matched `detail` receives the matched `kind`, register-on-mount/unregister-on-unmount, the single-slot global + `getRegisteredNavigate` + the `registerNavigate` re-export deleted; all call sites migrated in the same change — App.tsx (the 5 dispatcher registrations, incl. the 2 out-of-scope, whose kinds arrays come from App.tsx:283-287 / :328-332 + each effect gains the matching cleanup; + any remaining direct `ObjectRoute` sites post-B, at most the `service` block), `ResourceRoute` → `kinds={[spec.kind]}`, test side: the 58 `kind=` sites in the 44 test files + the 5 `registerNavigate` imports move to `lib/objectRef.ts` with two-arg calls (record both file counts in the commit body); `object_route.test.tsx` rewritten for `kinds` + the keyed registry (incl. unmount-unregister); `objectRef.test.ts` registry tests (failing first).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test && task fe-build && task fe-check` exit 0 (tsc proves the breaking prop is fully migrated — no `kind=` survives) and `grep -rn "registeredNavigate\|getRegisteredNavigate" frontend/src` → zero hits.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: registering for one kind leaves other kinds intact; re-registering a kind replaces only that kind's fn; unmounting removes only the fn the route registered; after the last route for a kind unmounts the lookup is empty; the route table's kind sets are disjoint; a matching ref renders the detail on a multi-kind route; a foreign-kind ref renders the list; detail receives the matched kind as a param; a single-kind route passes its own kind to detail; the out-of-scope dispatchers register through the kind-keyed API; relay consumption on single-kind routes is unchanged; the single-slot navigate global is gone
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: kind-keyed registry in `src/lib/objectRef.ts` (`NavigateFn`, `registerNavigate(kinds, fn)`, `unregisterNavigate(kinds, fn)` removing only entries still pointing at your own fn, `getNavigateFor(kind)`) + `ObjectRoute` takes `kinds: string[]`, kind-matched `detail` receives the matched `kind`, register-on-mount/unregister-on-unmount, the single-slot global + `getRegisteredNavigate` + the `registerNavigate` re-export deleted; all call sites migrated in the same change — App.tsx (the 5 dispatcher registrations, incl. the 2 out-of-scope, whose kinds arrays come from App.tsx:283-287 / :328-332 + eac. 2: verify per Acceptance: `corepack pnpm test && task fe-build && task fe-check` exit 0 (tsc proves the breaking prop is fully migrated — no `kind=` survives) and `grep -rn "registeredNavigate\|getRegisteredNavigate" frontend/src` → zero hits.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
