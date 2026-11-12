---
id: TASK-080
title: >-
  TICKET-01: registry + shared components + generator + limitrange and role
  tracers (door check)
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-5
dependencies: []
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
ordinal: 76000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Frontend Kind Registry (2026-11-07-frontend-kind-registry): the full `frontend/src/lib/kinds.ts` (`KindSpec` + ALL 24 rows: 21 standard + 3 custom, transcribed from the `App.tsx` `ObjectRoute` / `OldDataRedirect` blocks + each view's `CCardTitle` verbatim + each view's fetch URL plural; `legacyData: false` on the 6 storage rows; `clusterScoped` from `OldDataRedirect`) + `ResourceListView` (card + breadcrumb + TanStack Query fetch + `KubeDataTable` + `openObject` row wiring) + `ResourceDataView` (single-fetch AND list-find variants) + `ResourceRoute`/`LegacyDataRoute` (both wrapping content in `ProtectedRoute`) + the `App.tsx` generator (all 21 standard route pairs; no `/data` route where `legacyData` is false) + convert the two tracers `LimitRange{,Data}.tsx` (single-fetch) and `Role{,Data}.tsx` (list-find) to thin wrappers + delete the limitrange + role hand blocks + `tests/lib/kinds.test.ts` (registry invariants, RED first) + `tests/components/resource-list-view.test.tsx` + `tests/components/resource-data-view.test.tsx` (RED first) + shared `KubeDataTable` test fake extracted for the component tests + re-point `limit_ranges` / `limit_range_data` / `roles` view tests (pass the registry row's `spec` in `renderAt`).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test` + `task fe-build` + `task fe-check` green; `kinds.test.ts` invariants green (unique routes, expected-kinds set fixture, shared-rendered ⇔ factory absent, `legacyData: false` only on the 6 storage rows, custom rows factory-free with non-empty `kinds`); the 3 unit title pins green **unedited**; `dist/assets/` still contains separate `LimitRange*` + `Role*` chunks (chunk names recorded in the commit body); zero per-kind branches inside the shared components.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: the registry rows are keyed by kind with unique routes; the registry standard-kind set matches the app route table; the registry rows carry verbatim titles and non-empty plurals; the registry marks legacy-data false only for the six storage kinds; a registry side is shared-rendered exactly when its factory is absent; standard kind routes are generated from the registry; the six storage kinds emit no legacy data redirect route; adding a standard kind requires no App.tsx edit; the shared list view opens the data view via openObject on the same route; the shared data view renders detail with a muted not-found state; the shared data view shows a muted not-found state on a miss; the list-find data variant fetches the full list and finds client-side; the tracer kinds render end-to-end through the generated registry; the converted tracer views keep one chunk each; the door-check unit title pins stay green unedited
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: the full `frontend/src/lib/kinds.ts` (`KindSpec` + ALL 24 rows: 21 standard + 3 custom, transcribed from the `App.tsx` `ObjectRoute` / `OldDataRedirect` blocks + each view's `CCardTitle` verbatim + each view's fetch URL plural; `legacyData: false` on the 6 storage rows; `clusterScoped` from `OldDataRedirect`) + `ResourceListView` (card + breadcrumb + TanStack Query fetch + `KubeDataTable` + `openObject` row wiring) + `ResourceDataView` (single-fetch AND list-find variants) + `ResourceRoute`/`LegacyDataRoute` (both wrapping content in `ProtectedRoute`) + the `App.tsx` generator (all 21 standard. 2: verify per Acceptance: `corepack pnpm test` + `task fe-build` + `task fe-check` green; `kinds.test.ts` invariants green (unique routes, expected-kinds set fixture, shared-rendered ⇔ factory absent, `legacyData: false` only on the 6 storage rows, custom rows factory-free with non-empty `kinds`); the 3 unit title pins green **unedited**; `dist/assets/` still contains separate `LimitRange*` + `Role*` chunks (chunk names recorded in the commit body); zero per-kind branches inside the shared components.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
