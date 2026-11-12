---
id: TASK-081
title: 'TICKET-02: batch A - serviceaccount clusterrole namespace node crd'
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
ordinal: 77000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Frontend Kind Registry (2026-11-07-frontend-kind-registry): blueprint Task 2 — `ClusterRole{,Data}.tsx` → thin wrappers (shared list + list-find data; the rule table moves into `detail`); `ServiceAccounts.tsx` + `CRDs.tsx` → list wrappers only (`ServiceAccountData.tsx` / `CrdData.tsx` stay hand-rolled, take `spec` for the `kind`/`plural`-driven fetches); `namespace` / `node` route-coverage only (both views stay hand-rolled — the TopMenu admin button / delete column / rollup tiles / second `/metrics/*` query stay in the views; the row factories point at them); delete the 5 remaining hand blocks from `App.tsx` (serviceaccount, clusterrole, namespace, node, crd — the role block was deleted in TICKET-01); re-point the batch's view tests where a view gains `spec`.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test && task fe-build && task fe-check` green; clusterrole renders the shared list + list-find data via the generated route; serviceaccount/crd render shared lists with hand-rolled data views; namespace/node render their hand-rolled views through the registry lazy factories; legacy `/data` redirects for these routes behave as today; zero title-assertion edits.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: batch A kinds render through the generated registry; custom-rendered sides keep their hand-rolled behaviour
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 2 — `ClusterRole{,Data}.tsx` → thin wrappers (shared list + list-find data; the rule table moves into `detail`); `ServiceAccounts.tsx` + `CRDs.tsx` → list wrappers only (`ServiceAccountData.tsx` / `CrdData.tsx` stay hand-rolled, take `spec` for the `kind`/`plural`-driven fetches); `namespace` / `node` route-coverage only (both views stay hand-rolled — the TopMenu admin button / delete column / rollup tiles / second `/metrics/*` query stay in the views; the row factories point at them); delete the 5 remaining hand blocks from `App.tsx` (serviceaccount, clusterrole, namespace, nod. 2: verify per Acceptance: `corepack pnpm test && task fe-build && task fe-check` green; clusterrole renders the shared list + list-find data via the generated route; serviceaccount/crd render shared lists with hand-rolled data views; namespace/node render their hand-rolled views through the registry lazy factories; legacy `/data` redirects for these routes behave as today; zero title-assertion edits.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
