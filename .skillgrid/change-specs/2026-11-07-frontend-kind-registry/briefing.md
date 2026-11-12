# Frontend Kind Registry — Generated Routes + Shared List/Data Views (Change B) — Briefing

> Companion to `blueprint.md`. The *why*: the 13 fully-standard + 2 list-find view pairs of the jscpd
> clone family, 21 hand-unrolled `ObjectRoute` blocks + 18 `OldDataRedirect`
> blocks (39) in `App.tsx` (1,302L, cx 126), and a kind-addition ritual of
> ~9–10 files. Decisions: ADR-0041 + interview `q6`/`q7`
> (mnemonic `interview/kind-arch-20261107`). Depends on change A landing (the
> catalog is the backend half of the same registry concept).

## What

One typed registry, `frontend/src/lib/kinds.ts`, is the single source for
per-kind route / plural / titles / data-redirect / custom flags. `App.tsx`
renders its resource routes **from the registry** (one generated route block
per standard kind) instead of 39 hand-unrolled blocks. The cloned list and
data view bodies become two shared components (`ResourceListView`,
`ResourceDataView` with a `single` and a `list-find` data variant); each
converted per-kind file stays a thin lazy-loaded config wrapper so code
splitting is unchanged. Kinds whose rendering genuinely differs keep
hand-rolled views: 3 `custom` rows (one row per route, `kinds: string[]` —
the Gateway API tabbed lists, the NetworkPolicy 3-kind dispatcher) and
custom-rendered sides inside standard rows (5 divergent data views:
serviceaccount/namespace/node/crd/secret — role/clusterrole get the shared
`list-find` variant; 3 custom list views: namespace/node/persistentvolume —
the PV claim-namespace filter). The cert-manager + external-LB dispatchers
(8 kinds) and the role-binding/cluster-role-binding list-only routes are out
of scope (user decision 2026-11-07) and stay hand-written in `App.tsx`.

## Requirements

- **R1.** `lib/kinds.ts` registry: registry kind → `{ kind, plural, title, route, clusterScoped, legacyData, custom?, kinds?, list?, data? }` (a side's factory absent → the shared component renders it; present → the hand-rolled view). Rows transcribed from the current `App.tsx` `ObjectRoute`/`OldDataRedirect` blocks + each view's `CCardTitle` verbatim + each view's fetch URL (the plural); `legacyData: false` for the 6 storage first-build rows whose `/data` URL never shipped.
- **R2.** `App.tsx` renders resource routes from the registry (generated
  block per kind: `ObjectRoute` + legacy `/data` `OldDataRedirect`). All
  non-resource routes (login, clusters, cluster dashboard, profile,
  permissions, kubeconfig, admin, user/privilege, stubs) are untouched.
- **R3.** `ResourceListView` (card + breadcrumb + TanStack Query fetch +
  `KubeDataTable` + `openObject` row wiring) and `ResourceDataView`
  (breadcrumb + fetch + NOT_FOUND + JSON highlight block) carry the shared
  behaviour; per-kind view files shrink to config (columns, `toRow`, detail
  table) wrapped in the shared component.
- **R4.** Card titles stay byte-identical — the unit-suite title pins + the 5 view-derived e2e strings are the backstop; no title assertion may be edited.
- **R5.** Custom rows (ingress tabbed route, ingress-class tabbed route, network-policy route — one row per route, `kinds: string[]`) and custom-rendered sides (the 5 divergent data views, the 3 custom lists incl. the persistentvolume claim-filter) keep their hand-rolled views; the registry still owns their routes/redirects/metadata.
- **R6.** Object navigation unchanged (ADR-0040): no object identity in URLs,
  ref-driven detail, legacy `/data` redirects intact. Change C (the seam)
  lands later; this change keeps `ObjectRoute`'s single-`kind` prop.
- **R7.** No behaviour change: `corepack pnpm test` green, `task fe-build` +
  `task fe-check` (air-gap) green, e2e smoke green.

## Success

- Adding a standard kind = one registry row + one thin view pair (no `App.tsx`
  edit, no 100-line view clone).
- `App.tsx` < ~700 lines; the per-view clone family among shared-rendered kinds (jscpd) gone.
- The registry is the single place a kind's route/title lives.

## Out of scope

- Backend (change A), the navigation seam / `kinds: string[]` (change C),
  dead-code chore (change D).
- New UI. Tailwind. Changes to the e2e-asserted copy. New dependencies.
