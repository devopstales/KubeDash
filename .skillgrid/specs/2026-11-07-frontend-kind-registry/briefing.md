# Frontend Kind Registry — Generated Routes + Shared List/Data Views (Change B) — Briefing

> Companion to `blueprint.md`. The *why*: 25 near-identical `*Data.tsx`/list view
> pairs (jscpd clone family), 20 hand-unrolled `ObjectRoute` blocks + 17
> `OldDataRedirect` blocks in `App.tsx` (1,124L, cx 126), and a kind-addition
> ritual of ~9–10 files. Decisions: ADR-0041 + interview `q6`/`q7`
> (mnemonic `interview/kind-arch-20261107`). Depends on change A landing (the
> catalog is the backend half of the same registry concept).

## What

One typed registry, `frontend/src/lib/kinds.ts`, is the single source for
per-kind route / title / data-redirect / custom flags. `App.tsx` renders its
resource routes **from the registry** (one generated route block per kind)
instead of 37 hand-unrolled blocks. The cloned list and data view bodies
become two shared components (`ResourceListView`, `ResourceDataView`); each
per-kind file stays a thin lazy-loaded config wrapper so code splitting is
unchanged. Kinds whose rendering genuinely differs keep hand-rolled views and
are flagged `custom` in the registry (the Gateway API tabbed lists, the
NetworkPolicy 3-kind dispatcher, the PV claim-namespace filter).

## Requirements

- **R1.** `lib/kinds.ts` registry: registry kind → `{ title, route, clusterScoped, custom? }`.
  Rows transcribed from the current `App.tsx` `ObjectRoute`/`OldDataRedirect`
  blocks + each view's `CCardTitle` verbatim.
- **R2.** `App.tsx` renders resource routes from the registry (generated
  block per kind: `ObjectRoute` + legacy `/data` `OldDataRedirect`). All
  non-resource routes (login, clusters, cluster dashboard, profile,
  permissions, kubeconfig, admin, user/privilege, stubs) are untouched.
- **R3.** `ResourceListView` (card + breadcrumb + TanStack Query fetch +
  `KubeDataTable` + `openObject` row wiring) and `ResourceDataView`
  (breadcrumb + fetch + NOT_FOUND + JSON highlight block) carry the shared
  behaviour; per-kind view files shrink to config (columns, `toRow`, detail
  table) wrapped in the shared component.
- **R4.** Card titles stay byte-identical — the e2e smoke's `exact: true`
  title assertions are the backstop; no e2e title assertion may be edited.
- **R5.** Custom kinds (ingress tabbed list, ingress-class tabbed list,
  network-policy 3-kind dispatcher, persistentvolume claim-filter list) keep
  their hand-rolled views; the registry still owns their routes/redirects.
- **R6.** Object navigation unchanged (ADR-0040): no object identity in URLs,
  ref-driven detail, legacy `/data` redirects intact. Change C (the seam)
  lands later; this change keeps `ObjectRoute`'s single-`kind` prop.
- **R7.** No behaviour change: `corepack pnpm test` green, `task fe-build` +
  `task fe-check` (air-gap) green, e2e smoke green.

## Success

- Adding a standard kind = one registry row + one thin view pair (no `App.tsx`
  edit, no 100-line view clone).
- `App.tsx` < ~700 lines; the per-view clone family (jscpd) gone.
- The registry is the single place a kind's route/title lives.

## Out of scope

- Backend (change A), the navigation seam / `kinds: string[]` (change C),
  dead-code chore (change D).
- New UI. Tailwind. Changes to the e2e-asserted copy. New dependencies.
