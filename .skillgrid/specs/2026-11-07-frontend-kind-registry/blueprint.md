# Frontend Kind Registry — Generated Routes + Shared Views — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T2
**Build shape:** Tracer thread — the open risk is whether one generated route block + shared list/data components reproduces the per-kind behaviour (exact titles, code splitting, `openObject` wiring, legacy redirects) for a real kind before 19 more are converted.
**Classification:** standard (L2 verification floor: full unit suite + `task fe-build` + `task fe-check`)
**Goal:** One typed registry (`src/lib/kinds.ts`) owns every kind's route/title/redirect/custom flag; `App.tsx` renders resource routes from it; the 25 cloned view pairs become thin config wrappers over two shared components.
**Architecture:** `lib/kinds.ts` declares `KindSpec { kind, title, route, clusterScoped?, custom?, list?, data? }` where `list`/`data` are lazy import factories — lazy, so no static import cycle with the view files (the views receive their `spec` as a prop and import nothing from the registry). A `ResourceRoute` component in `App.tsx` loads a row's `list`/`data` and renders `ObjectRoute`; a generator emits one route pair per standard row. `ResourceListView` (card + breadcrumb + TanStack Query + `KubeDataTable` + `openObject` row wiring) and `ResourceDataView` (breadcrumb + fetch + NOT_FOUND + JSON highlight) carry the behaviour the 25 pairs each re-implement; per-kind files shrink to config (columns, `toRow`, detail table). Custom rows (3 dispatcher routes + the PV claim-filter list) keep hand-rolled views and stay explicit `<Route>` blocks; the registry still owns their metadata.
**Tech Stack:** React 19, TypeScript 5.8, react-router-dom, TanStack Query, CoreUI, Vitest + RTL + MSW.
**Spec:** `./briefing.md`
**Critic:** pending

## Hypothesis

**Claim:** One generated route block per registry row + two shared view components reproduces the hand-rolled per-kind behaviour (byte-identical titles, per-view code splitting, ref-driven detail, legacy `/data` redirects, the `openObject` seam) for all standard kinds.
**Right condition:** tracer kind converted and green (Step 8 of Task 1); after all batches, the 20 hand-unrolled `ObjectRoute` blocks + 17 `OldDataRedirect` blocks are gone, replaced by the generator, and the e2e exact-title smoke is green with **zero** title assertions edited.
**Wrong condition:** a kind needs per-kind branching inside `ResourceListView`/`ResourceDataView` (a fifth column source, a second fetch shape, a title that is not its `CCardTitle`), or code splitting changes (the bundle must keep one chunk per view), or an e2e title assertion must be edited.
**Thinnest MVP:** `limitrange` converted end-to-end (registry row, shared components, generated route pair, tests).
**Door check:** Task 1.

## Terms

- **Kind**, **Kind catalog**, **Registry kind** — `.skillgrid/knowledge/glossary/02-technical-terms.md`
- Object navigation (ADR-0040), object ref, relay — repo ADR vocabulary; no new terms

## Must-Haves (goal-backward verification)

**Truths:**
- [backstop] every card title renders byte-identically to today — backstop: the existing e2e smoke's `exact: true` assertions, none of which may be edited (held-out: `task e2e`)
- list rows open the data view via `openObject` on the same route; the URL never carries object identity (ADR-0040 R1); the legacy `<route>/data` URL redirects as today (R7)
- each per-kind view stays a separate lazy chunk (code splitting unchanged) — verifiable via `vite build` chunk list diff for the converted kinds
- adding a standard kind touches `lib/kinds.ts` (one row) + one thin view pair — no `App.tsx` edit (verified by the tracer commit's diff)
- custom kinds render exactly as today (tabbed ingress/ingress-class lists, the 3-kind network-policy dispatcher, the PV claim-filter list)

**Artifacts:**
- `frontend/src/lib/kinds.ts` — `KindSpec` + `KINDS` registry (all rows)
- `frontend/src/components/ResourceListView.tsx` — shared list behaviour
- `frontend/src/components/ResourceDataView.tsx` — shared data behaviour
- `frontend/src/components/ResourceRoute.tsx` — per-row route element (lazy load + `ObjectRoute` wiring; legacy-redirect element too)
- `frontend/src/views/**` — per-kind files reduced to config wrappers (one per kind, lazy-load targets unchanged)
- `frontend/tests/lib/kinds.test.ts` — registry invariants
- `frontend/tests/components/resource-list-view.test.tsx` + `resource-data-view.test.tsx` — shared-component tests (incl. the shared `KubeDataTable` test fake)
- `frontend/src/App.tsx` — generator; the 37 hand-unrolled resource blocks gone

**Key links:**
- `ResourceRoute` reads the row's lazy factories; the view's `spec` prop (title, `kind`, `route`, `clusterScoped`) is the ONLY place a view learns its identity — no view may hard-code its `KIND`/`LIST_ROUTE`/title after conversion
- `ResourceListView`'s `openObject(spec.kind, name, ns, spec.route, navigate)` wiring is the same seam the list views use today
- the generator iterates `KINDS`; a future row automatically gets its route pair — the registry test asserts route uniqueness so a typo fails
- custom rows are the ONLY hand-written `<Route>` resource blocks left in `App.tsx`

**One-way-door decisions:** None — no URL/contract change (ADR-0040 intact), no new dependency, e2e-asserted copy frozen.

## Global Constraints

- React 19 + TS 5.8 strict; CoreUI SCSS only (no Tailwind); no new dependencies (ADR-0020 air-gap: `task fe-check` green)
- e2e title assertions (`exact: true`) are frozen — if one must change, stop and report (door-check failure)
- `corepack pnpm test` green at every commit; `task fe-build` + `task fe-sync` after frontend changes (the frontend loop)
- per-kind lazy chunks preserved (one chunk per view file)
- conventional commits; spec zone (this blueprint) commits before code zone

## File Structure

- `frontend/src/lib/kinds.ts` — registry data + `KindSpec`; imports nothing from `views/` statically (lazy factories only)
- `frontend/src/components/ResourceListView.tsx` — the list behaviour (fetch via `apiFetch` on the cluster store, `KubeDataTable`, breadcrumb/card, `openObject` row click)
- `frontend/src/components/ResourceDataView.tsx` — the data behaviour (fetch single object, NOT_FOUND state, breadcrumb with ref-clearing list item, JSON `SyntaxHighlighter` block)
- `frontend/src/components/ResourceRoute.tsx` — `<ResourceRoute spec>` (ObjectRoute element) + `<LegacyDataRoute spec>` (OldDataRedirect element)
- `frontend/src/App.tsx` — `queryClient` shell, non-resource routes, the 3 custom dispatcher routes, the generator over `KINDS`
- `frontend/src/views/<Area>/<Kind>.tsx` / `<Kind>Data.tsx` — thin wrappers: `<ResourceListView spec={spec} columns={...} toRow={...} />` / `<ResourceDataView spec={spec} detail={...} />`
- `frontend/tests/` — registry invariants, shared-component tests, shared `KubeDataTable` fake

## The Registry (rows)

Rows transcribed from `App.tsx` (`kind=`, `listRoute=`, `clusterScoped` on `OldDataRedirect`) + each view's `CCardTitle` (verbatim) + the view's lazy path. Standard rows (generator-owned): `serviceaccount`, `role`, `clusterrole`, `clusterrolebinding`, `namespace`, `node`, `crd`, `secret`, `priorityclass`, `runtimeclass`, `resourcequota`, `poddisruptionbudget`, `verticalpodautoscaler`, `horizontalpodautoscaler`, `limitrange`, `storageclass`, `configmap`, `snapshotclass`, `volumesnapshot`, `pvc`, `persistentvolume` (21 rows — the authoritative row list is the `App.tsx` blocks themselves; the Task 1 step transcribes them and the registry test locks the count). Custom rows (explicit blocks, `custom: true`): the `/network/ingress` tabbed route (kinds `ingress`/`gateway`/`httproute`/`referencegrant`), the `/network/ingress-class` tabbed route (kinds `ingressclass`/`gatewayclass`), the network-policy route (kinds `NetworkPolicy`/`CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy`). `persistentvolume`'s **list** is the claim-filter custom behaviour — its row is standard-routed but its list wrapper keeps the filter (a config-level exception inside `ResourceListView`'s row mapping, not a new branch: the list's fetch/filter closure is the row's `list` factory's business).

---

### Task 1: Door check — registry, shared components, generator, tracer kind (limitrange)

**Files:**
- Create: `frontend/src/lib/kinds.ts`, `frontend/src/components/ResourceListView.tsx`, `frontend/src/components/ResourceDataView.tsx`, `frontend/src/components/ResourceRoute.tsx`, `frontend/tests/lib/kinds.test.ts`, `frontend/tests/components/resource-list-view.test.tsx`, `frontend/tests/components/resource-data-view.test.tsx`
- Modify: `frontend/src/App.tsx` (generator + first row), `frontend/src/views/OtherResource/LimitRange.tsx` + `LimitRangeData.tsx` (thin wrappers)
- Test: the three new test files

**Interfaces:**
- Produces: `KindSpec { kind: string; title: string; route: string; clusterScoped?: boolean; custom?: boolean; list?: () => Promise<{ default: React.ComponentType<{ spec: KindSpec }> }>; data?: () => Promise<{ default: React.ComponentType<{ spec: KindSpec; name: string; namespace: string }> }> }`; `KINDS: KindSpec[]`; `<ResourceRoute spec>`; `<LegacyDataRoute spec>`; `<ResourceListView spec columns toRow item?>`; `<ResourceDataView spec name namespace detail>`
- Seam: the view's `spec` prop — a view's identity (title/kind/route) is injectable, so tests render any kind through the shared components without mounting the router
- Deletion test: deleting the generator re-creates 10 hand-unrolled route blocks per kind in `App.tsx`; deleting the shared components re-creates ~100 lines of fetch/table/breadcrumb/NOT_FOUND per view pair
- Adapters: 2 — the real router (generated routes) + the component tests (direct render with a stubbed `spec`)

**SATISFIES:** `registry-tracer-kind`

- [ ] **Step 1: Registry invariants (failing).** `kinds.test.ts`: routes unique; titles non-empty; every non-custom row has `list` + `data` factories; custom rows have no factories. Run `corepack pnpm vitest run tests/lib/kinds.test.ts` → FAIL (module missing).
- [ ] **Step 2: Implement `lib/kinds.ts`** — `KindSpec` + ALL rows (standard 21 + custom 3), transcribed from `App.tsx` + the views' `CCardTitle`s (the named sources); registry test green.
- [ ] **Step 3: Shared components (failing first).** `resource-list-view.test.tsx`: renders the card with `spec.title` (exact string assert), fetches via MSW (`/api/v1/clusters/1/resources/limitrange`), renders `KubeDataTable` rows from `toRow`, row click calls `openObject(spec.kind, name, ns, spec.route, …)` (spy). `resource-data-view.test.tsx`: renders detail for `{spec, name, namespace}`, NOT_FOUND state on empty fetch, breadcrumb list item clears the active ref (spy), JSON block present. Shared `KubeDataTable` fake extracted to `tests/components/kube-data-table.test-utils.tsx` (the fake the view tests already each re-write). Run → FAIL.
- [ ] **Step 4: Implement `ResourceListView`/`ResourceDataView`** — behaviour ported 1:1 from `LimitRange.tsx`/`LimitRangeData.tsx` (the named source), parameterised on `spec` + row config. Tests green.
- [ ] **Step 5: `ResourceRoute`/`LegacyDataRoute` + generator.** `App.tsx`: `KINDS.filter(s => !s.custom).map(s => <Route path={s.route} …/><Route path={s.route + '/data'} …/>)`; non-custom `App.tsx` edits only. The two limitrange blocks are deleted in favour of the generated pair.
- [ ] **Step 6: Convert the tracer.** `LimitRange.tsx` → `<ResourceListView spec={spec} columns={[name, namespace, created]} toRow={toRow} />`; `LimitRangeData.tsx` → `<ResourceDataView spec name namespace detail={…} />` (the limits table moves into `detail`).
- [ ] **Step 7: Chunk check.** `task fe-build`; confirm `dist/assets/` still contains a separate `LimitRange*` chunk (code splitting preserved) — record the chunk name in the commit body.
- [ ] **Step 8: Door-check verdict.** `corepack pnpm test` + `task fe-build` + `task fe-check` green; the e2e limitrange title (ui-smoke) green with the assertion unedited → PASSED. Any per-kind branch needed inside the shared components, a split-chunk loss, or an edited title assertion → **stop, report, user decides**.
- [ ] **Step 9: Commit.** `refactor: frontend kind registry + shared list/data views; cutover limitrange (door check passed)`

### Task 2: Batch A — the 7 kinds: serviceaccount, role, clusterrole, clusterrolebinding, namespace, node, crd

**Files:** Modify the 7 view pairs → thin wrappers; `App.tsx` (delete the 7 hand blocks; the generator now covers them)
**Interfaces:** Consumes Task 1's components/generator; Produces: nothing new
**SATISFIES:** `batch-a-converted`
- [ ] **Step 1: Convert the 7 pairs** — port each view's columns/`toRow`/detail table verbatim into its wrapper; delete the hand blocks from `App.tsx`.
- [ ] **Step 2: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `refactor: cutover batch A (7 kinds) to the generated registry`

### Task 3: Batch B — secret, priorityclass, runtimeclass, resourcequota, poddisruptionbudget, verticalpodautoscaler, horizontalpodautoscaler

**Files:** same shape as Task 2 (7 view pairs + `App.tsx`)
**Interfaces:** Consumes Task 1; Produces: nothing new
**SATISFIES:** `batch-b-converted`
- [ ] **Step 1: Convert the 7 pairs + delete the blocks.**
- [ ] **Step 2: Run + commit.** green → `refactor: cutover batch B (7 kinds) to the generated registry`

### Task 4: Batch C — storageclass, configmap, snapshotclass, volumesnapshot, pvc, persistentvolume

**Files:** same shape (6 view pairs + `App.tsx`)
**Interfaces:** Consumes Task 1; the `persistentvolume` list wrapper keeps its claim-namespace filter inside its row config (the named exception — the filter closure stays in the view, not in the shared component)
**SATISFIES:** `batch-c-converted`
- [ ] **Step 1: Convert the 6 pairs + delete the blocks.**
- [ ] **Step 2: Run + commit.** green → `refactor: cutover batch C (6 kinds) to the generated registry`

### Task 5: Custom rows locked, clone family gone, e2e backstop

**Files:**
- Modify: `frontend/src/App.tsx` (custom dispatcher routes reference their registry rows' metadata — `IngressRoute`/`IngressClassRoute`/`NetworkPolicyRoute` read `KINDS` for their route strings, no local constants)
- Test: `frontend/tests/` (any per-view test that faked `KubeDataTable` inline switches to the shared fake)

**Interfaces:** Consumes Tasks 1–4; Produces: the finished change
**SATISFIES:** `custom-rows-locked`
- [ ] **Step 1: Route strings from the registry** in the 3 dispatcher components (their `listRoute`/redirect constants become `KINDS` lookups); behaviour unchanged.
- [ ] **Step 2: Clone check.** `npx jscpd --reporters ai --summary` over `frontend/src/views` — the per-view clone family (the ~104L `*Data.tsx` pairs) is gone; record the before/after in the commit body.
- [ ] **Step 3: Full floor + e2e backstop.** `corepack pnpm test` + `task fe-build` + `task fe-check` + `task e2e` (exact-title smoke, assertions unedited) green.
- [ ] **Step 4: Commit.** `refactor: custom rows locked to registry; e2e title backstop green`

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Task 1 Step 2; R2 → Task 1 Step 5 + batches; R3 → Tasks 1 Steps 3–4 + batches; R4 → every task's e2e/frozen-assertion rule + Task 5 Step 3; R5 → Task 5 Step 1 (+ the PV filter exception, Task 4); R6 → global constraint (ADR-0040 intact, single-`kind` prop unchanged — that's change C); R7 → every task's green step. No gaps.
2. **Must-haves coverage:** R1–R7 map to truths/artifacts/links; the title backstop is the one `backstop` truth with `task e2e` as its held-out test.
3. **One-way-door completeness:** none — no URL/contract change; nothing to tag.
4. **Placeholder scan:** row lists are exhaustive (the registry test locks the count); the only dynamic step is the jscpd re-measure with the exact command.
5. **Type consistency:** `KindSpec` fields, component prop names, and route-pair paths used identically in Tasks 1–5.
