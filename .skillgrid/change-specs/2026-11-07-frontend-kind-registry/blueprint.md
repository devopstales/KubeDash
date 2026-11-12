# Frontend Kind Registry — Generated Routes + Shared Views — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T2
**Build shape:** Tracer thread — the open risk is whether one generated route block + shared list/data components reproduce the per-kind behaviour (exact titles, code splitting, `openObject` wiring, legacy redirects) for real kinds before the rest are converted; two tracers at the door — `limitrange` (single-fetch data) and `role` (the list-fetch + client-side-find data variant), so both shared data shapes are proven before any batch is cut.
**Classification:** standard (L2 verification floor: full unit suite + `task fe-build` + `task fe-check`)
**Goal:** One typed registry (`src/lib/kinds.ts`) owns every kind's route/plural/titles/redirect/custom flag; `App.tsx` renders resource routes from it; the 13 fully-standard view pairs + the 2 role/clusterrole pairs become thin config wrappers over two shared components (data variants: single-fetch / list-find); the 8 divergent sides (5 hand-rolled data views, 3 hand-rolled list views) stay custom-rendered — spec-driven identity, hand-rolled behaviour.
**Architecture:** `lib/kinds.ts` declares `KindSpec { kind, plural, title, route, clusterScoped?, legacyData?, custom?, kinds?, list?, data? }` where `list`/`data` are lazy import factories — lazy, so no static import cycle with the view files (the views receive their `spec` as a prop and import nothing from the registry); a side's factory absent → the shared component renders that side, present → the hand-rolled view (custom-rendered side). A `ResourceRoute` component in `App.tsx` loads a row's `list`/`data` and renders `ObjectRoute`; a generator emits one route pair per standard row (the `/data` route only when `legacyData` is not `false`). `ResourceListView` (card + breadcrumb + TanStack Query + `KubeDataTable` + `openObject` row wiring) and `ResourceDataView` (breadcrumb + fetch + NOT_FOUND + JSON highlight, or the `list-find` variant: full-list fetch + client-side find, transcribed data-title, no JSON) carry the behaviour the cloned pairs each re-implement; converted per-kind files shrink to config (columns, `toRow`, detail table). Custom rows (3 dispatcher routes, one row per route with `kinds: string[]`) keep hand-rolled views and stay explicit `<Route>` blocks; the registry still owns their metadata.
**Tech Stack:** React 19, TypeScript 5.8, react-router-dom, TanStack Query, CoreUI, Vitest + RTL + MSW.
**Spec:** `./briefing.md`
**Critic:** criticB (reviewer) 2026-11-07: **SOUND-WITH-FIXES** — 2 CRITICAL + 5 MAJOR + 8 MINOR, all findings folded in per user decision (hybrid: role/clusterrole get the shared list-find data variant, the other 5 divergent data views + 3 custom lists stay custom-rendered; cert-manager + external-LB dispatchers scoped out of B; the fleet `KubeDataTable` test-fake migration moved to change D; the row list corrected — `service` in, `clusterrolebinding` out; block counts corrected to 21 + 18 = 39)

## Hypothesis

**Claim:** One generated route block per registry row + two shared view components (data variants: single-fetch / list-find; the custom-rendered escape for the 8 divergent sides) reproduces the hand-rolled per-kind behaviour (byte-identical titles, per-view code splitting, ref-driven detail, legacy `/data` redirects where they shipped, the `openObject` seam) for all 21 standard kinds.
**Right condition:** both tracers (`limitrange`, `role`) converted and green (Step 8 of Task 1); after all batches, the 21 hand-unrolled `ObjectRoute` blocks + 18 `OldDataRedirect` blocks (39 total) are gone, replaced by the generator, and the unit-suite title pins (the 8 named test files) + the 5 view-derived e2e strings are green with **zero** assertions edited.
**Wrong condition:** a kind needs per-kind branching inside `ResourceListView`/`ResourceDataView` (a fifth column source, a data shape beyond {single-fetch, list-find}, a title that is not its transcribed string), or code splitting changes (the bundle must keep one chunk per view), or a unit/e2e title assertion must be edited.
**Thinnest MVP:** `limitrange` + `role` converted end-to-end (registry rows, shared components incl. the list-find data variant, generated route pair, tests).
**Door check:** Task 1.

## Terms

- **Kind**, **Kind catalog**, **Registry kind** — `.skillgrid/knowledge/glossary/02-technical-terms.md`
- **Custom-rendered side** — a standard row's list or data side keeps its hand-rolled view (the registry row carries that side's factory); the registry owns the route + metadata, the view owns the behaviour (criticB fold-in, 2026-11-07)
- **`list-find` data variant** — the shared data shape for role/clusterrole: fetch the full list, `find` client-side (criticB fold-in, 2026-11-07)
- Object navigation (ADR-0040), object ref, relay — repo ADR vocabulary

## Must-Haves (goal-backward verification)

**Truths:**
- [backstop] every card title renders byte-identically to today — backstop: the existing unit-suite title pins (`limit_ranges.test.tsx:182`, `limit_range_data.test.tsx:178`, `roles.test.tsx:145`, `cluster_roles.test.tsx:213`, `namespace_data.test.tsx:63`, `secrets.test.tsx:252`, `service_accounts.test.tsx:244`, `pvs.test.tsx:219`) + the 5 view-derived e2e strings (`Ingress List`, `IngressClass List`, `Persistent Volume List`, `CRD Data — ConfigMap`, non-exact `Namespace List`) — none may be edited (the e2e sweep's other exact strings pin the sidebar nav, not views; held-out: `task e2e`)
- list rows open the data view via `openObject` on the same route; the URL never carries object identity (ADR-0040 R1); the legacy `<route>/data` URL redirects as today where it shipped (R7) — the 6 storage first-build rows never shipped a `/data` URL, so the generator emits no redirect route for them (`legacyData: false`)
- each per-kind view stays a separate lazy chunk (code splitting unchanged) — `vite build` chunk list diff asserted in Task 1 (the tracers) and again in Task 5 for ALL converted kinds
- adding a standard kind touches `lib/kinds.ts` (one row) + one thin view pair — no `App.tsx` edit (verified by the tracer commit's diff)
- custom rows render exactly as today (tabbed ingress/ingress-class lists, the 3-kind network-policy dispatcher); custom-rendered sides render exactly as today (the 5 divergent data views: serviceaccount/namespace/node/crd/secret; the 3 custom list views: namespace/node/persistentvolume — spec-driven identity, hand-rolled behaviour)

**Artifacts:**
- `frontend/src/lib/kinds.ts` — `KindSpec` + `KINDS` registry (all rows)
- `frontend/src/components/ResourceListView.tsx` — shared list behaviour
- `frontend/src/components/ResourceDataView.tsx` — shared data behaviour
- `frontend/src/components/ResourceRoute.tsx` — per-row route element (lazy load + `ObjectRoute` wiring; legacy-redirect element too)
- `frontend/src/views/**` — per-kind files reduced to config wrappers (one per kind, lazy-load targets unchanged)
- `frontend/tests/lib/kinds.test.ts` — registry invariants
- `frontend/tests/components/resource-list-view.test.tsx` + `resource-data-view.test.tsx` — shared-component tests (incl. the shared `KubeDataTable` test fake)
- `frontend/src/App.tsx` — generator; the 39 hand-unrolled resource blocks gone (21 `ObjectRoute` + 18 `OldDataRedirect`)

**Key links:**
- `ResourceRoute` reads the row's lazy factories; for views rendered through the shared components the view's `spec` prop (title, `kind`, `plural`, `route`, `clusterScoped`) is the ONLY place a view learns its identity — no shared-rendered view may hard-code its `KIND`/`LIST_ROUTE`/title after conversion. Custom-rendered views keep their own copy (hand-rolled by definition) but take `spec` for `kind`/`plural`-driven fetches and `openObject` wiring
- `ResourceListView`'s `openObject(spec.kind, name, ns, spec.route, navigate)` wiring is the same seam the list views use today
- the generator iterates `KINDS`; a future row automatically gets its route pair — the registry test asserts route uniqueness so a typo fails
- custom rows are the only hand-written `<Route>` resource blocks left in `App.tsx` — except the named out-of-scope blocks (user decision 2026-11-07): the cert-manager + external-LB dispatcher blocks (8 kinds) and the role-binding/cluster-role-binding list-only plain routes (no `/data`, only targets openable — `RoleBinding.tsx:23`)

**One-way-door decisions:** None — no URL/contract change (ADR-0040 intact), no new dependency, e2e-asserted copy frozen.

## Global Constraints

- React 19 + TS 5.8 strict; CoreUI SCSS only (no Tailwind); no new dependencies (ADR-0020 air-gap: `task fe-check` green)
- unit-suite title pins + the 5 view-derived e2e strings are frozen — if one must change, stop and report (door-check failure)
- `corepack pnpm test` green at every commit; `task fe-build` + `task fe-sync` after frontend changes (the frontend loop)
- per-kind lazy chunks preserved (one chunk per view file)
- conventional commits; spec zone (this blueprint) commits before code zone

## File Structure

- `frontend/src/lib/kinds.ts` — registry data + `KindSpec`; imports nothing from `views/` statically (lazy factories only)
- `frontend/src/components/ResourceListView.tsx` — the list behaviour (fetch via `apiFetch` on the cluster store, `KubeDataTable`, breadcrumb/card, `openObject` row click)
- `frontend/src/components/ResourceDataView.tsx` — the data behaviour, two variants: `single` (fetch one object, muted NOT_FOUND state, metadata table, detail table, JSON `SyntaxHighlighter` block) and `list-find` (fetch the full list, client-side `find`, transcribed data-title, no metadata table, no JSON — the role/clusterrole shape)
- `frontend/src/components/ResourceRoute.tsx` — `<ResourceRoute spec>` (ObjectRoute element) + `<LegacyDataRoute spec>` (OldDataRedirect element)
- `frontend/src/App.tsx` — `queryClient` shell, non-resource routes, the 3 custom dispatcher routes + the untouched out-of-scope blocks (cert-manager/ELB dispatchers, role-binding/cluster-role-binding list-only routes), the generator over `KINDS`
- `frontend/src/views/<Area>/<Kind>.tsx` / `<Kind>Data.tsx` — thin wrappers: `<ResourceListView spec={spec} columns={...} toRow={...} />` / `<ResourceDataView spec={spec} detail={...} />`
- `frontend/tests/` — registry invariants, shared-component tests, shared `KubeDataTable` fake

## The Registry (rows)

Rows transcribed from `App.tsx` (`kind=`, `listRoute=`, `clusterScoped` on `OldDataRedirect`), each view's `CCardTitle` (verbatim), each view's fetch URL (the `plural`), and the view's lazy path. **Standard rows (21, generator-owned routes):** `serviceaccount`, `role`, `clusterrole`, `namespace`, `node`, `crd`, `secret`, `service`, `priorityclass`, `runtimeclass`, `resourcequota`, `poddisruptionbudget`, `verticalpodautoscaler`, `horizontalpodautoscaler`, `limitrange`, `storageclass`, `configmap`, `snapshotclass`, `volumesnapshot`, `pvc`, `persistentvolume` — the authoritative row list is the `App.tsx` `ObjectRoute` blocks themselves (grep-verified 21); the Task 1 step transcribes them and the registry test locks the exact kind **set** (an expected-kinds fixture — the count lock alone is blind to a row swap). **`clusterrolebinding`/`rolebinding` are NOT registry rows** — list-only plain routes with no `/data` redirect (`RoleBinding.tsx:23`: the kind is list-only; only its targets are openable); they stay hand-written as named out-of-scope blocks. **Per-side classification** (a side's factory absent → the shared component renders that side; present → the hand-rolled view, i.e. a custom-rendered side): fully-standard (both sides shared) — `service`, `priorityclass`, `runtimeclass`, `resourcequota`, `poddisruptionbudget`, `verticalpodautoscaler`, `horizontalpodautoscaler`, `limitrange`, `storageclass`, `configmap`, `snapshotclass`, `volumesnapshot`, `pvc` (13); shared list + `list-find` data — `role`, `clusterrole` (2); custom-rendered **data** (shared list, hand-rolled data view) — `serviceaccount`, `crd`, `secret` (3); custom-rendered **both sides** — `namespace`, `node` (2); custom-rendered **list** (shared data) — `persistentvolume` (claim filter + `/metrics/pvcs` join + custom cells stay in `Pv.tsx`). **`legacyData`** defaults `true`; `false` for exactly the 6 storage first-build rows (`storageclass`, `configmap`, `snapshotclass`, `volumesnapshot`, `pvc`, `persistentvolume`) — their `/data` URL never shipped (`App.tsx:1028-1131`), so the generator emits no `LegacyDataRoute` for them; `clusterScoped` for those 6 is transcribed from the data view's namespace-less prop (no `OldDataRedirect` exists to read). **Custom rows (3, `custom: true`, one row per route — `kinds: string[]`, the redirect-fallback kind is the first entry):** the `/network/ingress` tabbed route (kinds `ingress`/`gateway`/`httproute`/`referencegrant`), the `/network/ingress-class` tabbed route (kinds `ingressclass`/`gatewayclass`), the network-policy route (kinds `NetworkPolicy`/`CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy`). **Out of scope (user decision 2026-11-07):** the cert-manager + external-LB dispatcher blocks and their 8 kinds (`clusterissuer`/`issuer`/`certificaterequest`/`certificate`, `ipaddresspool`/`l2advertisement`/`bgpeers`/`bgpadvertisement`) stay hand-written in `App.tsx` — a future change can register them.

---

### Task 1: Door check — registry, shared components, generator, tracer kind (limitrange)

**Files:**
- Create: `frontend/src/lib/kinds.ts`, `frontend/src/components/ResourceListView.tsx`, `frontend/src/components/ResourceDataView.tsx`, `frontend/src/components/ResourceRoute.tsx`, `frontend/tests/lib/kinds.test.ts`, `frontend/tests/components/resource-list-view.test.tsx`, `frontend/tests/components/resource-data-view.test.tsx`
- Modify: `frontend/src/App.tsx` (generator + the 2 tracer rows), `frontend/src/views/OtherResource/LimitRange.tsx` + `LimitRangeData.tsx` (thin wrappers), `frontend/src/views/ClusterPermission/Role.tsx` + `RoleData.tsx` (thin wrappers — the list-find data tracer), `frontend/tests/views/limit_ranges.test.tsx` + `limit_range_data.test.tsx` + `roles.test.tsx` (pass the registry row's `spec` to the converted views in `renderAt`)
- Test: the three new test files + the three modified view tests

**Interfaces:**
- Produces: `KindSpec { kind: string; plural: string (transcribed from the view's fetch URL — today `kind + 's'` for all 21; the backend ADR-0041 catalog carries the explicit plural); title: string (the list card title, verbatim); route: string; clusterScoped?: boolean; legacyData?: boolean (default true); custom?: boolean; kinds?: string[] (custom rows only — the route's kind set); list?: () => Promise<{ default: React.ComponentType<{ spec: KindSpec }> }> (absent → `ResourceListView`); data?: () => Promise<{ default: React.ComponentType<{ spec: KindSpec; name: string; namespace: string }> }> (absent → `ResourceDataView`) }`; the per-kind string set for shared-rendered rows (data card title, data breadcrumb label, metadata Kind-row display, JSON card title, loading/error/empty/not-found copy) transcribed verbatim per row into the registry — the shared components render from `spec`, never from hard-coded copy; `KINDS: KindSpec[]`; `<ResourceRoute spec>` (content wrapped in `ProtectedRoute` — every resource route today is guarded; unauthenticated visits to generated routes must not lose the guard); `<LegacyDataRoute spec>` (emitted only when `legacyData` is not `false`); `<ResourceListView spec columns toRow>` with `toRow: (item: Record<string, unknown>, namespace?: string) => Row` (the real `toRow`s are all `(item)` or `(item, namespace)` — one explicit signature; the old `item?` prop is dropped); `<ResourceDataView spec name namespace detail dataVariant?>` with `dataVariant: 'single' | 'list-find'` (default `'single'`)
- Seam: the view's `spec` prop — a view's identity (title/kind/route) is injectable, so tests render any kind through the shared components without mounting the router
- Seam: the view's `spec` prop — a view's identity (title/kind/route) is injectable, so tests render any kind through the shared components without mounting the router
- Deletion test: deleting the generator re-creates 10 hand-unrolled route blocks per kind in `App.tsx`; deleting the shared components re-creates ~100 lines of fetch/table/breadcrumb/NOT_FOUND per view pair
- Adapters: 2 — the real router (generated routes) + the component tests (direct render with a stubbed `spec`)

**SATISFIES:** `registry-tracer-kind`

- [ ] **Step 1: Registry invariants (failing).** `kinds.test.ts`: routes unique across all 24 rows; titles non-empty; the standard-kind set equals the expected-kinds fixture (pins composition, not just the count); a standard row's side is shared-rendered ⇔ its factory is absent; custom rows have no factories + a non-empty `kinds` array; `plural` non-empty for every row; `legacyData: false` only on the 6 storage rows. Run `corepack pnpm vitest run tests/lib/kinds.test.ts` → FAIL (module missing).
- [ ] **Step 2: Implement `lib/kinds.ts`** — `KindSpec` + ALL rows (standard 21 + custom 3) per the Registry section's classification, transcribed from `App.tsx` + the views' `CCardTitle`s + fetch URLs (plurals) + the 6 storage rows' `legacyData: false` + `clusterScoped` from `OldDataRedirect` (or the data view's namespace-less prop for the 6); registry test green.
- [ ] **Step 3: Shared components (failing first).** `resource-list-view.test.tsx`: renders the card with `spec.title` (exact string assert), fetches via MSW (`/api/v1/clusters/1/resources/limitrange`), renders `KubeDataTable` rows from `toRow`, row click calls `openObject(spec.kind, name, ns, spec.route, …)` (spy). `resource-data-view.test.tsx`: renders detail for `{spec, name, namespace}`, NOT_FOUND state on empty fetch, breadcrumb list item clears the active ref (spy), JSON block present. the `list-find` variant (role shape: full-list fetch + client-side `find`, transcribed data-title, no metadata table, no JSON block) renders its detail on a hit and the muted NOT_FOUND on a miss. Shared `KubeDataTable` fake extracted to `tests/components/kube-data-table.test-utils.tsx` — the **faithful** init-time-capture variant (the PV/PVC usage-join tests depend on its DataTables quirk); the fleet migration of the ~20 existing inline fakes is change D, not here. Run → FAIL.
- [ ] **Step 4: Implement `ResourceListView`/`ResourceDataView`** — behaviour ported 1:1 from `LimitRange.tsx`/`LimitRangeData.tsx` (the named source), parameterised on `spec` + row config. Tests green.
- [ ] **Step 5: `ResourceRoute`/`LegacyDataRoute` + generator.** `App.tsx`: `KINDS.filter(s => !s.custom).map(s => <Route path={s.route} …/>{s.legacyData !== false && <Route path={s.route + '/data'} …/>})` (no `/data` route for the 6 storage rows); both elements wrap their content in `ProtectedRoute`; non-custom `App.tsx` edits only. The limitrange + role blocks are deleted in favour of the generated pairs.
- [ ] **Step 6: Convert the tracers.** `LimitRange.tsx` → `<ResourceListView spec={spec} columns={[name, namespace, created]} toRow={toRow} />`; `LimitRangeData.tsx` → `<ResourceDataView spec name namespace detail={…} />` (the limits table moves into `detail`). `Role.tsx` → the shared list; `RoleData.tsx` → `<ResourceDataView spec name namespace dataVariant="list-find" detail={…} />` (the rule table moves into `detail`). The three modified view tests pass their registry row's `spec` in `renderAt`.
- [ ] **Step 7: Chunk check.** `task fe-build`; confirm `dist/assets/` still contains separate `LimitRange*` + `Role*` chunks (code splitting preserved — each lazy factory is a distinct dynamic `import()`, so the factories living in `lib/kinds.ts` cannot merge chunks) — record the chunk names in the commit body. Task 5 re-runs this diff for ALL converted kinds.
- [ ] **Step 8: Door-check verdict.** `corepack pnpm test` + `task fe-build` + `task fe-check` green; the unit-suite title pins (`limit_ranges`/`limit_range_data`/`roles.test.tsx`) green **unedited** → PASSED. (The e2e sweep asserts no `Limit Ranges` string — ui-smoke only shell-checks that route — so the unit pins ARE the title backstop; `task e2e` runs unedited as the full-surface gate.) Any per-kind branch needed inside the shared components, a split-chunk loss, or an edited title pin → **stop, report, user decides**.
- [ ] **Step 9: Commit.** `refactor: frontend kind registry + shared list/data views; cutover limitrange (door check passed)`

### Task 2: Batch A — the 6 kinds: serviceaccount, role, clusterrole, namespace, node, crd

**Files:** Modify: `Role.tsx` + `RoleData.tsx` + `ClusterRole.tsx` + `ClusterRoleData.tsx` (thin wrappers — `role`/`clusterrole` are the list-find data pair), `ServiceAccount.tsx` + `CRDs.tsx` (list wrappers; `ServiceAccountData.tsx`/`CrdData.tsx` stay hand-rolled, take `spec` for `kind`/`plural`-driven fetches), `App.tsx` (delete the 6 hand blocks; the generator now covers them), the batch's view tests (`cluster_roles.test.tsx`, `service_accounts.test.tsx`, `namespaces.test.tsx`, `namespace_data.test.tsx`, `nodes.test.tsx`, `crds.test.tsx` — pass the registry row's `spec` where the view gains one; `roles.test.tsx` already handled in Task 1)
**Interfaces:** Consumes Task 1's components/generator; Produces: nothing new
**SATISFIES:** `batch-a-converted`
- [ ] **Step 1: Convert the 6 kinds per the Registry classification** — `role`/`clusterrole`: list + `list-find` data wrappers (the rule tables move into `detail`); `serviceaccount`/`crd`: list wrappers only (the data views stay hand-rolled); `namespace`/`node`: route coverage only (both views stay hand-rolled — the TopMenu admin button / delete column / rollup tiles / second `/metrics/*` query stay in the views); delete the 6 hand blocks from `App.tsx`.
- [ ] **Step 2: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `refactor: cutover batch A (6 kinds) to the generated registry`

### Task 3: Batch B — secret, priorityclass, runtimeclass, resourcequota, poddisruptionbudget, verticalpodautoscaler, horizontalpodautoscaler

**Files:** same shape as Task 2 — `secret` is custom-rendered **data** (shared list wrapper + `SecretData.tsx` stays hand-rolled: reveal/clipboard, no JSON, red not-found); the other 6 kinds are fully-standard; view tests: `secrets.test.tsx` + the 6 standard kinds' test files (pass the registry row's `spec`)
**Interfaces:** Consumes Task 1; Produces: nothing new
**SATISFIES:** `batch-b-converted`
- [ ] **Step 1: Convert the 7 kinds per the Registry classification + delete the blocks.**
- [ ] **Step 2: Run + commit.** green → `refactor: cutover batch B (7 kinds) to the generated registry`

### Task 4: Batch C — storageclass, configmap, snapshotclass, volumesnapshot, pvc, persistentvolume

**Files:** same shape (6 view pairs + `App.tsx`); all 6 rows carry `legacyData: false` — the generator emits no `/data` route for any of them; `persistentvolume` is custom-rendered **list** (`Pv.tsx` stays hand-rolled: claim filter + `/metrics/pvcs` join + status/usage cells; `PvData.tsx` → shared wrapper); view tests: `pvs.test.tsx` (the faithful `KubeDataTable` fake the usage-join tests depend on), `pvcs.test.tsx`, `storage_classes.test.tsx`, `configmaps.test.tsx`, `snapshot_classes.test.tsx`, `volume_snapshots.test.tsx`
**Interfaces:** Consumes Task 1; the PV exception is structural, not a config flag — the row's `list` factory points at the hand-rolled view, the shared component is not involved
**SATISFIES:** `batch-c-converted`
- [ ] **Step 1: Convert the 6 kinds per the Registry classification + delete the blocks.**
- [ ] **Step 2: Run + commit.** green → `refactor: cutover batch C (6 kinds) to the generated registry`

### Task 5: Custom rows locked, clone family gone, e2e backstop

**Files:**
- Modify: `frontend/src/App.tsx` (the 3 custom route blocks read their route strings from their registry rows — no path literals in the blocks; the list views' `LIST_ROUTE` constants stay untouched — change C rewires the dispatcher routes)

**Interfaces:** Consumes Tasks 1–4; Produces: the finished change
**SATISFIES:** `custom-rows-locked`
- [ ] **Step 1: Route strings from the registry** in the 3 custom `App.tsx` route blocks (path literals become row lookups); behaviour unchanged.
- [ ] **Step 2: Clone check + chunk diff.** `npx jscpd --reporters ai --summary` over `frontend/src/views` — the per-view clone family among shared-rendered kinds (the ~104L `*Data.tsx` pairs, the 13 standard + 2 list-find) is gone (the 8 custom-rendered sides are hand-rolled by design); `vite build` chunk list diff for ALL converted kinds — one chunk per view file; record both before/afters in the commit body.
- [ ] **Step 3: Full floor + title backstop.** `corepack pnpm test` (unit title pins unedited) + `task fe-build` + `task fe-check` + `task e2e` (the 5 view-derived strings unedited; the sweep's other exact strings pin the sidebar nav) green.
- [ ] **Step 4: Commit.** `refactor: custom rows locked to registry; e2e title backstop green`

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Task 1 Step 2; R2 → Task 1 Step 5 + batches; R3 → Tasks 1 Steps 3–4 + batches; R4 → every task's e2e/frozen-assertion rule + Task 5 Step 3; R5 → Task 5 Step 1 (+ the PV filter exception, Task 4); R6 → global constraint (ADR-0040 intact, single-`kind` prop unchanged — that's change C); R7 → every task's green step. No gaps.
2. **Must-haves coverage:** R1–R7 map to truths/artifacts/links; the title backstop is the one `backstop` truth with `task e2e` as its held-out test.
3. **One-way-door completeness:** none — no URL/contract change; nothing to tag.
4. **Placeholder scan:** row lists are exhaustive (the registry test locks the count); the only dynamic step is the jscpd re-measure with the exact command.
5. **Type consistency:** `KindSpec` fields, component prop names, and route-pair paths used identically in Tasks 1–5.
6. **Critic fold-in (2026-11-07):** all 15 criticB findings resolved per user decision — row list corrected (`service` in, `clusterrolebinding` out; role-binding/cluster-role-binding = list-only plain routes); hybrid classification (role/clusterrole list-find shared variant, the other 5 divergent data views + 3 custom lists custom-rendered); `legacyData` for the 6 storage rows; the door check re-cited to the unit title pins; the batch view-test files added to the Files lists; the PV exception made structural (row `list` factory, no shared-component escape); cert-manager/ELB scoped out (named remaining hand-written blocks); one row per custom route with `kinds: string[]`; the per-kind string set enumerated; chunk diff asserted in Task 5; counts corrected (21 + 18 = 39) + the expected-kinds set fixture; Task 5 Step 1 scoped to the `App.tsx` custom blocks; the fleet test-fake migration moved to change D; `plural` added to `KindSpec`; the `toRow` signature fixed + `item?` dropped; `ProtectedRoute` in both route elements + the `clusterScoped` transcription source named.
