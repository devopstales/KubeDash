# Navigation Seam — Multi-Kind Routes + Kind-Keyed Registry — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T1
**Build shape:** Smallest usable whole — the change is one seam + one component prop + three conversions + two pinned tests; the whole is small enough to ship as one unit, and it is usable (and testable) only complete.
**Classification:** small (L1 verification floor: focused tests + full unit suite + `task fe-build`)
**Goal:** `ObjectRoute` takes `kinds: string[]`, the navigate seam becomes a kind-keyed registry in `lib/objectRef.ts` with proper unregistration, the three in-scope hand-rolled dispatchers (network-policy, ingress, ingress-class) collapse into multi-kind `ObjectRoute` elements — the two out-of-scope dispatchers (cert-manager, external-LB) migrate their seam registrations but stay hand-rolled — and the relay TTL pair is pinned by tests on both sides.
**Architecture:** The seam moves from a single-slot module global in `ObjectRoute.tsx` (three writers, last-mount-wins, no unregistration — a stale-closure leak on unmount) to a `Map<string, NavigateFn>` in `lib/objectRef.ts` keyed by kind: `registerNavigate(kinds, fn)` / `unregisterNavigate(kinds, fn)` (remove only entries still pointing at your own fn) / `getNavigateFor(kind)`. Cross-kind stomping is impossible (a kind belongs to exactly one mounted route — asserted by a kind-disjointness test); the old global is deleted. `ObjectRoute` matches the active ref against any of `kinds` and hands the matched `kind` to `detail`, so the tabbed routes are `kinds: ['ingress', 'gateway', 'httproute', 'referencegrant']` + a kind-switching `detail` — no dispatcher components.
**Tech Stack:** React 19, TypeScript 5.8, Vitest + RTL; pytest for the backend TTL pin.
**Spec:** `./briefing.md`
**Critic:** criticC (reviewer) 2026-11-07: **SOUND-WITH-FIXES** — 3 MAJOR + 6 MINOR, all findings folded in (the 5-vs-3 dispatcher inventory corrected — cert-manager/ELB seam registrations migrate in Task 1, their components stay hand-rolled per the user's B scope decision; the ~49-file test-side migration gets its own step with both discovery greps; the relay-consumption delta declared an explicit truth with a mount test; the backend pin file/locator corrected; briefing R2 reconciled to the code; the `registerNavigate` re-export deleted; the kind-disjointness invariant tested; the e2e backstop re-scoped to what it actually covers)
**Depends on:** Change B landed (the generated routes exist; the `ResourceRoute` wrapper passes `kinds={[spec.kind]}` and is updated in Task 1).

## Hypothesis

**Claim:** A kind-keyed navigate registry + `kinds: string[]` on `ObjectRoute` expresses the five multi-kind routes with zero duplicated seam logic and no behaviour change (one documented additive delta: deep links to the three converted routes now consume the relay on mount — parity with single-kind routes).
**Right condition:** the three in-scope dispatcher components deleted (the cert-manager/ELB components stay hand-rolled per the B scope decision — their seam registrations are migrated); one `ObjectRoute` per converted multi-kind route; the seam registry keyed (no single-slot global anywhere — grep-provable); object-navigation e2e green.
**Wrong condition:** a multi-kind route needs behaviour the `detail(params)` switch cannot express (e.g. per-kind list rendering — the tabbed lists render ONE list component regardless of kind, so this is expected not to happen), or the relay/redirect behaviour drifts.
**Thinnest MVP:** the seam registry + prop change + one converted route (network-policy — the `kindFromParam` case, the hardest).
**Door check:** Task 1.

## Terms

- Object navigation, object ref, relay — ADR-0040 vocabulary; no new terms

## Must-Haves (goal-backward verification)

**Truths:**
- `ObjectRoute` renders the detail iff the active ref's kind ∈ `kinds`; `detail` receives the matched `kind` (for a single-kind route, that kind)
- exactly one `ObjectRoute` element per **converted** multi-kind route; `NetworkPolicyRoute`/`IngressRoute`/`IngressClassRoute` no longer exist; `CertManagerRoute`/`ExternalLoadBalancerRoute` still exist (out of scope per the user's B decision) but their seam registrations use the kind-keyed API
- the navigate registry is kind-keyed: registering for `['a']` then `['b']` leaves `getNavigateFor('a')` intact; unmount removes only the fn that was registered (a second component mounting for the same kind replaces, then its unmount restores nothing — last-mounted-wins **per kind** is the contract)
- unmount unregisters: after the route unmounts, `getNavigateFor(kind)` no longer returns its (stale) fn
- frontend `RELAY_TTL_MS === 60_000` and backend `STASH_TTL_SECONDS === 60` — each pinned by a test that names the counterpart constant (the cross-boundary invariant is test-enforced)
- behaviour unchanged except one documented additive delta (criticC fold-in): the three **converted** multi-kind routes now consume the relay on mount (`ObjectRoute`'s existing `consumeIncoming` path) — deep links to them gain the same relay handoff single-kind routes have today; none of the five dispatchers ever did. Ref-driven detail, relay consumption on single-kind routes, legacy redirects, `origin: 'link'` hydration all unchanged — e2e object-navigation green

**Artifacts:**
- `frontend/src/lib/objectRef.ts` — the kind-keyed registry (`registerNavigate`/`unregisterNavigate`/`getNavigateFor` + `NavigateFn` type home)
- `frontend/src/components/ObjectRoute.tsx` — `kinds: string[]` prop, kind-matched `detail`, register/unregister lifecycle; the single-slot global deleted
- `frontend/src/App.tsx` — three multi-kind `ObjectRoute` elements; the three dispatchers deleted
- `frontend/src/components/ResourceRoute.tsx` (from B) — passes `kinds={[spec.kind]}`
- `frontend/tests/components/object_route.test.tsx` — rewritten for `kinds` + the keyed registry (incl. the unmount-unregister case)
- `frontend/tests/lib/objectRef.test.ts` — registry tests + the pinned `RELAY_TTL_MS`
- `backend/tests/api/test_object_handoff.py` (where the `object_handoff` tests live; `STASH_TTL_SECONDS` is defined in `app/core/object_handoff.py:39`) — pinned `STASH_TTL_SECONDS == 60`

**Key links:**
- `ObjectRoute`'s register (mount) / unregister (unmount) pair is the ONLY writer of the registry; `OldDataRedirect` needs no seam (it `<Navigate>`s directly — verified 2026-11-07: it imports only `mintToken`/`readRegistry`/`setActiveRef`/`writeRegistry` and does not read the navigate registry; the seam's production readers are none — the registry exists for the redirect-path seam's future + test observability; briefing R2's `getNavigateFor` wording is amended to match)
- the `detail` switch in the three converted routes is the ONLY per-kind branch left in navigation for in-scope kinds; the two out-of-scope dispatchers (cert-manager/ELB) keep their own `detail` branches
- each TTL test names the other side's constant + file in a comment — the pin is bilateral by construction

**One-way-door decisions:** None — the breaking `kind` → `kinds` prop is internal (all call sites migrate in-change); no URL/contract change.

## Global Constraints

- React 19 + TS 5.8 strict; no new dependencies; `task fe-check` (air-gap) green
- ADR-0040 semantics frozen: ref-driven detail, no identity in URLs, relay consumption on mount exactly once
- `corepack pnpm test` green at every commit; `task fe-build` + `task fe-sync` after changes
- conventional commits; spec zone commits before code zone

## File Structure

- `frontend/src/lib/objectRef.ts` — existing ref/relay API + the kind-keyed navigate registry (the seam's home; stays router-free — it stores callables, never imports react-router)
- `frontend/src/components/ObjectRoute.tsx` — the wrapper (kinds, detail-with-kind, lifecycle)
- `frontend/src/components/ResourceRoute.tsx` — B's generated-route element (one-line update)
- `frontend/src/App.tsx` — the three converted route blocks + the 2 out-of-scope dispatchers' migrated registrations (their components stay hand-rolled)
- `frontend/tests/components/object_route.test.tsx`, `frontend/tests/lib/objectRef.test.ts`
- `backend/tests/api/test_object_handoff.py` — the backend pin

---

### Task 1: Kind-keyed registry + `kinds: string[]` (the breaking prop) + call-site migration

**Files:**
- Modify: `frontend/src/lib/objectRef.ts` (registry in), `frontend/src/components/ObjectRoute.tsx` (prop + lifecycle + global out + the `registerNavigate` re-export deleted — all import sites take it from `lib/objectRef.ts`), `frontend/src/App.tsx` (every single-kind `ObjectRoute` call site — post-B this is at most the `service` block (:1180) — + **all 5 dispatchers'** registrations adapt to the new signatures: the 3 in-scope ones keep their own registration until Task 2 deletes them; the 2 out-of-scope (cert-manager :295, external-LB :340) stay migrated), `frontend/src/components/ResourceRoute.tsx` (`kinds={[spec.kind]}`), the test-side migration: the 44 test files rendering `<ObjectRoute kind=…>` (58 sites — `grep -rln "<ObjectRoute" frontend/tests`) + the 5 test files importing the old single-arg `registerNavigate` (`grep -rln "registerNavigate" frontend/tests`: `nav.test.tsx`, `views/network_policies.test.tsx`, `views/certmanager.test.tsx`, `views/external_loadbalancer.test.tsx`, `views/gateway_api_data.test.tsx`) + `frontend/tests/components/object_route.test.tsx`
- Test: `frontend/tests/lib/objectRef.test.ts` (registry semantics, failing first)

**Interfaces:**
- Produces: `NavigateFn = (path: string) => void`; `registerNavigate(kinds: string[], fn: NavigateFn): void`; `unregisterNavigate(kinds: string[], fn: NavigateFn): void` (removes an entry only if it still equals `fn`); `getNavigateFor(kind: string): NavigateFn | null`; `ObjectRouteProps { kinds: string[]; listRoute: string; list: ReactNode; detail: (params: { name: string; namespace?: string; kind: string }) => ReactNode }`
- Consumes: B's `ResourceRoute` + generated routes
- Seam: `lib/objectRef.ts` is router-free (stores callables) — the seam's interface is the three functions
- Deletion test: deleting the registry re-creates the single-slot global + the last-mount-wins ambiguity across the 6 writers
- Adapters: 2 — the mounted `ObjectRoute` (prod) + the test registry assertions

**SATISFIES:** `keyed-seam`

- [ ] **Step 1: Failing tests.** `objectRef.test.ts`: register `['a'],f1` + `['b'],f2` → `getNavigateFor('a')===f1` (no cross-kind clobber); `unregisterNavigate(['a'],f1)` → `getNavigateFor('a')===null`, `['b']` intact; unregister with a different fn is a no-op (guard against unmount-after-replace); direct replace: register `['a'],f1` → register `['a'],f2` → `getNavigateFor('a')===f2` (last-write-wins per kind); the route table's kind sets are disjoint (an exhaustive list from the 5 dispatcher kind arrays + the single-kind routes — a duplicate kind fails the test). `object_route.test.tsx`: `kinds: ['x']` renders detail for a ref of kind `x`, list otherwise; `detail` receives `kind: 'x'`; after unmount `getNavigateFor('x')` is null; the old `getRegisteredNavigate` import is gone from the test. Run `corepack pnpm vitest run tests/lib/objectRef.test.ts tests/components/object_route.test.tsx` → FAIL.
- [ ] **Step 2: Implement the registry** in `objectRef.ts` (`Map<string, NavigateFn>` + the three functions); move `NavigateFn` there.
- [ ] **Step 3: `ObjectRoute` — `kinds: string[]`, kind-matched `detail`, register on mount / unregister on unmount; delete the single-slot global + `getRegisteredNavigate`.**
- [ ] **Step 4: Migrate call sites.** `App.tsx`: every `<ObjectRoute kind="k"` → `kinds={["k"]}`; **all 5** dispatchers call `registerNavigate([their kinds], fn)` (and the effect gains the matching cleanup — the stale-closure leak is fixed even for them; the cert-manager/ELB kinds arrays from App.tsx:283-287 / :328-332); `ResourceRoute` → `kinds={[spec.kind]}`. Test side: every `<ObjectRoute kind="k"` in the 44 test files → `kinds={["k"]}`; the 5 `registerNavigate` imports move to `lib/objectRef.ts` + two-arg calls (record both file counts in the commit body).
- [ ] **Step 5: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `refactor: kind-keyed navigate registry + ObjectRoute kinds (breaking prop, all call sites migrated)`

### Task 2: Delete the three dispatchers — multi-kind `ObjectRoute` elements

**Files:**
- Modify: `frontend/src/App.tsx` (the 3 route blocks → single `ObjectRoute` elements; the 3 dispatcher components deleted)
- Test: `frontend/tests/` (any test importing the 3 in-scope dispatchers — `grep -rln "NetworkPolicyRoute\|IngressRoute\b\|IngressClassRoute" tests/`; the cert-manager/ELB test mirrors are untouched — their components stay)

**Interfaces:**
- Consumes: Task 1's `kinds` + kind-switching `detail`
- Produces: the finished navigation surface

**SATISFIES:** `dispatchers-collapsed`

- [ ] **Step 1: Convert.** `/security/network-policy` → `<ObjectRoute kinds={['NetworkPolicy','CiliumNetworkPolicy','CiliumClusterwideNetworkPolicy']} listRoute=… list={<NetworkPolicyView/>} detail={(p) => <NetworkPolicyDataView name={p.name} kind={p.kind} namespace={p.namespace ?? ''} />} />` (the `kindFromParam` legacy redirect is untouched — it's `OldDataRedirect`'s business). `/network/ingress` → `kinds={['ingress','gateway','httproute','referencegrant']}`, `detail={(p) => p.kind === 'ingress' ? <IngressDataView name={p.name} namespace={p.namespace ?? ''}/> : <GatewayApiDataView name={p.name} kind={p.kind} namespace={p.namespace ?? ''}/>}`. `/network/ingress-class` → `kinds={['ingressclass','gatewayclass']}`, `detail={(p) => p.kind === 'ingressclass' ? <IngressClassDataView name={p.name}/> : <GatewayClassDataView name={p.name}/>}`. Delete `NetworkPolicyRoute`/`IngressRoute`/`IngressClassRoute` + their `registerNavigate`/`sweepRelay`/bump machinery (~135 lines of duplicated seam logic). The rewritten blocks take `listRoute` from their `KINDS` custom rows (B's registry owns the route data — `ObjectRoute`'s `listRoute` prop is documentation-value only: verified unused in the render path). `CertManagerRoute`/`ExternalLoadBalancerRoute` are untouched (out of scope per the B decision — their seam registrations were already migrated in Task 1).
- [ ] **Step 2: Regression tests.** For each converted route: the list renders once (tabbed list, no per-kind duplication), a ref of each kind renders the right detail, a ref of a foreign kind renders the list; **plus the relay-consumption delta test** (the documented behaviour addition): seed the relay + one-shot meta, mount a converted route element, assert the detail renders AND the relay self-deletes (mirroring `object_route.test.tsx:64-89`). One `OldDataRedirect` `kindFromParam` unit test (fallback kind → detail; foreign `?kind=` → list) — three routes depend on it and nothing tests it today. (The `object_route.test.tsx` patterns from Task 1, at the route level via the App render or the route elements directly.)
- [ ] **Step 3: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `refactor: three multi-kind routes on ObjectRoute kinds (dispatchers deleted)`

### Task 3: Pinned relay-TTL tests, both sides

**Files:**
- Modify: `frontend/tests/lib/objectRef.test.ts` (the frontend pin), `backend/tests/api/test_object_handoff.py` (the backend pin — where the `object_handoff` tests live; `STASH_TTL_SECONDS` is defined in `app/core/object_handoff.py:39`)
- Test: both files

**Interfaces:** Consumes: `RELAY_TTL_MS` (`frontend/src/lib/objectRef.ts`), `STASH_TTL_SECONDS` (`backend/app/core/object_handoff.py:39`)
**SATISFIES:** `ttl-pinned`
- [ ] **Step 1: Frontend pin.** `test('relay TTL is pinned to the backend stash TTL', () => { expect(RELAY_TTL_MS).toBe(60_000) })` — comment: `// backend/app/core/object_handoff.py STASH_TTL_SECONDS — change both together (ADR-0040 R4 handoff window)`.
- [ ] **Step 2: Backend pin.** `def test_stash_ttl_pinned_to_frontend_relay_ttl(): assert STASH_TTL_SECONDS == 60` — comment: `# frontend/src/lib/objectRef.ts RELAY_TTL_MS — change both together (ADR-0040 R4 handoff window)`.
- [ ] **Step 3: Run + commit.** `corepack pnpm test && uv run pytest tests/api/test_object_handoff.py -v` → `test: pin the relay TTL pair on both sides of the boundary`

### Task 4: Green + e2e backstop

**Files:** none (verification only)
**SATISFIES:** `seam-green`
- [ ] **Step 1: Full floor.** `corepack pnpm test` + `task fe-build` + `task fe-check` + `uv run pytest -m "not integration"`.
- [ ] **Step 2: e2e backstop.** `task e2e` — green. (What it actually covers: the three converted routes as list-title mounts only; the sole relay-consumption e2e is the single-kind `crd` deep link; the sole old-URL-redirect e2e is `/security/secret/data`; `kindFromParam` has no e2e — its coverage is the Task 2 Step 2 unit test. Row-click→detail has no e2e at all — unit-only, by design.)
- [ ] **Step 3: Prove the global is gone.** `grep -rn "registeredNavigate\|getRegisteredNavigate" frontend/src` → zero hits. Record in the commit body.
- [ ] **Step 4: Commit** (if Step 3's proof changed nothing, fold into the Task 3 commit; otherwise `chore: seam proof — single-slot global gone`).

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Task 1; R2 → Task 1 (registry in `objectRef.ts`, global deleted); R3 → Task 2; R4 → Task 3; R5 → Task 4. No gaps.
2. **Must-haves coverage:** every truth maps to a task step; the registry contract (per-kind last-write-wins, unmount-unregister, replace-guard) is fully specified in Task 1 Step 1's tests.
3. **One-way-door completeness:** the breaking prop is internal (all call sites in-change) — correctly not flagged.
4. **Placeholder scan:** the backend test file is named by the exact grep that locates it (a step, not a TBD); all kind arrays are exhaustive from the current dispatchers.
5. **Type consistency:** `NavigateFn`, `registerNavigate`/`unregisterNavigate`/`getNavigateFor`, `ObjectRouteProps` used identically across tasks and tests.
6. **Critic fold-in (2026-11-07):** all 9 criticC findings resolved — the 5-vs-3 dispatcher inventory (cert-manager/ELB seam registrations migrate in Task 1, components stay hand-rolled per the user's B scope decision — the documented 3-convert/2-keep asymmetry); the ~49-file test-side migration with both discovery greps + the file counts in the commit body; the relay-consumption delta declared an explicit truth + a mount test; the backend pin file corrected (`tests/api/test_object_handoff.py`) + the locating grep dropped; briefing R2 reconciled to the code (the seam has no production readers); the `registerNavigate` re-export deleted (6 import sites moved); the rewritten blocks' `listRoute` sourced from `KINDS` (B's route data stays live); the kind-disjointness invariant + the direct-replace assertion tested; the e2e backstop re-scoped to what it actually covers + the `kindFromParam` unit test.
