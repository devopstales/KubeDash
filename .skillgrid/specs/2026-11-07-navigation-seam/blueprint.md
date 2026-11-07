# Navigation Seam — Multi-Kind Routes + Kind-Keyed Registry — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T1
**Build shape:** Smallest usable whole — the change is one seam + one component prop + three conversions + two pinned tests; the whole is small enough to ship as one unit, and it is usable (and testable) only complete.
**Classification:** small (L1 verification floor: focused tests + full unit suite + `task fe-build`)
**Goal:** `ObjectRoute` takes `kinds: string[]`, the navigate seam becomes a kind-keyed registry in `lib/objectRef.ts` with proper unregistration, the three hand-rolled dispatchers collapse into multi-kind `ObjectRoute` elements, and the relay TTL pair is pinned by tests on both sides.
**Architecture:** The seam moves from a single-slot module global in `ObjectRoute.tsx` (three writers, last-mount-wins, no unregistration — a stale-closure leak on unmount) to a `Map<string, NavigateFn>` in `lib/objectRef.ts` keyed by kind: `registerNavigate(kinds, fn)` / `unregisterNavigate(kinds, fn)` (remove only entries still pointing at your own fn) / `getNavigateFor(kind)`. Cross-kind stomping is impossible (a kind belongs to exactly one mounted route); the old global is deleted. `ObjectRoute` matches the active ref against any of `kinds` and hands the matched `kind` to `detail`, so the tabbed routes are `kinds: ['ingress', 'gateway', 'httproute', 'referencegrant']` + a kind-switching `detail` — no dispatcher components.
**Tech Stack:** React 19, TypeScript 5.8, Vitest + RTL; pytest for the backend TTL pin.
**Spec:** `./briefing.md`
**Critic:** skipped (T1, fast-track) — see Self-Review for the fresh-eyes pass
**Depends on:** Change B landed (the generated routes exist; the `ResourceRoute` wrapper passes `kinds={[spec.kind]}` and is updated in Task 1).

## Hypothesis

**Claim:** A kind-keyed navigate registry + `kinds: string[]` on `ObjectRoute` expresses the three multi-kind routes with zero duplicated seam logic and no behaviour change.
**Right condition:** the three dispatcher components deleted; one `ObjectRoute` per multi-kind route; the seam registry keyed (no single-slot global anywhere — grep-provable); object-navigation e2e green.
**Wrong condition:** a multi-kind route needs behaviour the `detail(params)` switch cannot express (e.g. per-kind list rendering — the tabbed lists render ONE list component regardless of kind, so this is expected not to happen), or the relay/redirect behaviour drifts.
**Thinnest MVP:** the seam registry + prop change + one converted route (network-policy — the `kindFromParam` case, the hardest).
**Door check:** Task 1.

## Terms

- Object navigation, object ref, relay — ADR-0040 vocabulary; no new terms

## Must-Haves (goal-backward verification)

**Truths:**
- `ObjectRoute` renders the detail iff the active ref's kind ∈ `kinds`; `detail` receives the matched `kind` (for a single-kind route, that kind)
- exactly one `ObjectRoute` element per multi-kind route; `NetworkPolicyRoute`/`IngressRoute`/`IngressClassRoute` no longer exist
- the navigate registry is kind-keyed: registering for `['a']` then `['b']` leaves `getNavigateFor('a')` intact; unmount removes only the fn that was registered (a second component mounting for the same kind replaces, then its unmount restores nothing — last-mounted-wins **per kind** is the contract)
- unmount unregisters: after the route unmounts, `getNavigateFor(kind)` no longer returns its (stale) fn
- frontend `RELAY_TTL_MS === 60_000` and backend `STASH_TTL_SECONDS === 60` — each pinned by a test that names the counterpart constant (the cross-boundary invariant is test-enforced)
- no behaviour change: ref-driven detail, relay consumption, legacy redirects, `origin: 'link'` hydration — e2e object-navigation green

**Artifacts:**
- `frontend/src/lib/objectRef.ts` — the kind-keyed registry (`registerNavigate`/`unregisterNavigate`/`getNavigateFor` + `NavigateFn` type home)
- `frontend/src/components/ObjectRoute.tsx` — `kinds: string[]` prop, kind-matched `detail`, register/unregister lifecycle; the single-slot global deleted
- `frontend/src/App.tsx` — three multi-kind `ObjectRoute` elements; the three dispatchers deleted
- `frontend/src/components/ResourceRoute.tsx` (from B) — passes `kinds={[spec.kind]}`
- `frontend/tests/components/object_route.test.tsx` — rewritten for `kinds` + the keyed registry (incl. the unmount-unregister case)
- `frontend/tests/lib/objectRef.test.ts` — registry tests + the pinned `RELAY_TTL_MS`
- `backend/tests/core/test_object_handoff.py` (or the file hosting the existing `object_handoff` tests — the named source: wherever `STASH_TTL_SECONDS` is imported by tests) — pinned `STASH_TTL_SECONDS == 60`

**Key links:**
- `ObjectRoute`'s register (mount) / unregister (unmount) pair is the ONLY writer of the registry; `OldDataRedirect` needs no seam (it `<Navigate>`s directly — verified 2026-11-07: it does not read the registry; the seam's production readers are none, the registry exists for the redirect-path seam's future + test observability)
- the `detail` switch in the three converted routes is the ONLY per-kind branch left in navigation
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
- `frontend/src/App.tsx` — the three converted route blocks
- `frontend/tests/components/object_route.test.tsx`, `frontend/tests/lib/objectRef.test.ts`
- `backend/tests/core/test_object_handoff.py` — the backend pin

---

### Task 1: Kind-keyed registry + `kinds: string[]` (the breaking prop) + call-site migration

**Files:**
- Modify: `frontend/src/lib/objectRef.ts` (registry in), `frontend/src/components/ObjectRoute.tsx` (prop + lifecycle + global out), `frontend/src/App.tsx` (the 17 single-kind `ObjectRoute` call sites + the 3 dispatchers' registrations adapt to the new signatures — behaviour unchanged, they keep their own registration until Task 2 deletes them), `frontend/src/components/ResourceRoute.tsx` (`kinds={[spec.kind]}`), `frontend/tests/components/object_route.test.tsx`
- Test: `frontend/tests/lib/objectRef.test.ts` (registry semantics, failing first)

**Interfaces:**
- Produces: `NavigateFn = (path: string) => void`; `registerNavigate(kinds: string[], fn: NavigateFn): void`; `unregisterNavigate(kinds: string[], fn: NavigateFn): void` (removes an entry only if it still equals `fn`); `getNavigateFor(kind: string): NavigateFn | null`; `ObjectRouteProps { kinds: string[]; listRoute: string; list: ReactNode; detail: (params: { name: string; namespace?: string; kind: string }) => ReactNode }`
- Consumes: B's `ResourceRoute` + generated routes
- Seam: `lib/objectRef.ts` is router-free (stores callables) — the seam's interface is the three functions
- Deletion test: deleting the registry re-creates the single-slot global + the last-mount-wins ambiguity across the 4 writers
- Adapters: 2 — the mounted `ObjectRoute` (prod) + the test registry assertions

**SATISFIES:** `keyed-seam`

- [ ] **Step 1: Failing tests.** `objectRef.test.ts`: register `['a'],f1` + `['b'],f2` → `getNavigateFor('a')===f1` (no cross-kind clobber); `unregisterNavigate(['a'],f1)` → `getNavigateFor('a')===null`, `['b']` intact; unregister with a different fn is a no-op (guard against unmount-after-replace). `object_route.test.tsx`: `kinds: ['x']` renders detail for a ref of kind `x`, list otherwise; `detail` receives `kind: 'x'`; after unmount `getNavigateFor('x')` is null; the old `getRegisteredNavigate` import is gone from the test. Run `corepack pnpm vitest run tests/lib/objectRef.test.ts tests/components/object_route.test.tsx` → FAIL.
- [ ] **Step 2: Implement the registry** in `objectRef.ts` (`Map<string, NavigateFn>` + the three functions); move `NavigateFn` there.
- [ ] **Step 3: `ObjectRoute` — `kinds: string[]`, kind-matched `detail`, register on mount / unregister on unmount; delete the single-slot global + `getRegisteredNavigate`.**
- [ ] **Step 4: Migrate call sites.** `App.tsx`: every `<ObjectRoute kind="k"` → `kinds={["k"]}`; the 3 dispatchers call `registerNavigate([their kinds], fn)` (and the effect gains the matching cleanup — the stale-closure leak is fixed even for them); `ResourceRoute` → `kinds={[spec.kind]}`.
- [ ] **Step 5: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `refactor: kind-keyed navigate registry + ObjectRoute kinds (breaking prop, all call sites migrated)`

### Task 2: Delete the three dispatchers — multi-kind `ObjectRoute` elements

**Files:**
- Modify: `frontend/src/App.tsx` (the 3 route blocks → single `ObjectRoute` elements; the 3 dispatcher components deleted)
- Test: `frontend/tests/` (any test importing the dispatchers — `grep -rln "NetworkPolicyRoute\|IngressRoute\b\|IngressClassRoute" tests/`)

**Interfaces:**
- Consumes: Task 1's `kinds` + kind-switching `detail`
- Produces: the finished navigation surface

**SATISFIES:** `dispatchers-collapsed`

- [ ] **Step 1: Convert.** `/security/network-policy` → `<ObjectRoute kinds={['NetworkPolicy','CiliumNetworkPolicy','CiliumClusterwideNetworkPolicy']} listRoute=… list={<NetworkPolicyView/>} detail={(p) => <NetworkPolicyDataView name={p.name} kind={p.kind} namespace={p.namespace ?? ''} />} />` (the `kindFromParam` legacy redirect is untouched — it's `OldDataRedirect`'s business). `/network/ingress` → `kinds={['ingress','gateway','httproute','referencegrant']}`, `detail={(p) => p.kind === 'ingress' ? <IngressDataView name={p.name} namespace={p.namespace ?? ''}/> : <GatewayApiDataView name={p.name} kind={p.kind} namespace={p.namespace ?? ''}/>}`. `/network/ingress-class` → `kinds={['ingressclass','gatewayclass']}`, `detail={(p) => p.kind === 'ingressclass' ? <IngressClassDataView name={p.name}/> : <GatewayClassDataView name={p.name}/>}`. Delete `NetworkPolicyRoute`/`IngressRoute`/`IngressClassRoute` + their `registerNavigate`/`sweepRelay`/bump machinery (~135 lines of duplicated seam logic).
- [ ] **Step 2: Regression tests.** For each converted route: the list renders once (tabbed list, no per-kind duplication), a ref of each kind renders the right detail, a ref of a foreign kind renders the list. (The `object_route.test.tsx` patterns from Task 1, at the route level via the App render or the route elements directly.)
- [ ] **Step 3: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `refactor: three multi-kind routes on ObjectRoute kinds (dispatchers deleted)`

### Task 3: Pinned relay-TTL tests, both sides

**Files:**
- Modify: `frontend/tests/lib/objectRef.test.ts` (the frontend pin), `backend/tests/core/test_object_handoff.py` (the backend pin — the file that hosts `object_handoff`'s tests; locate via `grep -rln "object_handoff" backend/tests/`)
- Test: both files

**Interfaces:** Consumes: `RELAY_TTL_MS` (`frontend/src/lib/objectRef.ts`), `STASH_TTL_SECONDS` (`backend/app/core/object_handoff.py:39`)
**SATISFIES:** `ttl-pinned`
- [ ] **Step 1: Frontend pin.** `test('relay TTL is pinned to the backend stash TTL', () => { expect(RELAY_TTL_MS).toBe(60_000) })` — comment: `// backend/app/core/object_handoff.py STASH_TTL_SECONDS — change both together (ADR-0040 R4 handoff window)`.
- [ ] **Step 2: Backend pin.** `def test_stash_ttl_pinned_to_frontend_relay_ttl(): assert STASH_TTL_SECONDS == 60` — comment: `# frontend/src/lib/objectRef.ts RELAY_TTL_MS — change both together (ADR-0040 R4 handoff window)`.
- [ ] **Step 3: Run + commit.** `corepack pnpm test && uv run pytest tests/core/test_object_handoff.py -v` → `test: pin the relay TTL pair on both sides of the boundary`

### Task 4: Green + e2e backstop

**Files:** none (verification only)
**SATISFIES:** `seam-green`
- [ ] **Step 1: Full floor.** `corepack pnpm test` + `task fe-build` + `task fe-check` + `uv run pytest -m "not integration"`.
- [ ] **Step 2: e2e backstop.** `task e2e` — the object-navigation flows (open, relay share, legacy redirect) green.
- [ ] **Step 3: Prove the global is gone.** `grep -rn "registeredNavigate\|getRegisteredNavigate" frontend/src` → zero hits. Record in the commit body.
- [ ] **Step 4: Commit** (if Step 3's proof changed nothing, fold into the Task 3 commit; otherwise `chore: seam proof — single-slot global gone`).

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Task 1; R2 → Task 1 (registry in `objectRef.ts`, global deleted); R3 → Task 2; R4 → Task 3; R5 → Task 4. No gaps.
2. **Must-haves coverage:** every truth maps to a task step; the registry contract (per-kind last-write-wins, unmount-unregister, replace-guard) is fully specified in Task 1 Step 1's tests.
3. **One-way-door completeness:** the breaking prop is internal (all call sites in-change) — correctly not flagged.
4. **Placeholder scan:** the backend test file is named by the exact grep that locates it (a step, not a TBD); all kind arrays are exhaustive from the current dispatchers.
5. **Type consistency:** `NavigateFn`, `registerNavigate`/`unregisterNavigate`/`getNavigateFor`, `ObjectRouteProps` used identically across tasks and tests.
6. **Critic skipped:** T1 + fast-track (small, internal, no one-way door) — recorded in the header per the skill.
