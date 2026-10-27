# Session-Style Namespace Selection — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution
> (recommended) or skillgrid:simple-execution to implement this plan
> task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** EXECUTED (2026-10-27) — Task 1 steps 1–2, 6 done and verified;
steps 3–5 (manual browser matrix) deferred to the acceptance pass.

**Tier:** T1 (from `briefing.md`).

**Build shape:** Single store change + one test file. No tracer thread —
the change is one seam (the store's persistence layer) with an existing
consumer (`AppHeader.jsx`) that already behaves correctly against it.

**Class:** standard (verification floor L2: `task fe-build` +
`corepack pnpm test` + `task fe-check`). No backend suite — no backend
change. No kind-gated integration test.

**Goal:** Make the header `ns_select` choice survive a page reload by
persisting `selectedCluster` + `selectedNamespace` to `localStorage`
via `zustand/middleware` `persist` — the client-side stand-in for 4.1's
`session['ns_select']`.

**Architecture:** Wrap the existing `useClusterStore` in `persist`.
`partialize` exposes exactly the two data fields; actions are not
persisted. Storage key `kd-cluster-scope`. Rehydration is synchronous
`localStorage` (the default `createJSONStorage(() => localStorage)`),
so the store is populated before first render — no async flash, no
hydration race in the header. All ~10 read views and `AppHeader.jsx` are
untouched: they read the store, which now simply survives reload.

**Tech Stack:** React 18, Zustand (already a dependency;
`zustand/middleware` is part of the same package — no new dependency,
ADR-0020 air-gap safe). Vitest + RTL for the test (existing setup).

**Spec:** `briefing.md` (requirements R1–R3).

**In-force ADRs:** ADR-0020 (air gap — `persist` adds no external
fetch/CDN), ADR-0025 (session delivery — unchanged; this is UI-scope
state, not auth state). No ADR is opened, amended, or superseded.

**Decision notes:**

- **Per-cluster scope** (user decision, 2026-10-27): the persisted shape
  is `{ selectedCluster, selectedNamespace }` together — the namespace
  is only meaningful relative to the cluster it was selected on. The
  header's existing draft-reset on cluster switch (`AppHeader.jsx:83-87`)
  composes with this: switching clusters clears the draft, and the
  rehydrated ns is re-validated against the new cluster's list by the
  existing `preferredNamespace` fallback chain.
- **Store persists raw values; the header validates.** The store does
  NOT know a namespace list (it has no cluster data), so a stale persisted
  ns is resolved by the header's fallback chain (`selectedNamespace` →
  `default` → first entry), not by store-side cleanup. Keeping validation
  where the data lives (the header already fetches the ns list via
  TanStack Query) avoids a circular dependency between store and queries.
- **No server round-trip.** Deliberate deferral (briefing.md, Intent 1):
  if cross-device per-user defaults are needed later, the `persist`
  storage option is the swap point for a server-backed implementation.

## Hypothesis

**Claim:** Wrapping `useClusterStore` in `persist` with
`partialize: (s) => ({ selectedCluster: s.selectedCluster,
selectedNamespace: s.selectedNamespace })` makes the header selection
survive reload with zero changes to `AppHeader.jsx` or any read view.

**Right condition:** select cluster + ns, reload, the header renders on
the same cluster with the same ns selected; a stale ns falls back via the
existing chain.

**Wrong condition:** rehydrated state causes a visible flash of the
fallback value before the persisted value applies (proof the sync
`localStorage` storage is not actually synchronous for this store shape),
OR a read view renders against the persisted cluster before
`useCluster()` has re-validated it (proof the store and the query layer
race on boot).

**Thinnest MVP:** Task 1 (persist wrapper + store test).

**Door check:** none — `zustand/middleware` `persist` with
`createJSONStorage(() => localStorage)` is the library's documented
default pattern; no unproven contract.

## Tasks

### Task 1 — Persist the cluster-scope store

**File(s):** `frontend/src/store/cluster.ts`,
`frontend/tests/store/cluster.test.ts` (create if absent).

- [x] **Step 1 — Red (store test).** Add a test file (or extend the
      existing store test, if one exists) with:
      1. `setSelectedCluster` + `setSelectedNamespace`, then clear the
         module registry / re-import the store, assert both values are
         back from `localStorage` under key `kd-cluster-scope`.
      2. `localStorage` contains a corrupted entry (`'not-json'`) before
         first import: the store rehydrates to its empty initial state
         (`selectedCluster: null, selectedNamespace: null`), no throw.
      3. Only the two data fields land in `localStorage` — assert the
         stored JSON has no `setSelectedCluster` / `setSelectedNamespace`
         keys (`partialize` holds).
      4. Persisted `selectedNamespace: null` round-trips as `null`
         (the Namespaces-delete path), not as `"null"` or absent.
      Run: `corepack pnpm test -- cluster` — fails (store is not
      persisted yet; step 1.1 sees `null`).
- [x] **Step 2 — Green.** In `cluster.ts`, import
      `{ persist, createJSONStorage }` from `zustand/middleware`, wrap
      the existing `create<ClusterStore>()(...)` initializer:
      ```ts
      export const useClusterStore = create<ClusterStore>()(
        persist(
          (set) => ({ /* existing state + actions, verbatim */ }),
          {
            name: 'kd-cluster-scope',
            storage: createJSONStorage(() => localStorage),
            partialize: (s) => ({
              selectedCluster: s.selectedCluster,
              selectedNamespace: s.selectedNamespace,
            }),
          },
        ),
      )
      ```
      Update the file's doc comment to note the persistence (storage
      key, what persists, that the header owns ns validation). Keep the
      `SelectedCluster` interface and the `ClusterStore` interface
      unchanged — persistence is an implementation detail of the store,
      not part of its type.
- [ ] **Step 3 — Verify store behavior in the browser.** `task fe-dev`,
      then manually: pick cluster + ns in the header → hard reload →
      header is on the same cluster/ns. Check
      `localStorage['kd-cluster-scope']` in devtools: exactly the two
      fields. Repeat with a second namespace. Repeat after switching
      clusters.
- [ ] **Step 4 — Stale-ns fallback.** In a cluster whose namespace list
      lacks the persisted ns (temporarily edit the stored value in
      devtools to a name that doesn't exist, reload): the select shows
      `default` (or the first ns), not the stale name; no console error.
      Restore the value.
- [ ] **Step 5 — Clear-ns path.** On the Namespaces page, delete the
      currently selected namespace: the store goes to `null`, the
      select falls back, and `localStorage` now holds
      `selectedNamespace: null`.
- [x] **Step 6 — Full verification floor.** `task fe-build`
      (typecheck + lint + build), `corepack pnpm test` (whole frontend
      suite), `task fe-check` (air-gap — `persist` must not introduce
      any external reference into the bundle). All green.
- [x] **Step 7 — Commit.** Conventional commit, atomic:
      `feat(store): persist cluster + namespace selection (4.1 ns_select parity)`.

## Verification (whole change)

| Check | Command | Expected |
|---|---|---|
| Store unit tests | `cd frontend && corepack pnpm test -- cluster` | all pass |
| Frontend typecheck + lint + build | `task fe-build` | green |
| Full frontend suite | `cd frontend && corepack pnpm test` | green |
| Air-gap bundle | `task fe-check` | no `https?://` or `//cdn.` refs |
| Manual reload matrix | `task fe-dev` + browser | acceptance 1–5 in `briefing.md` (deferred to acceptance pass) |

**Not verified here (and why):** cross-device persistence (deferred —
briefing.md Intent 1); server-side per-user defaults (Option B, deferred);
backend (no backend change).

## Rollback

One commit, one file + one test file. `git revert` restores the
in-memory-only store; the `localStorage` entry is inert (no reader).
No data migration: the stored JSON is orphaned, not corrupting.
