# Session-Style Namespace Selection — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-27-ns-select-persist`
**Date:** 2026-10-27

**Tier:** T1 — single-file frontend store change + one test file. No
backend, no migration, no new dependency (`zustand` is already in use;
`zustand/middleware` ships with it).

## Intent

Make the header namespace selector (`ns_select`, the 4.1-mirroring form in
`AppHeader.jsx`) behave like 4.1's session-scoped `session['ns_select']` did
for the user: the choice **sticks across page reloads**. Today the selection
lives only in the in-memory Zustand store (`frontend/src/store/cluster.ts`)
and is lost on reload; the header comment at `store/cluster.ts:16` already
declares the intent ("matching 4.1's session `ns_select`") — this change
closes that gap.

Scope decisions (ratified in planning, 2026-10-27):

1. **Client-side persistence, not server state.** This codebase's auth is
   JWT + HttpOnly cookies (ADR-0025); there is no Flask server-side session.
   A per-user, cross-device default-namespace endpoint (the heavier Option B)
   is deliberately deferred — if needed later, the store's persistence layer
   is the seam where a server-backed implementation swaps in.
2. **Per-cluster, not global.** The namespace list is per-cluster and the
   header already resets its draft on cluster switch; a single global
   selection would be wrong the moment a user has two clusters with
   disjoint namespace sets. Persisted state is the last-viewed cluster plus
   that cluster's selected namespace.
3. **Both `selectedCluster` and `selectedNamespace` persist.** Persisting
   the cluster is what makes the persisted namespace meaningful on rehydrate
   (the ns must be rehydrated into the correct cluster's context), and it
   restores the last-viewed cluster on reload — standard 4.1 behavior.

## Reference

- 4.1 (pre-rewrite, session + Jinja): `session['ns_select']` in
  `4.1:src/kubedash/blueprint/security/security.py` and the header partial
  `4.1:src/kubedash/templates/partials/header.html.j2` — the select + Submit
  wrote the choice into the WSGI session; every subsequent page read it.
  The behavioral contract being mirrored: **the choice survives a reload and
  scopes the read pages**.
- Current code (the seam): `frontend/src/store/cluster.ts` — `selectedCluster`
  + `selectedNamespace` in `useClusterStore` (Zustand, no persistence today).
- Current consumer: `frontend/src/components/AppHeader.jsx:75-112` — draft
  state, `preferredNamespace` fallback chain, Submit → `setSelectedNamespace`.
- ~10 read views consume `selectedNamespace` (e.g. `Secret.tsx`,
  `RoleBinding.tsx`, `CrdData.tsx`, `Namespaces.tsx`) — none change in this
  build; they keep reading the store.

Deliberately NOT carried over from 4.1:

- server-side session storage — replaced by `localStorage` (see Intent 1);
- per-request `ns_select` form encoding — the SPA already applies the choice
  on Submit via the store, no change.

## Requirements

### R1 — Persisted store

`useClusterStore` (`frontend/src/store/cluster.ts`) is wrapped in
`persist` from `zustand/middleware`:

- Storage key: `kd-cluster-scope`.
- `partialize` covers `selectedCluster` and `selectedNamespace` (both).
  Nothing else is persisted; `setSelected*` actions are not part of the
  persisted shape.
- Rehydrate silently: on load, the store repopulates from
  `localStorage` before any component reads it (standard `persist`
  behavior).

### R2 — Rehydrate semantics

- If the persisted `selectedNamespace` still exists in the rehydrated
  cluster's namespace list, the header shows it (no user action).
- If it does not exist (namespace deleted, RBAC changed, or the persisted
  cluster changed under the user), the header's existing
  `preferredNamespace` fallback chain (`selectedNamespace` → `default` →
  first list entry) applies — the store persists the raw value, the header
  owns validation. No new fallback logic is added.
- `selectedNamespace: null` (e.g. `Namespaces.tsx` clearing it after a
  namespace delete) persists as `null` and the fallback chain applies on
  next load. This is correct behavior, not a bug.
- A corrupted/undecodable `localStorage` entry yields the empty initial
  state (standard `persist` behavior); nothing crashes.

### R3 — No consumer changes

`AppHeader.jsx` and all read views are untouched. The header's existing
draft-on-cluster-switch behavior (lines 83-87) already composes with the
persisted state: switching clusters resets the draft and the persisted ns
is re-validated against the new cluster's list by the fallback chain.

## Acceptance

1. Select cluster A + namespace `team-a` in the header, reload the page:
   the header is on cluster A with the namespace select showing `team-a`.
2. Select a second namespace and reload: the new value is restored.
3. Switch to cluster B (different namespace set), submit a namespace there,
   reload: cluster B and its namespace are restored; switching back to
   cluster A restores cluster A's persisted namespace.
4. Delete the selected namespace from the Namespaces page (store sets
   `null`), reload: the select shows the fallback (`default` or first),
   not a stale value.
5. `localStorage` removed (or empty profile), reload: header behaves as
   today (fallback chain, no crash).
6. `task fe-build` (typecheck + lint + build) and `pnpm test` pass.
