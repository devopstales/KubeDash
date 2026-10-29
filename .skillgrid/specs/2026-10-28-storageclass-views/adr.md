# StorageClass Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `storageclasses`, core group (`""`), namespace `None` (cluster-scoped); the SAR is asked BEFORE the client call; 403 names the denied resource. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as nodes/priorityclasses/runtimeclasses for a cluster-scoped core kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `StorageV1Api` (the 4.1 code used it; one new attribute `self._storage` in the 5.0 client); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by PriorityClassData/SecretData). |
| ADR-0022 (other-resources placement) | The view lives under Storage (the 4.1 `storage` blueprint grouping) — the ratified nav-placement deviation. The nav leaf already exists at this path, and 4.1's own template lived in `storage/`. (ADR-0022's "other-resources" clause is for 4.1's `other-resources` API grouping; Storage is the analogous placement for 4.1's `storage` grouping.) |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (Nodes / PriorityClass / RuntimeClass = the same cluster-scoped core-
kind family, same `_KINDS` + `_GETTERS` wiring, same list+data view pair).

## Recorded deviations from 4.1

- **`?name=` navigation, not 4.1's hidden form + `session['ns_select']`.**
  4.1's list page POSTed a hidden form per row (`sc_name`) and the data page
  re-listed the whole cluster then filtered in Python (`for sc in
  storage_classes: if sc["name"] == sc_name`). 5.0 reaches the data page by
  query param and does a single `?name=` read (the PriorityClassData contract
  — the kind is cluster-scoped, so NO `namespace` param).
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data pages
  render `JSON.stringify` of the `to_dict` item — JSON is a YAML subset, and
  the `json` grammar is the truthful classifier for the exact text rendered
  (ratified rule, PriorityClassData final review 2026-10-28).
- **The data "Binding Mode" label is rendered as `Volume Binding Mode`.**
  4.1's list page header is `Volume Binding Mode` but its data page row label
  is the shorter `Binding Mode` for the same `volume_binding_mode` field. 5.0
  keeps the list header verbatim (`Volume Binding Mode`) on both pages for
  consistency. (Cosmetic — the value is the same field.)
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
