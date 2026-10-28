# VolumeSnapshot Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-volumesnapshot-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `VolumeSnapshot` leaf
(`/storage/volumesnapshot`, `_nav.tsx:102`) that currently renders the
placeholder stub (`views/Stub/routes.ts:23`). **4.1 has a real LIST template
for this kind but NO data template**: `storage/volumesnapshot.html.j2`
(list: Usable / Name / SnapshotClass / VolumeClaim / RestorSize) — the data
link is **commented out** (a dead link; 4.1 has no `/volumesnapshot/data`
route). Unlike SnapshotClass, **VolumeSnapshot is a CRD**
(`volumesnapshots.snapshot.storage.k8s.io`, group `snapshot.storage.k8s.io`,
**namespaced**); the 4.1 read is `k8sPersistentVolumeSnapshotListGet`
(`4.1:src/kubedash/lib/k8s/storage.py:162`):
`CustomObjectsApi().list_cluster_custom_object("snapshot.storage.k8s.io", "v1",
"volumesnapshots")` — a hardcoded `v1` AND a hardcoded **all-namespaces**
read (the 4.1 list ignored the header-selected namespace, showing snapshots
from every namespace). The list deep-indexes `spec.source
.persistentVolumeClaimName` and `spec.volumeSnapshotClassName` — both 500 on a
SourceMode-less snapshot (a latent 4.1 bug).

Port the 4.1 LIST shape to 5.0 with the ratified deltas, and **ADD a 5.0 data
page** (4.1 had none — the dead link is resolved by a real
`?name=&namespace=` detail):

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store,
  as in the NetworkPolicies and ResourceQuota views (a fix for 4.1's
  all-namespaces list).
- **Read seam:** the **Cilium precedent** — a CRD kind read as a FULL custom
  object (spec/status intact, camelCase), with the CRD's OWN served version +
  scope as the authority (an improvement over 4.1's hardcoded `v1` AND a
  fix for 4.1's hardcoded all-namespaces read — 5.0 honors the header
  namespace per the CRD's scope), and **CRD-absent degrades to `[]`** (the
  snapshot operator is optional; a cluster without it is a first-class empty
  state, not an error). Not the lossy `list_crd_instances` projection (which
  drops `spec`/`status`).
- **Detail rendering:** the 5.0 data page (new — 4.1 had none) renders
  4.1's list columns as a CTable (Source / SnapshotClass / Ready To Use /
  Restore Size / Bound Content) + labels/annotations sub-tables + the
  full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
  grammar (the truthful-classifier rule ratified for PriorityClassData, final
  review 2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `volumesnapshots`, group `snapshot.storage.k8s.io`,
  namespace from the query (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/storage/volumesnapshot` and `/storage/volumesnapshot/data`, removing the
stub, so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated VolumeSnapshot list endpoint

`GET /api/v1/clusters/<id>/resources/volumesnapshots?namespace=<ns>` MUST
return the VolumeSnapshot list for that namespace (`kind: "volumesnapshots"`,
items as FULL custom objects — the raw `to_dict` with `metadata`/`spec`/
`status` intact, camelCase, NOT the lossy `CrdInstance` projection). The CRD's
OWN served version + scope is the authority (the `get_crd_served` pattern);
when the CRD is namespaced-scoped, `namespace` selects the namespace; when
cluster-scoped (a future CRD revision), `namespace` is accepted and ignored.
Without a `namespace` param the list spans all namespaces
(`list_cluster_custom_object` — the all-namespaces branch). The read is
SAR-gated per ADR-0004: `list` on `volumesnapshots`, group
`snapshot.storage.k8s.io`, namespace = the query namespace or `None`; on deny
the response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked
BEFORE any K8s client call. An unbound user is 404 from the binding gate.
When the CRD is **absent** (snapshot operator not installed) the list MUST be
`[]` — a first-class empty state, not an error (the Cilium absence contract).
The kind identifier is the plural `volumesnapshots`; the singular
`volumesnapshot` is rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/volumesnapshots?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single full object, a miss is `[]` (not a 404 — the data page
renders a not-found state). SAR-gated on `get` with the same namespace
semantics. CRD-absent is also `[]`. The namespace param is REQUIRED for the
lookup: without it the route falls back to `namespace = "default"` (the
generic route's existing `name` branch behavior) — the data page ALWAYS sends
the namespace it was linked with. No new HTTP route is added: the kind is
wired through `_KINDS` + `_GETTERS` only.

### R3 — The list page

`/storage/volumesnapshot` MUST render a `KubeDataTable` in the header-selected
namespace (`useClusterStore.selectedNamespace ?? 'default'`, the NetworkPolicies
pattern — a fix for 4.1's all-namespaces list) with columns **Name / Usable /
SnapshotClass / VolumeClaim / Restore Size**. The card title is EXACTLY
`Volume Snapshot List` (4.1's title, kept verbatim — the e2e-smoke contract).
The Name cell links to
`/storage/volumesnapshot/data?name=<name>&namespace=<ns>` — the list view is
the sole producer of those query strings (a fix for 4.1's commented-out dead
link).

- **Usable** = `status.readyToUse` rendered as a badge (the 4.1 success/danger
  badge pair — `True` → success, otherwise → danger; `—` when absent).
- **SnapshotClass** = `spec.volumeSnapshotClassName` (`—` when absent — 4.1's
  deep-index 500s here on a SourceMode-less snapshot; 5.0 renders `—`).
- **VolumeClaim** = `spec.source.persistentVolumeClaimName` (`—` when absent
  — same deep-index fix).
- **Restore Size** = `status.restoreSize` (`—` when absent).

States: no cluster selected → `No cluster selected.`; loading → `Loading
volume snapshots...`; error → red error line; empty list → `No volume
snapshots found` (first-class, not an error — this is ALSO the CRD-absent
state; the page does not distinguish "CRD absent" from "no snapshots" in the
empty state, both render the same copy).

### R4 — The detail page

`/storage/volumesnapshot/data?name=<name>&namespace=<ns>` MUST fetch the
object with a **single `?name=&namespace=` request** (not 4.1's list-then-
filter — 4.1 had no data page at all). Empty `items` is a not-found **STATE**
— pinned copy `No VolumeSnapshot '<name>' found`, muted, not an error. The
page renders:

- A CTable (Name / Created / Source / SnapshotClass / Ready To Use / Restore
  Size / Bound Content / Labels / Annotations):
  - **Source** = `spec.source.persistentVolumeClaimName` (`—` when absent).
  - **SnapshotClass** = `spec.volumeSnapshotClassName` (`—` when absent).
  - **Ready To Use** = `status.readyToUse` (badge-style: `True` → success,
    otherwise → danger; `—` when absent).
  - **Restore Size** = `status.restoreSize` (`—` when absent).
  - **Bound Content** = `status.boundVolumeSnapshotContentName` (`—` when
    absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creationTimestamp`.
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: volume snapshot name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/storage/volumesnapshot` is removed from `views/Stub/routes.ts`. The
`_nav.tsx` leaf is UNCHANGED (path and label). The data route is not a nav
entry (same as priorityclass/data, network-policy/data).

## Non-goals

- No create/edit/delete for VolumeSnapshots (read-only, as in 4.1 and as in
  every other 5.0 resource view to date).
- No `VolumeSnapshotContent` view — that is a separate CRD
  (`volumesnapshotcontents`) and out of scope for this change.
- No deep-link to the target PVC or SnapshotClass pages — 4.1's list linked
  those cells to `/storage/pvc` and `/storage/snapshot-class` via hidden
  forms; 5.0 has no workload/PVC page destination yet, so those cells render
  as plain text (the full `spec`/`status` is in the JSON block).
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace (a fix for 4.1's all-namespaces list); the
  all-namespaces list branch exists for the API (R1) and future consumers
  only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Volume Snapshot List` is the only smoke-relevant contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`. The data page (new in 5.0) is reached by
   query params — 4.1 had NO data page (the list's name link was commented
   out, a dead link).
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. The list honors the header-selected namespace (a fix for 4.1's hardcoded
   `list_cluster_custom_object` all-namespaces read, which ignored
   `session['ns_select']` and showed snapshots from every namespace).
4. The CRD version is resolved via `get_crd_served` (the CRD's OWN served
   version as authority), not 4.1's hardcoded `"v1"`.
5. The deep-index 500 is fixed: 4.1's `pvs["spec"]["source"]
   ["persistentVolumeClaimName"]` and `pvs["spec"]
   ["volumeSnapshotClassName"]` raise `KeyError` (500) on a SourceMode-less
   snapshot; 5.0 renders `—` for absent keys (certainty rule: never guess,
   never crash the row).
6. **CRD-absent degrades to `[]`, not an error.** 4.1's
   `k8sPersistentVolumeSnapshotListGet` swallows the `ApiException` and
   returns `[]` — the snapshot operator is optional, so a cluster without it
   is a first-class empty state. 5.0 keeps this via the Cilium
   `get_crd_served` contract: CRD 404 → `served is None` → `[]`; any other
   read failure → `ClusterUnreachableError` (502).
7. The SnapshotClass / VolumeClaim cells are plain text, not 4.1's hidden-
   form links to `/storage/snapshot-class` and `/storage/pvc` (5.0 has no
   PVC page destination yet).
8. `trimAnnotations` is NOT replicated — annotations render verbatim; the
   JSON block is the same, and 5.0 has no 4.1 trim helper.
