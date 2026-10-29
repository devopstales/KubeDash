# SnapshotClass Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-snapshotclass-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `SnapshotClass` leaf
(`/storage/snapshot-class`, `_nav.tsx:104`) that currently renders the
placeholder stub (`views/Stub/routes.ts:22`). **4.1 has real templates for
this kind**: `storage/snapshot-class.html.j2` (list: Name / Default / Deletion
Policy / Driver) and `snapshot-class-data.html.j2` (data: Name / Created /
Annotations / Labels / Deletion Policy / Driver / a Parameters table). Unlike
the core-API kinds, **SnapshotClass is a CRD**
(`volumesnapshotclasses.snapshot.storage.k8s.io`, group
`snapshot.storage.k8s.io`, **cluster-scoped**); the 4.1 read is
`k8sSnapshotClassListGet` (`4.1:src/kubedash/lib/k8s/storage.py:46`):
`CustomObjectsApi().list_cluster_custom_object("snapshot.storage.k8s.io", "v1",
"volumesnapshotclasses")` — a hardcoded `v1` (no runtime version resolution,
unlike VPAs). The data page is the 4.1 list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` query param (no `?namespace=` — the kind is
  cluster-scoped) — no 4.1 hidden forms / POST / `session['ns_select']`
  (the Namespaces/Nodes/CRDs/ResourceQuota decision).
- **Read seam:** the **Cilium precedent** — a CRD kind read as a FULL custom
  object (spec/status intact, camelCase), with the CRD's OWN served version +
  scope as the authority (an improvement over 4.1's hardcoded `v1`) and
  **CRD-absent degrades to `[]`** (the snapshot operator is optional; a
  cluster without it is a first-class empty state, not an error). Not the
  lossy `list_crd_instances` projection (which drops `driver`/
  `deletionPolicy`/`parameters`).
- **Detail rendering:** the data page keeps 4.1's curated tables (metadata,
  deletion policy, driver, parameters) and ADDS the full-object
  `JSON.stringify(item, null, 2)` block with the `json` hljs grammar (the
  truthful-classifier rule ratified for PriorityClassData, final review
  2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `volumesnapshotclasses`, group `snapshot.storage.k8s.io`,
  namespace `None` (cluster-scoped).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/storage/snapshot-class` and `/storage/snapshot-class/data`, removing the
stub, so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated SnapshotClass list endpoint

`GET /api/v1/clusters/<id>/resources/volumesnapshotclasses` MUST return the
VolumeSnapshotClass list (`kind: "volumesnapshotclasses"`, items as FULL
custom objects — the raw `to_dict` with `metadata`/`driver`/`deletionPolicy`/
`parameters` intact, camelCase, NOT the lossy `CrdInstance` projection). The
CRD's OWN served version + scope is the authority (the `get_crd_served`
pattern). The kind is **cluster-scoped**: a `namespace` param is accepted and
ignored (the `list_runtime_classes` pattern). The read is SAR-gated per
ADR-0004: `list` on `volumesnapshotclasses`, group `snapshot.storage.k8s.io`,
namespace `None`; on deny the response is 403 `RBAC_DENIED` naming the
resource, and the SAR is asked BEFORE any K8s client call. An unbound user is
404 from the binding gate. When the CRD is **absent** (snapshot operator not
installed) the list MUST be `[]` — a first-class empty state, not an error
(the Cilium absence contract). The kind identifier is the plural
`volumesnapshotclasses`; the singular `volumesnapshotclass` is rejected with
`RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/volumesnapshotclasses?name=<name>` MUST
return a 0/1-item list through the same generic route (`_GETTERS`): a hit is
the single full object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` with namespace `None` (cluster-scoped).
CRD-absent is also `[]`. The `?name=` branch's `namespace = "default"`
fallback is irrelevant (the read ignores namespace). No new HTTP route is
added: the kind is wired through `_KINDS` + `_GETTERS` only.

### R3 — The list page

`/storage/snapshot-class` MUST render a `KubeDataTable` of the cluster's
VolumeSnapshotClasses (cluster-scoped — no namespace selector applies) with
columns **Name / Default / Deletion Policy / Driver**. The card title is
EXACTLY `Snapshot Classes List` (4.1's title, kept verbatim — the e2e-smoke
contract). The Name cell links to
`/storage/snapshot-class/data?name=<name>` — the list view is the sole
producer of those query strings (cluster-scoped: NO `namespace` param).

- **Default** = the `snapshot.storage.kubernetes.io/is-default-class`
  annotation value (`—` when absent).
- **Deletion Policy** = `deletionPolicy` (`—` when absent).
- **Driver** = `driver` (`—` when absent).

States: no cluster selected → `No cluster selected.`; loading → `Loading
snapshot classes...`; error → red error line; empty list → `No snapshot
classes found` (first-class, not an error — this is ALSO the CRD-absent
state; the page does not distinguish "CRD absent" from "no snapshot classes"
in the empty state, both render the same copy).

### R4 — The detail page

`/storage/snapshot-class/data?name=<name>` MUST fetch the object with a
**single `?name=` request** (not 4.1's list-then-filter). Empty `items` is a
not-found **STATE** — pinned copy `No VolumeSnapshotClass '<name>' found`,
muted, not an error. The page renders:

- A CTable (Name / Created / Deletion Policy / Driver / Labels / Annotations):
  - **Deletion Policy** = `deletionPolicy` (`—` when absent), **Driver** =
    `driver` (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creationTimestamp`.
- A **Parameters** table (a key/value CTable, `No parameters` when absent),
  one row per `parameters` entry (4.1's dynamic-key Parameters card — the
  `parameters` field is a `map[string]string`).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: snapshot class name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/storage/snapshot-class` is removed from `views/Stub/routes.ts`. The
`_nav.tsx` leaf is UNCHANGED (path and label). The data route is not a nav
entry (same as priorityclass/data, network-policy/data).

## Non-goals

- No create/edit/delete for VolumeSnapshotClasses (read-only, as in 4.1 and as
  in every other 5.0 resource view to date).
- No `VolumeSnapshot` / `VolumeSnapshotContent` views — those are separate nav
  leaves (`/storage/volumesnapshot`) and out of scope for this change.
- No all-namespaces LIST mode on the page (the kind is cluster-scoped; there
  is only one list).
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Snapshot Classes List` is the only smoke-relevant contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` query-param navigation; no 4.1 hidden form / POST /
   `session['ns_select']`; no list-then-filter on the data page. The kind is
   cluster-scoped, so there is NO `?namespace=` param (unlike the namespaced
   kinds).
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. The read is a **FULL custom object** (driver/deletionPolicy/parameters/
   metadata intact, camelCase) via the Cilium precedent, not the lossy
   `list_crd_instances` projection — the SnapshotClass pages need
   `deletionPolicy`, `driver`, and `parameters`, which the projection drops.
4. The CRD version is resolved via `get_crd_served` (the CRD's OWN served
   version as authority), not 4.1's hardcoded `"v1"`.
5. **CRD-absent degrades to `[]`, not an error.** 4.1's `k8sSnapshotClassListGet`
   swallows the `ApiException` and returns `[]` — the snapshot operator is
   optional, so a cluster without it is a first-class empty state. 5.0 keeps
   this via the Cilium `get_crd_served` contract: CRD 404 → `served is None`
   → `[]`; any other read failure → `ClusterUnreachableError` (502).
6. 4.1's `trimAnnotations` is NOT replicated — annotations render verbatim;
   the JSON block is the same, and 5.0 has no 4.1 trim helper.
