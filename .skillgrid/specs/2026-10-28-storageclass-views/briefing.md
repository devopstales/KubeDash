# StorageClass Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-storageclass-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `StorageClass` leaf
(`/storage/storage-class`, `_nav.tsx:103`) that currently renders the
placeholder stub (`views/Stub/routes.ts:21`). **4.1 has real templates for
this kind**: `storage/storage-class.html.j2` (list: Name / Default / Reclaim
Policy / Volume Binding Mode) and `storage-class-data.html.j2` (data: Name /
Created / Annotations / Labels / Reclaim Policy / Binding Mode / Provisioner /
a Parameters card). Unlike SnapshotClass, **StorageClass is a core API**
(`storageclasses`, core group, **cluster-scoped**); the 4.1 read is
`k8sStorageClassListGet` (`4.1:src/kubedash/lib/k8s/storage.py:15`):
`StorageV1Api().list_storage_class` — a generated core-API model, so the
`to_dict` form is snake_case. The data page is the 4.1 list-then-filter by
name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` query param (no `?namespace=` — the kind is
  cluster-scoped) — no 4.1 hidden forms / POST / `session['ns_select']`
  (the Namespaces/Nodes/CRDs/ResourceQuota decision).
- **Detail rendering:** the data page keeps 4.1's curated tables (metadata,
  reclaim policy, binding mode, provisioner, parameters) and ADDS the
  full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
  grammar (the truthful-classifier rule ratified for PriorityClassData, final
  review 2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `storageclasses`, core group (`""`), namespace `None`
  (cluster-scoped).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/storage/storage-class` and `/storage/storage-class/data`, removing the stub,
so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated StorageClass list endpoint

`GET /api/v1/clusters/<id>/resources/storageclasses` MUST return the
StorageClass list (`kind: "storageclasses"`, items in kubernetes `to_dict`
snake_case form). The kind is **cluster-scoped**: a `namespace` param is
accepted and ignored (the `list_nodes` / `list_priority_classes` pattern).
The read is SAR-gated per ADR-0004: `list` on `storageclasses`, core group
(`""`), namespace `None`; on deny the response is 403 `RBAC_DENIED` naming the
resource, and the SAR is asked BEFORE any K8s client call. An unbound user is
404 from the binding gate. The kind identifier is the plural
`storageclasses`; the singular `storageclass` is rejected with
`RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/storageclasses?name=<name>` MUST return a
0/1-item list through the same generic route (`_GETTERS`): a hit is the single
object, a miss is `[]` (not a 404 — the data page renders a not-found state).
SAR-gated on `get` with namespace `None` (cluster-scoped). The `?name=`
branch's `namespace = "default"` fallback is irrelevant (the read ignores
namespace). No new HTTP route is added: the kind is wired through `_KINDS` +
`_GETTERS` only.

### R3 — The list page

`/storage/storage-class` MUST render a `KubeDataTable` of the cluster's
StorageClasses (cluster-scoped — no namespace selector applies) with columns
**Name / Default / Reclaim Policy / Volume Binding Mode**. The card title is
EXACTLY `Storage Classes List` (4.1's title, kept verbatim — the e2e-smoke
contract). The Name cell links to `/storage/storage-class/data?name=<name>` —
the list view is the sole producer of those query strings (cluster-scoped: NO
`namespace` param).

- **Default** = the `storageclass.kubernetes.io/is-default-class` annotation
  value (`—` when absent).
- **Reclaim Policy** = `reclaim_policy` (`—` when absent).
- **Volume Binding Mode** = `volume_binding_mode` (`—` when absent).

States: no cluster selected → `No cluster selected.`; loading → `Loading
storage classes...`; error → red error line; empty list → `No storage classes
found` (first-class, not an error).

### R4 — The detail page

`/storage/storage-class/data?name=<name>` MUST fetch the object with a
**single `?name=` request** (not 4.1's list-then-filter). Empty `items` is a
not-found **STATE** — pinned copy `No StorageClass '<name>' found`, muted, not
an error. The page renders:

- A CTable (Name / Created / Reclaim Policy / Binding Mode / Provisioner /
  Labels / Annotations):
  - **Reclaim Policy** = `reclaim_policy` (`—` when absent), **Binding Mode**
    = `volume_binding_mode` (`—` when absent), **Provisioner** =
    `provisioner` (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creation_timestamp`.
- A **Parameters** table (a key/value CTable, `No parameters` when absent),
  one row per `parameters` entry (4.1's dynamic-key Parameters card — the
  `parameters` field is a `map[string]string`).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: storage class name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/storage/storage-class` is removed from `views/Stub/routes.ts`. The
`_nav.tsx` leaf is UNCHANGED (path and label). The data route is not a nav
entry (same as priorityclass/data, network-policy/data).

## Non-goals

- No create/edit/delete for StorageClasses (read-only, as in 4.1 and as in
  every other 5.0 resource view to date).
- No `allowVolumeExpansion` / `allowedTopologies` first-class display — 4.1's
  data page did not surface them; the raw object is in the JSON block.
- No all-namespaces LIST mode on the page (the kind is cluster-scoped; there
  is only one list).
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Storage Classes List` is the only smoke-relevant contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` query-param navigation; no 4.1 hidden form / POST /
   `session['ns_select']`; no list-then-filter on the data page. The kind is
   cluster-scoped, so there is NO `?namespace=` param (unlike the namespaced
   kinds).
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. The data page's "Binding Mode" label is rendered as `Volume Binding Mode`
   (the 4.1 list header) — 4.1's data page used the shorter "Binding Mode"
   label for the same `volume_binding_mode` field; 5.0 keeps the list header
   verbatim for consistency.
4. `trimAnnotations` is NOT replicated — annotations render verbatim; the
   JSON block is the same, and 5.0 has no 4.1 trim helper.
