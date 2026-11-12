# PVC Views (List + Data + Usage) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-pvc-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `VolumeClaims` leaf
(`/storage/pvc`, `_nav.tsx:119`) that currently renders the placeholder stub
(`views/Stub/routes.ts:19`). **4.1 has real templates for this kind**:
`storage/pvc.html.j2` (list: **Status / Name / StorageClass / Volume /
Capacity / Usage**) and `storage/pvc-data.html.j2` (data: Status / Name /
Namespace / Created / Annotations / Labels / StorageClass / Persistent Volume /
Access Mode / VolumeMode / Capacity). Unlike the VolumeSnapshot kind, **PVC is
a core API** (`persistentvolumeclaims`, core group, **namespaced**); the 4.1
read is `k8sPersistentVolumeClaimListGet`
(`4.1:src/kubedash/lib/k8s/storage.py:83`):
`CoreV1Api().list_namespaced_persistent_volume_claim` — a generated core-API
model, so the `to_dict` form is snake_case. The 4.1 Usage column comes from a
SECOND read, `k8sPVCMetric` (`4.1:src/kubedash/lib/k8s/metrics.py:348`): for
EVERY node, the kubelet `/stats/summary` endpoint
(`connect_get_node_proxy_with_path(name, path="stats/summary")`), then an
aggregation of each pod's `volume` entries that carry a `pvcRef` — used /
capacity bytes, `percentageUsed = usedBytes / capacityBytes * 100`. The data
page is the 4.1 list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store,
  as in the NetworkPolicies and ResourceQuota views.
- **Usage column (ratified 2026-10-28):** the list keeps 4.1's Usage column.
  5.0 has no PVC-usage metrics route yet, so this change ADDS one
  (`GET /api/v1/clusters/<id>/metrics/pvcs?namespace=<ns>`) modeled on 4.1's
  `k8sPVCMetric` — kubelet stats, not metrics.k8s.io — with the ADR-0003
  query-only degrade: unavailable kubelet stats are the EXPECTED state
  (200, empty `items`, never an error), and a SAR deny on the stats read is
  reported as `metrics_denied: true`, not a 403 (the declared list never
  breaks on a missing observed tier).
- **Detail rendering:** the data page keeps 4.1's curated table (status,
  access modes, volume mode, capacity, storage class, bound volume, labels,
  annotations) and ADDS the full-object `JSON.stringify(item, null, 2)` block
  with the `json` hljs grammar (the truthful-classifier rule ratified for
  PriorityClassData, final review 2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `persistentvolumeclaims`, core group (`""`), namespace from
  the query (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/storage/pvc` and `/storage/pvc/data`, plus the PVC-usage metrics route,
removing the stub, so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated PVC list endpoint

`GET /api/v1/clusters/<id>/resources/persistentvolumeclaims?namespace=<ns>`
MUST return the PVC list for that namespace (`kind: "persistentvolumeclaims"`,
items in kubernetes `to_dict` snake_case form, `metadata`/`spec`/`status`
intact). With a `namespace` param the read is
`list_namespaced_persistent_volume_claim`; without one the list spans all
namespaces (`list_persistent_volume_claim_for_all_namespaces` — the
`list_secrets` / `list_resource_quotas` branch). The read is SAR-gated per
ADR-0004: `list` on `persistentvolumeclaims`, core group (`""`), namespace =
the query namespace or `None`; on deny the response is 403 `RBAC_DENIED`
naming the resource, and the SAR is asked BEFORE any K8s client call. An
unbound user is 404 from the binding gate. The kind identifier is the plural
`persistentvolumeclaims`; the singular `persistentvolumeclaim` (and 4.1's
route name `pvc`) is rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/persistentvolumeclaims?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup: without it the route falls back
to `namespace = "default"` (the generic route's existing `name` branch
behavior) — the data page ALWAYS sends the namespace it was linked with. No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — A PVC-usage metrics endpoint (kubelet stats, query-only)

`GET /api/v1/clusters/<id>/metrics/pvcs?namespace=<ns>` MUST return the
PVC-storage usage per namespace, derived from the kubelet `/stats/summary`
endpoint (NOT metrics.k8s.io — 4.1's `k8sPVCMetric` read the kubelet stats
and aggregated `pod.volume[].pvcRef`): per PVC in the namespace, the summed
`capacityBytes` / `usedBytes` / `availableBytes` across all pods using it and
`percentageUsed` = used / capacity * 100 (`0.0` when capacity is zero —
guard the 4.1 division-by-zero, which `eval`-era code never hit because
kubelet capacity is never zero in practice).

Response shape: `{ cluster, namespace, source: "kubelet stats/summary",
metrics_available, metrics_denied, items: [{ name, capacity_bytes,
used_bytes, available_bytes, percentage_used }] }`.

- **SAR:** `get` on `nodes` (core group, namespace `None`) — the stats read
  proxies through the node API — asked BEFORE any stats call (ADR-0004). On
  deny the response is still 200 with `metrics_denied: true` and `items: []`
  (the two-tier pattern from `metrics.py`'s summary route: the observed tier
  degrades to unknown, never 403 — the declared PVC list still renders).
- **Degrade (ADR-0003 certainty rule):** a node whose `/stats/summary` fails
  (404/5xx/timeout — no kubelet, kubelet down, stats unavailable) is SKIPPED
  and never raises; when NO node yields stats the response is 200 with
  `metrics_available: false` and `items: []`. NEVER 500 for a missing stats
  source; only a transport-level failure of the stats plumbing that the
  `list` path would also hit maps to `ClusterUnreachableError` (502) is
  permitted, and only when at least one node call reached the API server.
- **Namespace:** the param selects which `pvcRef.namespace` entries are
  aggregated (the 4.1 contract). With no param, `metrics_available` is `false`
  and `items` is `[]` (the page always passes a namespace; the all-namespace
  branch is not built — 4.1 never had one for this read).
- **404** from the binding gate (unbound user / missing cluster), as on every
  other `/clusters/<id>/...` route.

### R4 — The list page

`/storage/pvc` MUST render a `KubeDataTable` in the header-selected namespace
(`useClusterStore.selectedNamespace ?? 'default'`, the NetworkPolicies
pattern) with columns **Status / Name / StorageClass / Volume / Capacity /
Usage**. The card title is EXACTLY `Persistent Volume Claim List` (4.1's
title, kept verbatim — the e2e-smoke contract). The Name cell links to
`/storage/pvc/data?name=<name>&namespace=<ns>` — the list view is the sole
producer of those query strings.

- **Status** = `status.phase` rendered as a badge (4.1's three-tier badge
  pair — `Bound` → success, `Terminating` → danger, everything else →
  warning; `—` when absent).
- **StorageClass** = `spec.storage_class_name` (`—` when absent).
- **Volume** = `spec.volume_name` (`—` when absent — an unbound claim has no
  volume).
- **Capacity** = `status.capacity.storage` (`—` when absent).
- **Usage** = `percentage_used` from the R3 metrics route joined by PVC name:
  `42.7 %` (one decimal, 4.1's `round(1)`), `—` when the PVC is absent from
  the metrics response (unmeasured, no pods using it, or stats unavailable —
  the cell never errors).

The list fetches `/api/v1/clusters/<id>/resources/persistentvolumeclaims?namespace=<ns>`
ALWAYS with the namespace param (a namespaced kind — unlike the
cluster-scoped kinds); the usage query is a SECOND parallel fetch on
`/api/v1/clusters/<id>/metrics/pvcs?namespace=<ns>` (a failed usage fetch
degrades the Usage column to `—`, it never fails the list).

States: no cluster selected → `No cluster selected.`; loading → `Loading
persistent volume claims...`; error → red error line; empty list → `No
persistent volume claims found` (first-class, not an error).

### R5 — The detail page

`/storage/pvc/data?name=<name>&namespace=<ns>` MUST fetch the object with a
**single `?name=&namespace=` request** (not 4.1's list-then-filter). Empty
`items` is a not-found **STATE** — pinned copy `No PVC '<name>' found`, muted,
not an error. The page renders:

- A CTable (Status / Name / Namespace / Created / Access Mode / Volume Mode /
  Capacity / StorageClass / Persistent Volume / Labels / Annotations):
  - **Status** = `status.phase` (badge-style, same tiers as R4; `—` when
    absent).
  - **Namespace** = the `?namespace=` param (the page knows its namespace —
    4.1 passed `session['ns_select']` here).
  - **Access Mode** = `spec.access_modes` joined with `, ` (`—` when absent
    or empty).
  - **Volume Mode** = `spec.volume_mode` (`—` when absent).
  - **Capacity** = `status.capacity.storage` (`—` when absent).
  - **StorageClass** = `spec.storage_class_name` (`—` when absent).
  - **Persistent Volume** = `spec.volume_name` (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creation_timestamp`.
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: pvc name not provided`. Missing `namespace`
param → the page falls back to the header-selected namespace (it only renders
when a cluster is selected, so the store value is always available); it still
sends the resolved namespace in the request.

### R6 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/storage/pvc` is removed from `views/Stub/routes.ts`. The `_nav.tsx` leaf is
UNCHANGED (path and label). The data route is not a nav entry (same as
priorityclass/data, network-policy/data).

## Non-goals

- No create/edit/delete for PVCs (read-only, as in 4.1 and as in every other
  5.0 resource view to date).
- No `Volume` (PV) view — `/storage/pv` is a separate kind change; 4.1's
  Volume cells linked to `/storage/pv` via hidden forms, 5.0 renders plain
  text (the full object is in the JSON block).
- No `StorageClass` deep-link from the PVC cells — 5.0's StorageClass page is
  a separate change landing in the same batch; the cells render plain text
  (the full `spec` is in the JSON block).
- No per-volume breakdown of Usage (which pod uses what) — 4.1 showed the
  aggregate per PVC only; the pod-level detail is out of scope (it is in the
  kubelet stats the API returns, but the view does not render it).
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace; the all-namespaces list branch exists for the
  API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Persistent Volume Claim List` is the only smoke-relevant
  contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a Jinja table-only page.
3. **Usage is a second REST fetch, not a server-side join.** 4.1 computed
   `k8sPVCMetric` in the list route and joined in the template; 5.0 exposes
   it as its own metrics route (the ADR-0003 two-tier pattern) so the list
   renders even when kubelet stats are absent and the SAR deny on the stats
   tier degrades the column to `—` instead of a 500.
4. **The Usage metrics read is SAR-gated on `get nodes` and degrades, not
   403s** — 4.1's `k8sPVCMetric` read as the `Admin` token (no per-user
   gating at all); 5.0 asks the acting user's grant and reports
   `metrics_denied` (the metrics.k8s.io two-tier rule applied to the kubelet
   stats source).
5. **`eval` is replaced with a real JSON parse.** 4.1 `eval()`s the kubelet
   stats body (Python literal eval on an untrusted-ish wire string); 5.0 uses
   `json.loads`.
6. **`trimAnnotations` is NOT replicated** — annotations render verbatim; the
   JSON block is the same, and 5.0 has no 4.1 trim helper.
7. The 4.1 data page's label typo (`Lables`) is not replicated — 5.0 renders
   `Labels`.
8. 4.1's `k8sPVCMetric` computed percentages from values it had already
   divided by 1024 (KB); the ratio is dimensionless so the result is the
   same — 5.0 keeps raw bytes in the response and computes the ratio once
   (`used_bytes / capacity_bytes * 100`), rounding to one decimal in the
   view (4.1's `round(1)`).
