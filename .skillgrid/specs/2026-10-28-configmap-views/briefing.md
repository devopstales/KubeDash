# ConfigMap Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-configmap-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `ConfigMaps` leaf
(`/storage/configmap`, `_nav.tsx:118`) that currently renders the placeholder
stub (`views/Stub/routes.ts:17`). **4.1 has real templates for this kind**:
`storage/configmap.html.j2` (list: **Name / Created** — deliberately sparse;
the 4.1 list read projects only `name`/`created`/`annotations`/`labels`/
`data`/`version`) and `storage/configmap-data.html.j2` (data: Name /
Namespace / Kind / Created / Annotations / Labels / Version + a per-key
`data` table, each value in a `<pre><code>` block). Unlike the VolumeSnapshot
kind, **ConfigMap is a core API** (`configmaps`, core group, **namespaced**);
the 4.1 read is `k8sConfigmapListGet`
(`4.1:src/kubedash/lib/k8s/storage.py:200`):
`CoreV1Api().list_namespaced_config_map(namespace, _request_timeout=1)` — a
generated core-API model, so the `to_dict` form is snake_case. The data page
is the 4.1 list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store,
  as in the NetworkPolicies, ResourceQuota, and Secret views.
- **Detail rendering:** the data page keeps 4.1's metadata table (name,
  namespace, kind, created, version, labels, annotations) and ADDS the
  4.1 per-key **Data** table (one row per `data` entry, value in a
  `<pre><code>` block) — plus the full-object `JSON.stringify(item, null, 2)`
  block with the `json` hljs grammar (the truthful-classifier rule ratified
  for PriorityClassData, final review 2026-10-28).
- **List stays 4.1-sparse:** the list page renders **Name / Data Keys /
  Created** — 4.1's two columns plus a `Data Keys` count column
  (`data` key count, `—` when absent). Rationale: 4.1's list showed Name /
  Created only, but a ConfigMap with zero visible payload is useless to
  distinguish from one with a config; the key count is the one field that
  adds signal without a per-row payload read. `data` is present on the list
  read (a ConfigMap's `data` is public, unlike a Secret's), so the count is
  free — no second fetch.
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `configmaps`, core group (`""`), namespace from the query
  (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/storage/configmap` and `/storage/configmap/data`, removing the stub, so the
nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated ConfigMap list endpoint

`GET /api/v1/clusters/<id>/resources/configmaps?namespace=<ns>` MUST return
the ConfigMap list for that namespace (`kind: "configmaps"`, items in
kubernetes `to_dict` snake_case form, `metadata`/`data`/`binaryData` intact).
With a `namespace` param the read is `list_namespaced_config_map`; without
one the list spans all namespaces
(`list_config_map_for_all_namespaces` — the `list_secrets` branch). **No
field stripping**: unlike `list_secrets` (which pops `data`/`string_data`
because a Secret's values are sensitive), a ConfigMap's `data` is public
config and the list view renders a key count from it — the full `to_dict`
goes to the view. The read is SAR-gated per ADR-0004: `list` on `configmaps`,
core group (`""`), namespace = the query namespace or `None`; on deny the
response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked
BEFORE any K8s client call. An unbound user is 404 from the binding gate.
The kind identifier is the plural `configmaps`; the singular `configmap` is
rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/configmaps?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders
a not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup: without it the route falls back
to `namespace = "default"` (the generic route's existing `name` branch
behavior) — the data page ALWAYS sends the namespace it was linked with. No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — The list page

`/storage/configmap` MUST render a `KubeDataTable` in the header-selected
namespace (`useClusterStore.selectedNamespace ?? 'default'`, the NetworkPolicies
pattern) with columns **Name / Data Keys / Created**. The card title is
EXACTLY `Configmaps List` (4.1's title, kept verbatim — the e2e-smoke
contract; note 4.1's casing is `Configmaps`, not `ConfigMaps` — the nav
label stays `ConfigMaps`, the card title stays 4.1's `Configmaps List`).
The Name cell links to
`/storage/configmap/data?name=<name>&namespace=<ns>` — the list view is the
sole producer of those query strings.

- **Data Keys** = `Object.keys(data ?? {}).length`, rendered as a plain
  integer (`0` is a valid count, not `—`); `—` only when `data` is entirely
  absent from the object. (`binaryData` keys are NOT counted — 4.1's list
  read projected only `data`, and a ConfigMap with only `binaryData` is the
  edge case the JSON block covers; the count is a signal, not an inventory.)
- **Created** = `formatTimestamp` of `metadata.creation_timestamp`.

States: no cluster selected → `No cluster selected.`; loading → `Loading
configmaps...`; error → red error line; empty list → `No configmaps found`
(first-class, not an error).

### R4 — The detail page

`/storage/configmap/data?name=<name>&namespace=<ns>` MUST fetch the object
with a **single `?name=&namespace=` request** (not 4.1's list-then-filter).
Empty `items` is a not-found **STATE** — pinned copy `No ConfigMap '<name>'
found`, muted, not an error. The page renders:

- A CTable (Name / Namespace / Kind / Created / Version / Labels /
  Annotations):
  - **Namespace** = the `?namespace=` param (the page knows its namespace —
    4.1 passed `session['ns_select']` here).
  - **Kind** = `ConfigMap` (4.1 hardcoded this row).
  - **Version** = `metadata.resource_version` (`—` when absent) (4.1's
    `version` row, kept — it is the resourceVersion, useful for drift
    detection).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creation_timestamp`.
- A **Data** table (a CTable, `No data` when `data` is absent or empty), one
  row per `data` entry: the key as the row label, the value in a
  `<pre><code>` block with `white-space: pre-wrap; word-break: break-word`
  (4.1's `<pre><code>` block, re-implemented — the value is rendered
  verbatim, no base64 decode, no language detection: ConfigMap `data` values
  are plain strings, unlike a Secret's base64 `data`; the `secretLanguage`
  heuristic is NOT applied here — it is a Secret-only concern).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: configmap name not provided`. Missing
`namespace` param → the page falls back to the header-selected namespace
(it only renders when a cluster is selected, so the store value is always
available); it still sends the resolved namespace in the request.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the secret route block).
`/storage/configmap` is removed from `views/Stub/routes.ts`. The `_nav.tsx`
leaf is UNCHANGED (path and label). The data route is not a nav entry (same
as secret/data, network-policy/data).

## Non-goals

- No create/edit/delete for ConfigMaps (read-only, as in 4.1 and as in every
  other 5.0 resource view to date).
- No `binaryData` first-class display — 4.1's data page rendered only
  `data`; `binaryData` is base64 (it is in the JSON block, and a future
  change can add a decode-and-render table mirroring the Secret view's
  `SecretValue` component).
- No per-key language detection on `data` values (the `secretLanguage`
  heuristic is Secret-only — it decodes base64 first; ConfigMap values are
  plain strings and render as `<pre><code>` text, matching 4.1).
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace; the all-namespaces list branch exists for the
  API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Configmaps List` is the only smoke-relevant contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier) — 4.1's data page had no full-object block
   at all (only the metadata table + the per-key `data` table).
3. **The list gains a `Data Keys` column** (4.1 showed Name / Created only).
   The count is free — `data` is on the list read (a ConfigMap's `data` is
   public, so `list_configmaps` does NOT strip it, unlike `list_secrets`) —
   and it is the one field that distinguishes an empty ConfigMap from a
   populated one without a per-row payload read.
4. The list read uses NO per-request `_request_timeout=1` (4.1 passed a
   1-second timeout to `list_namespaced_config_map`; 5.0's client uses the
   pool's configured timeout — a 1 s list read on a large namespace is a
   spurious-failure source, and the 5.0 client's contract is the pool
   timeout, not a per-call override).
5. **`trimAnnotations` is NOT replicated** — annotations render verbatim;
   the JSON block is the same, and 5.0 has no 4.1 trim helper.
6. The data page's "Lables" typo (4.1's `configmap-data.html.j2` line 70)
   is not replicated — 5.0 renders `Labels`.
