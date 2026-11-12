# ResourceQuota Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-resourcequota-views`
**Date:** 2026-10-28
**Backlog:** TASK-047
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `Resource Quota` leaf
(`/other-resource/resource-quota`, `_nav.tsx:114`) that currently renders the
placeholder stub (`views/Stub/routes.ts:26`). Unlike the RuntimeClass leaf,
**4.1 has real templates for this kind**: `other-resources/resource-quota.html.j2`
(list: Name / Namespace / Request / Limit) and
`resource-quota-data.html.j2` (data: Name / Created / Namespace / Creation /
Selectors / Scopes / Annotations / Labels / a Status table of
used-vs-hard for `limits.cpu`, `limits.memory`, `requests.cpu`,
`requests.memory`). The 4.1 read is `k8sQuotaListGet`
(`4.1:src/kubedash/lib/k8s/other.py:203`): `CoreV1Api().list_namespaced_resource_quota`
— a **namespaced** kind (core group), scoped to the session's selected
namespace; the data page is the 4.1 list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden
  forms / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs decision).
  The namespace comes from the header's selected-namespace store, as in the
  NetworkPolicies view.
- **Detail rendering:** the data page keeps 4.1's curated tables (metadata,
  scopes, labels, annotations, status) and ADDS the full-object
  `JSON.stringify(item, null, 2)` block with the `json` hljs grammar (the
  truthful-classifier rule ratified for PriorityClassData, final review
  2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `resourcequotas`, core group (`''`), namespace from the
  query (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/other-resource/resource-quota` and `/other-resource/resource-quota/data`,
removing the stub, so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated ResourceQuota list endpoint

`GET /api/v1/clusters/<id>/resources/resourcequotas?namespace=<ns>` MUST
return the ResourceQuota list for that namespace (`kind: "resourcequotas"`,
items in kubernetes `to_dict` snake_case form). Without a `namespace` param
the list MUST span all namespaces (`list_resource_quota_for_all_namespaces`
— the `list_secrets` / `list_network_policies` all-namespaces branch). The
read is SAR-gated per ADR-0004: `list` on `resourcequotas`, core group
(`''`), namespace = the query namespace or `None`; on deny the response is
403 `RBAC_DENIED` naming the resource, and the SAR is asked BEFORE any K8s
client call. An unbound user is 404 from the binding gate. The kind
identifier is the plural `resourcequotas`; the singular `resourcequota` is
rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/resourcequotas?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup: without it the route falls back
to `namespace = "default"` (the generic route's existing `name` branch
behavior) — the data page ALWAYS sends the namespace it was linked with. No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — The list page

`/other-resource/resource-quota` MUST render a `KubeDataTable` in the
header-selected namespace (`useClusterStore.selectedNamespace ?? 'default'`,
the NetworkPolicies pattern) with columns **Name / Namespace / Requests /
Limits / Created**. The card title is EXACTLY `Resource Quota List` (4.1's
title, kept verbatim — the e2e-smoke contract). The Name cell links to
`/other-resource/resource-quota/data?name=<name>&namespace=<ns>` — the list
view is the sole producer of those query strings.

The **Requests** cell shows, one per line: `requests.cpu: <used> / <hard>`
and `requests.memory: <used> / <hard>` (4.1's badge pairs). The **Limits**
cell shows the same for `limits.cpu` / `limits.memory`. A key missing from
`status.used` or `status.hard` renders as `—` (4.1 would KeyError; 5.0
renders certainty, never guesses). `Created` is `formatTimestamp` of
`metadata.creation_timestamp`. States: no cluster selected →
`No cluster selected.`; loading → `Loading resource quotas...`; error → red
error line; empty list → `No resource quotas found` (first-class, not an
error).

### R4 — The detail page

`/other-resource/resource-quota/data?name=<name>&namespace=<ns>` MUST fetch
the object with a **single `?name=&namespace=` request** (not 4.1's
list-then-filter). Empty `items` is a not-found **STATE** — pinned copy
`No ResourceQuota '<name>' found`, muted, not an error. The page renders:

- A CTable (Name / Created / Namespace / Scope / Labels / Annotations):
  Scope as badge-style entries (`spec.scopes`, `—` when absent); Labels and
  Annotations as key/value sub-tables (`No labels` / `No annotations` when
  empty).
- A **Status** table with header Resource / Used / Hard Limit and one row per
  quota dimension: `limits.cpu`, `limits.memory`, `requests.cpu`,
  `requests.memory` (4.1's four dimensions, in 4.1's order); a missing
  value renders as `—`.
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: resource quota name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/other-resource/resource-quota` is removed from `views/Stub/routes.ts`. The
`_nav.tsx` leaf is UNCHANGED (path and label). The data route is not a nav
entry (same as priorityclass/data, network-policy/data).

## Non-goals

- No create/edit/delete for ResourceQuotas (read-only, as in 4.1 and as in
  every other 5.0 resource view to date).
- No `spec.scope_selector` UI on the data page — 4.1 rendered a "Selectors"
  row, but `k8sQuotaListGet` sets it to a single expression's `to_dict()`
  (overwriting per expression: a latent 4.1 bug for multi-expression
  selectors) and the raw value is covered by the full-object JSON block.
  Scope *names* (`spec.scopes`) are rendered first-class; the raw selector
  stays in the JSON block. Recorded as a 4.1 deviation in `adr.md`.
- No quota-consumption drill-down into the pods causing usage — the pod view
  does not exist in 5.0 yet.
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace (4.1's `ns_select`); the all-namespaces list
  branch exists for the API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Resource Quota List` is the only smoke-relevant contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. Missing `status.used` / `status.hard` keys render as `—` (certainty rule)
   instead of 4.1's KeyError.
4. `spec.scope_selector` is NOT rendered as its own table (4.1's
   Selectors row dropped; latent overwrite bug; the raw value is in the JSON
   block). `spec.scopes` is rendered.
5. 4.1's data-page duplicate `Creation` row (both `Created` and
   `Creation` showed `creation_timestamp`) is collapsed to one `Created`
   row.
6. 4.1's `trimAnnotations` (drop
   `kubectl.kubernetes.io/last-applied-configuration`) is NOT replicated —
   annotations render verbatim; the JSON block is the same, and 5.0 has no
   4.1 trim helper.
