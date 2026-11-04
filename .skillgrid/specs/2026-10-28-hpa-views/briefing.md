# HPAs (Horizontal Pod Autoscaler) Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-hpa-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries an `HPAs` leaf
(`/other-resource/horizontal-pod-autoscaler`, `_nav.tsx:111`) that currently
renders the placeholder stub (`views/Stub/routes.ts:23`). **4.1 has real
templates for this kind**: `other-resources/hpa.html.j2` (list: Name /
Namespace / Owner / Targets / MinReplicas / MaxReplicas / Replicas) and
`hpa-data.html.j2` (data: Name / Created / Namespace / Annotations / Labels /
Owner / Metrics / MinReplicas / MaxReplicas / Deployment pods / a Conditions
table). Unlike VPAs, **HPAs are a core API**
(`horizontalpodautoscalers`, group `""` v1, **namespaced**); the 4.1 read is
`k8sHPAListGet` (`4.1:src/kubedash/lib/k8s/other.py:110`):
`AutoscalingV1Api().list_namespaced_horizontal_pod_autoscaler` — a generated
core-API model, so the `to_dict` form is snake_case. The data page is the 4.1
list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store,
  as in the NetworkPolicies and ResourceQuota views.
- **Detail rendering:** the data page keeps 4.1's curated tables (metadata,
  owner, metrics, replicas, conditions) and ADDS the full-object
  `JSON.stringify(item, null, 2)` block with the `json` hljs grammar (the
  truthful-classifier rule ratified for PriorityClassData, final review
  2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `horizontalpodautoscalers`, core group (`""`), namespace
  from the query (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/other-resource/horizontal-pod-autoscaler` and
`/other-resource/horizontal-pod-autoscaler/data`, removing the stub, so the
nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated HPA list endpoint

`GET /api/v1/clusters/<id>/resources/horizontalpodautoscalers?namespace=<ns>`
MUST return the HorizontalPodAutoscaler list for that namespace
(`kind: "horizontalpodautoscalers"`, items in kubernetes `to_dict` snake_case
form). Without a `namespace` param the list MUST span all namespaces
(`list_horizontal_pod_autoscaler_for_all_namespaces` — the `list_secrets` /
`list_network_policies` all-namespaces branch). The read is SAR-gated per
ADR-0004: `list` on `horizontalpodautoscalers`, core group (`""`), namespace =
the query namespace or `None`; on deny the response is 403 `RBAC_DENIED`
naming the resource, and the SAR is asked BEFORE any K8s client call. An
unbound user is 404 from the binding gate. The kind identifier is the plural
`horizontalpodautoscalers`; the singular `horizontalpodautoscaler` is rejected
with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/horizontalpodautoscalers?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup: without it the route falls back
to `namespace = "default"` (the generic route's existing `name` branch
behavior) — the data page ALWAYS sends the namespace it was linked with. No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — The list page

`/other-resource/horizontal-pod-autoscaler` MUST render a `KubeDataTable` in
the header-selected namespace (`useClusterStore.selectedNamespace ??
'default'`, the NetworkPolicies pattern) with columns **Name / Namespace /
Owner / Targets / Min Replicas / Max Replicas / Replicas**. The card title is
EXACTLY `Horizontal Pod Autoscaler List` (4.1's title, kept verbatim — the
e2e-smoke contract). The Name cell links to
`/other-resource/horizontal-pod-autoscaler/data?name=<name>&namespace=<ns>` —
the list view is the sole producer of those query strings.

- **Owner** = `spec.scale_target_ref.name` (4.1 made it a link to the workload
  page — 5.0 has no workload-page destination yet, so it renders as plain
  text; the target is still shown first-class).
- **Targets** = `status.current_cpu_utilization_percentage` /
  `spec.target_cpu_utilization_percentage` `%`, the `UNKNOWN` literal when
  `current_cpu_utilization_percentage` is absent (4.1's exact behavior — a
  legacy v1 CPU-only field, see `adr.md` Deviations).
- **Min Replicas** = `spec.min_replicas`, **Max Replicas** = `spec.max_replicas`
  (the 4.1 list template's header-cell swap is corrected — the `MinReplicas`
  header showed `max_replicas`; 5.0 renders the matching value), **Replicas**
  = `status.current_replicas`. A missing value renders `—`.

States: no cluster selected → `No cluster selected.`; loading → `Loading
horizontal pod autoscalers...`; error → red error line; empty list →
`No horizontal pod autoscalers found` (first-class, not an error).

### R4 — The detail page

`/other-resource/horizontal-pod-autoscaler/data?name=<name>&namespace=<ns>`
MUST fetch the object with a **single `?name=&namespace=` request** (not 4.1's
list-then-filter). Empty `items` is a not-found **STATE** — pinned copy
`No HorizontalPodAutoscaler '<name>' found`, muted, not an error. The page
renders:

- A CTable (Name / Created / Namespace / Owner / Metrics / Min Replicas / Max
  Replicas / Replicas / Labels / Annotations):
  - **Owner** = `spec.scale_target_ref.name` (`—` when absent; plain text —
    the 4.1 workload link is dropped).
  - **Metrics** = `status.current_cpu_utilization_percentage` /
    `spec.target_cpu_utilization_percentage` `%` (the `UNKNOWN` literal when
    the current is absent — 4.1's exact behavior).
  - **Min Replicas** = `spec.min_replicas`, **Max Replicas** =
    `spec.max_replicas` (corrected from 4.1's data template, which read the
    same fields correctly — the swap was list-only).
  - **Replicas** = `status.current_replicas` Current /
    `status.desired_replicas` Desired (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creation_timestamp`.
- A **Conditions** table with header `Type / Status / Last Transition Time /
  Reason / Message`, one row per condition (`No conditions` when absent). The
  conditions are read from `status.conditions` when present, else from the
  legacy `autoscaling.alpha.kubernetes.io/conditions` annotation (4.1's
  source — 4.1's dynamic-key table is replaced by this typed shape; see
  `adr.md` Deviations).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: horizontal pod autoscaler name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/other-resource/horizontal-pod-autoscaler` is removed from
`views/Stub/routes.ts`. The `_nav.tsx` leaf is UNCHANGED (path and label).
The data route is not a nav entry (same as priorityclass/data,
network-policy/data).

## Non-goals

- No create/edit/delete for HorizontalPodAutoscalers (read-only, as in 4.1 and
  as in every other 5.0 resource view to date).
- No multi-metric (v2 `spec.metrics` / `status.conditions` with
  `Resource`/`ContainerResource`/`Object`/`Pods` metric kinds) display — 4.1
  rendered only the legacy v1 CPU target. The raw spec/status (including
  `spec.metrics`) is in the JSON block.
- No Owner deep-link: 4.1 linked Owner to `/workload/<kind-lower>s`; 5.0 has
  no workload-page destination yet, so the owner renders as plain text. The
  full `scale_target_ref` is in the JSON block.
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace (4.1's `ns_select`); the all-namespaces list
  branch exists for the API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Horizontal Pod Autoscaler List` is the only smoke-relevant
  contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. The list template's MinReplicas/MaxReplicas header-cell swap is
   corrected: the `Min Replicas` column shows `spec.min_replicas` and the
   `Max Replicas` column shows `spec.max_replicas` (4.1's `MinReplicas`
   header rendered `max_replicas`).
4. The Conditions table is typed (`Type / Status / Last Transition Time /
   Reason / Message`), not 4.1's dynamic-key table. The conditions are read
   from `status.conditions` when present, else from the legacy
   `autoscaling.alpha.kubernetes.io/conditions` annotation (4.1's source).
5. The Target/Owner link (to `/workload/<kind-lower>s`) is dropped — 5.0 has
   no workload-page destination yet; the owner renders as plain text.
6. `trimAnnotations` is NOT replicated — annotations render verbatim; the
   JSON block is the same, and 5.0 has no 4.1 trim helper.
   **OVERRIDDEN (2026-11-04):** the data view now applies 4.1's trim
   (user-requested format fix, commit `46929a10`) — the two machine-managed
   keys (`kubectl.kubernetes.io/last-applied-configuration`,
   `autoscaling.alpha.kubernetes.io/conditions`) are dropped from the
   annotations table; the JSON block still carries the full object.
