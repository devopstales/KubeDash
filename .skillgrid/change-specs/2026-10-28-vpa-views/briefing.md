# VPAs (Vertical Pod Autoscaler) Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-vpa-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `VPAs` leaf
(`/other-resource/vertical-pod-autoscaler`, `_nav.tsx:112`) that currently
renders the placeholder stub (`views/Stub/routes.ts:24`). **4.1 has real
templates for this kind**: `other-resources/vpa.html.j2` (list: Name /
Namespace / Target Kind / Target Name / Update Mode / Min Memory / Max Memory
/ Creation Timestamp) and `vpa-data.html.j2` (data: Name / Created / Namespace
/ Annotations / Labels / Target (Owner) / Update Mode / Container Policies /
Conditions). Unlike the core-API kinds, **VPAs are a CRD**
(`verticalpodautoscalers.autoscaling.k8s.io`, group `autoscaling.k8s.io`,
**namespaced**); the 4.1 read is `k8sVPAListGet`
(`4.1:src/kubedash/lib/k8s/other.py:50`), which resolves the CRD's
served+storage version at runtime (`get_vpa_crd_version`) then calls
`CustomObjectsApi().list_namespaced_custom_object`. The data page is the 4.1
list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store,
  as in the NetworkPolicies and ResourceQuota views.
- **Read seam:** the **Cilium precedent** — a CRD kind read as a FULL
  custom object (spec/status intact, camelCase), with the CRD's OWN served
  version + scope as the authority and **CRD-absent degrades to `[]`** (the
  VPA operator is optional; a cluster without it is a first-class empty state,
  not an error). Not the lossy `list_crd_instances` projection (which drops
  `spec`/`status`).
- **Detail rendering:** the data page keeps 4.1's curated tables (metadata,
  target, update mode, container policies, conditions) and ADDS the
  full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
  grammar (the truthful-classifier rule ratified for PriorityClassData, final
  review 2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `verticalpodautoscalers`, group `autoscaling.k8s.io`,
  namespace from the query (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/other-resource/vertical-pod-autoscaler` and
`/other-resource/vertical-pod-autoscaler/data`, removing the stub, so the nav
leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated VPA list endpoint

`GET /api/v1/clusters/<id>/resources/verticalpodautoscalers?namespace=<ns>`
MUST return the VerticalPodAutoscaler list for that namespace
(`kind: "verticalpodautoscalers"`, items as FULL custom objects — the raw
`to_dict` with `metadata`/`spec`/`status` intact, camelCase, NOT the lossy
`CrdInstance` projection). The CRD's OWN served version + scope is the
authority (the `get_crd_served` pattern); without a `namespace` param the list
MUST span all namespaces (`list_cluster_custom_object` — the
`list_cilium_network_policies` all-namespaces branch). The read is SAR-gated
per ADR-0004: `list` on `verticalpodautoscalers`, group
`autoscaling.k8s.io`, namespace = the query namespace or `None`; on deny the
response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked BEFORE
any K8s client call. An unbound user is 404 from the binding gate. When the
VPA CRD is **absent** (operator not installed) the list MUST be `[]` — a
first-class empty state, not an error (the Cilium absence contract). The kind
identifier is the plural `verticalpodautoscalers`; the singular
`verticalpodautoscaler` is rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/verticalpodautoscalers?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single full object, a miss is `[]` (not a 404 — the data page
renders a not-found state). SAR-gated on `get` with the same namespace
semantics. CRD-absent is also `[]`. The namespace param is REQUIRED for the
lookup: without it the route falls back to `namespace = "default"` (the
generic route's existing `name` branch behavior) — the data page ALWAYS sends
the namespace it was linked with. No new HTTP route is added: the kind is
wired through `_KINDS` + `_GETTERS` only.

### R3 — The list page

`/other-resource/vertical-pod-autoscaler` MUST render a `KubeDataTable` in
the header-selected namespace (`useClusterStore.selectedNamespace ??
'default'`, the NetworkPolicies pattern) with columns **Name / Namespace /
Target Kind / Target Name / Update Mode / Min Memory / Max Memory / Created**.
The card title is EXACTLY `Vertical Pod Autoscaler List` (4.1's title, kept
verbatim — the e2e-smoke contract). The Name cell links to
`/other-resource/vertical-pod-autoscaler/data?name=<name>&namespace=<ns>` —
the list view is the sole producer of those query strings.

- **Target Kind** = `spec.targetRef.kind`; **Target Name** =
  `spec.targetRef.name` (4.1 made Target Name a link to the workload page —
  5.0 has no workload-page destination yet, so it renders as plain text; the
  target is still shown first-class).
- **Update Mode** = `spec.updatePolicy.updateMode` (`N/A` when `updatePolicy`
  is absent — 4.1's literal).
- **Min Memory** = the `minAllowed.memory` of the LAST container in
  `spec.resourcePolicy.containerPolicies` that defines it (`N/A` when none —
  4.1's `{% set %}` overwrite semantics). **Max Memory** = the same for
  `maxAllowed.memory`.
- **Created** = `formatTimestamp` of `metadata.creation_timestamp`.

States: no cluster selected → `No cluster selected.`; loading →
`Loading vertical pod autoscalers...`; error → red error line; empty list →
`No vertical pod autoscalers found` (first-class, not an error — this is ALSO
the CRD-absent state; the page does not distinguish "CRD absent" from "no
VPAs" in the empty state, both render the same copy).

### R4 — The detail page

`/other-resource/vertical-pod-autoscaler/data?name=<name>&namespace=<ns>`
MUST fetch the object with a **single `?name=&namespace=` request** (not 4.1's
list-then-filter). Empty `items` is a not-found **STATE** — pinned copy
`No VerticalPodAutoscaler '<name>' found`, muted, not an error. The page
renders:

- A CTable (Name / Created / Namespace / Target (Owner) / Update Mode /
  Labels / Annotations):
  - **Target (Owner)** = `spec.targetRef.name` (`—` when absent).
  - **Update Mode** = `spec.updatePolicy.updateMode` (`N/A` when
    `updatePolicy` is absent — 4.1's literal).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creation_timestamp`.
- A **Container Policies** table with header `Container Name / Controlled
  Values / Mode / Min Allowed / Max Allowed / Controlled Resources`, one row
  per `spec.resourcePolicy.containerPolicies[]` entry (`No container
  policies` when the resource policy or its list is absent):
  - Min Allowed / Max Allowed render `resource: value` lines (`N/A` when the
    bound is absent).
  - Controlled Resources renders `spec.resourcePolicy.containerPolicies[i]
    .controlledResources` joined by `, ` (`N/A` when absent).
- A **Conditions** table with header `Type / Status / Last Transition Time /
  Reason / Message`, one row per `status.conditions[]` entry (`No conditions`
  when absent) — read from `status.conditions` (4.1's template iterated a
  top-level `conditions` key the read function never populated, so 4.1's table
  was always empty — see `adr.md` Deviations).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: vertical pod autoscaler name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/other-resource/vertical-pod-autoscaler` is removed from
`views/Stub/routes.ts`. The `_nav.tsx` leaf is UNCHANGED (path and label).
The data route is not a nav entry (same as priorityclass/data,
network-policy/data).

## Non-goals

- No create/edit/delete for VerticalPodAutoscalers (read-only, as in 4.1 and
  as in every other 5.0 resource view to date).
- No Target Name deep-link: 4.1 linked Target Name to
  `/workload/<kind-lower>s`; 5.0 has no workload-page destination yet, so the
  target name renders as plain text (the kind is still shown in the Target
  Kind column). The JSON block carries the full `targetRef`.
- No `status.recommendation` / `status.community.recommendation` drill-down —
  4.1's data page did not surface the recommendation; the raw status is in
  the JSON block.
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace (4.1's `ns_select`); the all-namespaces list
  branch exists for the API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Vertical Pod Autoscaler List` is the only smoke-relevant
  contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. The Conditions table reads `status.conditions`, not 4.1's top-level
   `conditions` key (which the read function never populated — 4.1's table
   was dead/always-empty). The raw conditions are in the JSON block either way.
4. The Target Name link (to `/workload/<kind-lower>s`) is dropped — 5.0 has no
   workload-page destination yet; the target name is plain text.
5. The custom object is read as a FULL object (spec/status intact, camelCase)
   via the Cilium precedent, not the lossy `list_crd_instances` projection —
   the VPA pages need `spec.resourcePolicy` and `status.conditions`, which the
   projection drops.
6. `trimAnnotations` is NOT replicated — annotations render verbatim; the JSON
   block is the same, and 5.0 has no 4.1 trim helper.
