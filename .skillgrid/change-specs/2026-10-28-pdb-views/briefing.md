# PodDisruptionBudget Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-pdb-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `Pod Disruption Budget` leaf
(`/other-resource/pod-disruption-budget`, `_nav.tsx:113`) that currently renders
the placeholder stub (`views/Stub/routes.ts:25`). **4.1 has real templates for
this kind**: `other-resources/pod-disruption-budget.html.j2` (list: Name /
Namespace / Min Available / Max Unavailable / Allowed Disruptions) and
`pod-disruption-budget-data.html.j2` (data: Name / Created / Namespace /
Creation / Annotations / Labels / Selector / Eviction Policy / a Status row /
a Conditions table). The 4.1 read is `k8sPodDisruptionBudgetListGet`
(`4.1:src/kubedash/lib/k8s/other.py:153`): `PolicyV1Api().list_namespaced_pod_disruption_budget`
— a **namespaced** kind (`policy/v1`), scoped to the session's selected
namespace; the data page is the 4.1 list-then-filter by name.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store,
  as in the NetworkPolicies and ResourceQuota views.
- **Detail rendering:** the data page keeps 4.1's curated tables (policy
  metadata, selector, eviction policy, status, conditions) and ADDS the
  full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
  grammar (the truthful-classifier rule ratified for PriorityClassData, final
  review 2026-10-28).
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `poddisruptionbudgets`, group `policy` (v1), namespace from
  the query (or `None` for the all-namespaces read).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja dropped.

Deliver: a real list page and a real detail page at
`/other-resource/pod-disruption-budget` and
`/other-resource/pod-disruption-budget/data`, removing the stub, so the nav
leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated PDB list endpoint

`GET /api/v1/clusters/<id>/resources/poddisruptionbudgets?namespace=<ns>`
MUST return the PodDisruptionBudget list for that namespace
(`kind: "poddisruptionbudgets"`, items in kubernetes `to_dict` snake_case
form). Without a `namespace` param the list MUST span all namespaces
(`list_pod_disruption_budget_for_all_namespaces` — the `list_secrets` /
`list_network_policies` all-namespaces branch). The read is SAR-gated per
ADR-0004: `list` on `poddisruptionbudgets`, group `policy` (v1), namespace =
the query namespace or `None`; on deny the response is 403 `RBAC_DENIED`
naming the resource, and the SAR is asked BEFORE any K8s client call. An
unbound user is 404 from the binding gate. The kind identifier is the plural
`poddisruptionbudgets`; the singular `poddisruptionbudget` is rejected with
`RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/poddisruptionbudgets?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup: without it the route falls back
to `namespace = "default"` (the generic route's existing `name` branch
behavior) — the data page ALWAYS sends the namespace it was linked with. No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — The list page

`/other-resource/pod-disruption-budget` MUST render a `KubeDataTable` in the
header-selected namespace (`useClusterStore.selectedNamespace ?? 'default'`,
the NetworkPolicies pattern) with columns **Name / Namespace / Min Available
/ Max Unavailable / Allowed Disruptions**. The card title is EXACTLY `Pod
Disruption Budget List` (4.1's title, kept verbatim — the e2e-smoke
contract). The Name cell links to
`/other-resource/pod-disruption-budget/data?name=<name>&namespace=<ns>` — the
list view is the sole producer of those query strings.

The **Min Available** cell shows `spec.min_available`; the **Max Unavailable**
cell shows `spec.max_unavailable`; the **Allowed Disruptions** cell shows
`status.disruptions_allowed`. A PDB's spec has EXACTLY one of
`min_available` / `max_unavailable` (the k8s API enforces it); the absent one
renders `—` (4.1's `{{ pdp.min_available }}` renders blank — 5.0 renders
certainty). `status.disruptions_allowed` renders `—` when `status` is absent
or `disruptions_allowed` is missing (4.1 would `UndefinedError` — see
`adr.md` Deviations, verified against 4.1's Jinja 3.1.6). States: no cluster
selected → `No cluster selected.`; loading → `Loading pod disruption
budgets...`; error → red error line; empty list → `No pod disruption budgets
found` (first-class, not an error).

### R4 — The detail page

`/other-resource/pod-disruption-budget/data?name=<name>&namespace=<ns>` MUST
fetch the object with a **single `?name=&namespace=` request** (not 4.1's
list-then-filter). Empty `items` is a not-found **STATE** — pinned copy
`No PodDisruptionBudget '<name>' found`, muted, not an error. The page
renders:

- A CTable (Name / Created / Namespace / Selector / Eviction Policy /
  Labels / Annotations):
  - **Selector**: `spec.selector.match_labels` rendered as `key: value`
    lines, `—` when absent (4.1's Selector row; 4.1 read ONLY `match_labels`
    — the full selector is covered by the JSON block).
  - **Eviction Policy**: `spec.unhealthy_pod_eviction_policy` (k8s ≥ 1.29)
    rendered as lines, `—` when absent (4.1's Eviction Policy row; 4.1's
    tuple bug is dropped — see `adr.md`).
  - **Labels** and **Annotations** as key/value sub-tables
    (`No labels` / `No annotations` when empty).
  - **Created** is `formatTimestamp` of `metadata.creation_timestamp` (4.1's
    duplicate Creation row is collapsed to this one row).
- A **Status** table with header `Key / Value` and rows: `Allowed
  disruptions` (`status.disruptions_allowed`), `Current healthy`
  (`status.current_healthy`), `Desired` (the effective min —
  `spec.min_available` when set, else the computed floor
  `ceil(maxUnavailableRatio × current_healthy)` as in the k8s API, else
  `—`). A missing value renders `—`.
- A **Conditions** table with header `Type / Status / Reason / Message`, one
  row per `status.conditions[]` entry, `No conditions` when empty (4.1's
  dynamic-key Conditions table is replaced by this typed shape).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (JSON is a YAML subset; the
  truthful-classifier rule ratified for PriorityClassData 2026-10-28), style
  `anOldHope`.

Missing `name` param → `Error: pod disruption budget name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/other-resource/pod-disruption-budget` is removed from
`views/Stub/routes.ts`. The `_nav.tsx` leaf is UNCHANGED (path and label).
The data route is not a nav entry (same as priorityclass/data,
network-policy/data).

## Non-goals

- No create/edit/delete for PodDisruptionBudgets (read-only, as in 4.1 and as
  in every other 5.0 resource view to date).
- No `spec.selector.match_expressions` UI on the data page — 4.1 rendered
  only `match_labels`; the raw selector (including `match_expressions`) is in
  the full-object JSON block. Recorded as a 4.1 deviation in `adr.md`.
- No `status.expected_pods` / `status.observed_generation` rows on the Status
  table — 4.1's Status row showed Allowed/Current/Desired only. The full
  status is in the JSON block.
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace (4.1's `ns_select`); the all-namespaces list
  branch exists for the API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Pod Disruption Budget List` is the only smoke-relevant
  contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The data page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not a YAML dump.
3. Missing `spec.min_available` / `spec.max_unavailable` render `—` (the
   absent one of the pair — 4.1 rendered blank); missing
   `status.disruptions_allowed` / `status.current_healthy` render `—` (4.1
   would `UndefinedError` when `status` is absent — a fresh PDB).
4. `spec.unhealthy_pod_eviction_policy` is read as a proper list (4.1's
   `pdb.spec.unhealthy_pod_eviction_policy,` trailing-comma tuple bug is
   dropped — 4.1 iterated a 1-tuple, not the list).
5. 4.1's data-page duplicate `Creation` row (both `Created` and `Creation`
   showed the creation timestamp) is collapsed to one `Created` row.
6. 4.1's `trimAnnotations` (drop
   `kubectl.kubernetes.io/last-applied-configuration`) is NOT replicated —
   annotations render verbatim; the JSON block is the same, and 5.0 has no
   4.1 trim helper.
7. 4.1's dynamic-key Conditions table (header built from the first
   condition's keys, `thead`/`tbody` both malformed) is replaced by a typed
   `Type / Status / Reason / Message` table — the k8s condition shape is
   fixed; the raw list is in the JSON block.
