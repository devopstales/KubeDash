# RuntimeClass Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-runtimeclass-views`
**Date:** 2026-10-28
**Backlog:** TASK-046
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `Runtime Class` leaf (`/other-resource/runtimeclass`,
`_nav.tsx:116`) that currently renders the placeholder stub
(`views/Stub/routes.ts:28`). The 4.1 codebase has **no RuntimeClass
template** — its nav pointed at a nonexistent template (a dead link); in 4.1
the kind appears only in the RBAC template ClusterRoles (`runtimeclasses` in
the reader/admin resource lists, `4.1:src/kubedash/functions/k8s.py`).

"Based on 4.1" therefore means: 4.1's **placement** (Other Resources — the
ratified deviation, ADR-0022, 2026-10-27) and 4.1's **RBAC treatment**
(`runtimeclasses` is cluster-scoped, `node.k8s.io/v1`, listed in the reader
ClusterRole). The page **shape** follows the ratified 5.0 precedent, not a
4.1 template: PriorityClass (list + data, both cluster-scoped, same
`other-resources` group) for the views, and TASK-032 (CRDs) for the
`_KINDS`/SAR wiring pattern.

Deliver: a real list page and a real detail page at
`/other-resource/runtimeclass` and `/other-resource/runtimeclass/data`,
removing the stub, so the nav leaf resolves to first-class views.

## Requirements

### R1 — A SAR-gated RuntimeClass list endpoint

`GET /api/v1/clusters/<id>/resources/runtimeclasses` MUST return the
RuntimeClass list (`kind: "runtimeclasses"`, items in kubernetes `to_dict`
snake_case form) from the cluster's client. The read is SAR-gated per
ADR-0004: `list` on `runtimeclasses`, group `node.k8s.io`, namespace `None`
(cluster-scoped); on deny the response is 403 `RBAC_DENIED` naming the
resource, and the SAR is asked BEFORE any K8s client call. An unbound user is
404 from the binding gate (the existing `_cluster_for` behavior). The kind
identifier is the plural `runtimeclasses`; the singular `runtimeclass` is
rejected with `RESOURCE_KIND_NOT_SUPPORTED` (mirrors
`test_priorityclass_kind_singular_rejected`).

### R2 — A `?name=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/runtimeclasses?name=<name>` MUST return
a 0/1-item list through the same generic route (`_GETTERS`): a hit is the
single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` (cluster-scoped, namespace `None`). No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — The list page

`/other-resource/runtimeclass` MUST render a `KubeDataTable` with columns
**Name / Handler / Overwrite Node Sel No Toleration / Pod Level Overhead /
Created**. The card title is EXACTLY `Runtime Classes` (the e2e smoke
convention from the PriorityClass precedent). The Name cell links to
`/other-resource/runtimeclass/data?name=<name>` — the list view is the sole
producer of those query strings. `Pod Level Overhead` renders
`<cpu> / <memory>` (e.g. `100m / 128Mi`) or `—` when the field is absent.
States: no cluster selected → `No cluster selected.`; loading →
`Loading runtime classes...`; error → red error line; empty list →
`No runtime classes found` (first-class, not an error).

### R4 — The detail page

`/other-resource/runtimeclass/data?name=<name>` MUST fetch the object with a
**single `?name=` request** (not 4.1's list-then-filter). The read carries no
namespace param (cluster-scoped). Empty `items` is a not-found **STATE** —
pinned copy `No RuntimeClass '<name>' found`, muted, not an error. The page
renders a CTable (Name / Kind / Created / Handler / Overwrite Node Sel No
Toleration / Pod Level Overhead / Labels / Annotations) plus the full object
as a syntax-highlighted block: `JSON.stringify(item, null, 2)` with the
`json` hljs grammar (JSON is a YAML subset; the truthful-classifier rule
ratified for PriorityClassData in the final review 2026-10-28), style
`anOldHope`. Missing `name` param → `Error: runtime class name not provided`.

### R5 — Routing and stub removal

`App.tsx` wires both views (mirroring the priorityclass route block).
`/other-resource/runtimeclass` is removed from `views/Stub/routes.ts`. The
`_nav.tsx` leaf is UNCHANGED (path and label). The data route is not a nav
entry (same as priorityclass/data).

## Non-goals

- No create/edit/delete for RuntimeClasses (read-only, as in 4.1 and as in
  every other 5.0 resource view to date).
- No new API path beyond the kind wiring — no `/runtimeclasses/instances`-
  style sub-route (RuntimeClass has no children).
- No pod→runtimeclass linkage (which pods use a class) — out of scope; the
  pod view does not exist in 5.0 yet.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Runtime Classes` is the only smoke-relevant contract.
- No RBAC **template** change: the built-in ClusterRole templates already
  carry `runtimeclasses` (4.1 parity verified); no migration, no seed change.

## Ratified deviations (recorded; see `adr.md` → Deviations)

1. 4.1 had no RuntimeClass page — the list+data shape follows the 5.0
   PriorityClass precedent, not a 4.1 template.
2. Placement under **Other Resources** per ADR-0022 (2026-10-27).
3. `?name=` query-param navigation; no 4.1 sessionStorage/hidden-form
   workarounds (the Namespaces/Nodes/CRDs decision).
4. The detail page's full-object block is **JSON** text with the `json` hljs
   grammar (truthful classifier), not YAML.
