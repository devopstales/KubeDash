# IngressClass + GatewayClass Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-ingressclass-gatewayclass-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

This change resolves TWO nav leaves under Network, both "the class that names
the controller for a routing resource":

1. **`/network/ingress-class`** — a 4.1-parity port. 4.1 has real templates:
   `network/ingress-class.html.j2` (list: **Name / Controller / Created**) and
   `network/ingress-class-data.html.j2` (data: Name / Created / Annotations /
   Labels / Controller + a conditional **Parameters** table). IngressClass is a
   **cluster-scoped core API** (`ingressclasses`, group `networking.k8s.io`,
   v1); the 4.1 read is `k8sIngressClassListGet`
   (`4.1:src/kubedash/lib/k8s/network.py:15`):
   `NetworkingV1Api().list_ingress_class(_request_timeout=1)` — a generated
   core-API model, so the `to_dict` form is snake_case. The 5.0 nav has NO
   `/network/ingress-class` leaf and NO stub — the leaf is **ADDED** (a nav
   change, not a stub-removal).
2. **`/network/gateway-class`** — NEW (4.1 has no Gateway API). GatewayClass
   is a **cluster-scoped CRD** (`gatewayclasses`, group
   `gateway.networking.k8s.io`, v1). This change **owns the GatewayClass CRD
   seam** (ratified 2026-10-28 — the companion `ingress-gateway-api-views`
   spec, which also lists GatewayClasses in a tab, has NOT landed yet; this
   spec owns `list_gateway_classes`/`get_gateway_class` + the `_KINDS` row,
   and that spec reuses it / dedupes when it lands). The 5.0 nav has NO
   `/network/gateway-class` leaf — the leaf is **ADDED**.

Both kinds are **cluster-scoped** — the `list_nodes` / `list_priority_classes`
/ `list_runtime_classes` pattern (the namespace param is accepted and ignored
for IngressClass; the CRD's OWN scope is the authority for GatewayClass, which
is cluster-scoped). The data pages follow the ratified 5.0 shape: the 4.1
curated table + the full-object `JSON.stringify(item, null, 2)` block with the
`json` hljs grammar (the truthful-classifier rule ratified for
PriorityClassData, final review 2026-10-28).

Deliver: a real list + data pair at `/network/ingress-class` and
`/network/ingress-class/data` (the 4.1 port) and a real list + data pair at
`/network/gateway-class` and `/network/gateway-class/data` (NEW), so both nav
leaves resolve to first-class views.

## Requirements

### R1 — A SAR-gated IngressClass list endpoint

`GET /api/v1/clusters/<id>/resources/ingressclasses` MUST return the
IngressClass list (`kind: "ingressclasses"`, items in kubernetes `to_dict`
snake_case form, `metadata`/`spec`/`status` intact). The kind is
**cluster-scoped**: a `namespace` param is accepted and ignored (the
`list_nodes` / `list_priority_classes` pattern). The read is SAR-gated per
ADR-0004: `list` on `ingressclasses`, group `networking.k8s.io`, namespace
`None`; on deny the response is 403 `RBAC_DENIED` naming the resource, and
the SAR is asked BEFORE any K8s client call. An unbound user is 404 from the
binding gate. The kind identifier is the plural `ingressclasses`; the
singular `ingressclass` is rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=` lookup for IngressClass via the existing generic route

`GET /api/v1/clusters/<id>/resources/ingressclasses?name=<name>` MUST return
a 0/1-item list through the same generic route (`_GETTERS`): a hit is the
single object, a miss is `[]` (not a 404 — the data page renders a not-found
state). SAR-gated on `get` with namespace `None` (cluster-scoped). The
`?name=` branch's `namespace = "default"` fallback is irrelevant (the read
ignores namespace). No new HTTP route is added: the kind is wired through
`_KINDS` + `_GETTERS` only.

### R3 — A SAR-gated GatewayClass list endpoint (the owned CRD seam)

`GET /api/v1/clusters/<id>/resources/gatewayclasses` MUST return the
GatewayClass list (`kind: "gatewayclasses"`, items as **FULL custom objects**
— the raw `to_dict` with `metadata`/`spec`/`status` intact, camelCase, NOT the
lossy `CrdInstance` projection). The GatewayClass CRD is **cluster-scoped**;
the CRD's OWN served version + scope is the authority (the `get_crd_served`
pattern — the VPA/Cilium CRD seam). When the CRD is **absent** (Gateway API
not installed) the list MUST be `[]` — a first-class empty state, not an
error (the Cilium/VPA absence contract: CRD 404 → `served is None` → `[]`;
any other read failure → `ClusterUnreachableError` 502). The read is
SAR-gated per ADR-0004: `list` on `gatewayclasses`, group
`gateway.networking.k8s.io`, namespace `None` (cluster-scoped); on deny the
response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked
BEFORE the CRD read. An unbound user is 404 from the binding gate. The kind
identifier is the plural `gatewayclasses`; the singular `gatewayclass` is
rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

This change **owns** the `list_gateway_classes`/`get_gateway_class` service
methods + the `_KINDS`/`_GETTERS` rows (the companion `ingress-gateway-api-
views` spec, which has not landed, reuses / dedupes them).

### R4 — A `?name=` lookup for GatewayClass via the existing generic route

`GET /api/v1/clusters/<id>/resources/gatewayclasses?name=<name>` MUST return
a 0/1-item list through the same generic route (`_GETTERS`): a hit is the
single full object, a miss is `[]`. SAR-gated on `get` with namespace `None`
(cluster-scoped). CRD-absent is also `[]`. No new HTTP route is added.

### R5 — The IngressClass list page

`/network/ingress-class` MUST render a `KubeDataTable` of the cluster's
IngressClasses (cluster-scoped — no namespace selector applies) with columns
**Name / Controller / Created**. The card title is EXACTLY `IngressClass
List` (4.1's title, kept verbatim — the e2e-smoke contract). The Name cell
links to `/network/ingress-class/data?name=<name>` — the list view is the
sole producer of those query strings (cluster-scoped: NO `namespace` param).

- **Controller** = `spec.controller` (`—` when absent).
- **Created** = `formatTimestamp` of `metadata.creation_timestamp`.

States: no cluster selected → `No cluster selected.`; loading → `Loading
ingress classes...`; error → red error line; empty list → `No ingress classes
found` (first-class, not an error).

### R6 — The IngressClass detail page

`/network/ingress-class/data?name=<name>` MUST fetch the object with a
**single `?name=` request** (not 4.1's list-then-filter). Empty `items` is a
not-found **STATE** — pinned copy `No IngressClass '<name>' found`, muted,
not an error. The page renders:

- A CTable (Name / Created / Controller / Labels / Annotations):
  - **Controller** = `spec.controller` (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty), rendered VERBATIM (no `trimAnnotations` —
    the 4.1 inline last-applied-configuration filter is NOT replicated).
  - **Created** = `formatTimestamp` of `metadata.creation_timestamp`.
- A **Parameters** table (a CTable, `No parameters` when `spec.parameters` is
  absent) — the 4.1 conditional Parameters card. In the `to_dict` form,
  `spec.parameters` is a `LocalObjectReference`
  (`{ api_version, kind, name }`); the table renders the present fields
  (Kind / Name / API Version, each `—` when absent) — the 4.1 template
  iterated `parameters.items()` (the dict's keys), so 5.0 renders the same
  key/value rows.
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (style `anOldHope`).

Missing `name` param → `Error: ingress class name not provided`.

### R7 — The GatewayClass list page

`/network/gateway-class` MUST render a `KubeDataTable` of the cluster's
GatewayClasses (cluster-scoped — no namespace selector applies) with columns
**Name / Controller / Age**. The card title is EXACTLY `GatewayClass List`
(NEW — 4.1 had no Gateway API; the title follows the 5.0 `<Kind> List`
convention). The Name cell links to
`/network/gateway-class/data?name=<name>` — the list view is the sole
producer of those query strings (cluster-scoped: NO `namespace` param).

- **Controller** = `spec.controllerName` (`—` when absent).
- **Age** = the human-readable age from `metadata.creationTimestamp`
  (e.g. `3d`, `5h`, `2m`) — the 5.0 convention for cluster-scoped CRD lists
  (the Gateway API tabbed page in the companion spec uses the same).

States: no cluster selected → `No cluster selected.`; loading → `Loading
gateway classes...`; error → red error line; empty list → `No gateway classes
found` (this is ALSO the CRD-absent state — the page does not distinguish
"CRD absent" from "none exist", both render the same copy).

### R8 — The GatewayClass detail page

`/network/gateway-class/data?name=<name>` MUST fetch the object with a
**single `?name=` request**. Empty `items` is a not-found **STATE** — pinned
copy `No GatewayClass '<name>' found`, muted, not an error (this is ALSO the
CRD-absent state). The page renders:

- A CTable (Name / Controller / Created / Labels / Annotations):
  - **Controller** = `spec.controllerName` (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty), rendered VERBATIM.
  - **Created** = `formatTimestamp` of `metadata.creation_timestamp`.
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (style `anOldHope`).

Missing `name` param → `Error: gateway class name not provided`.

### R9 — Routing and nav

- `App.tsx` wires both view pairs (mirroring the priorityclass route block —
  the cluster-scoped pattern).
- The `/network/ingress-class` and `/network/gateway-class` leaves are
  **ADDED** to the Network group in `_nav.tsx` (after the Ingress leaf) —
  `leaf('IngressClass', '/network/ingress-class')` and
  `leaf('GatewayClass', '/network/gateway-class')` (4.1 had the IngressClass
  leaf in its menu but not as a 5.0 nav item; 4.1 had no Gateway API at all).
- No stub removal — neither path is in `views/Stub/routes.ts` (both are new
  leaves).
- The data routes are not nav entries.

## Non-goals

- No create/edit/delete for IngressClasses or GatewayClasses (read-only, as
  in 4.1 and as in every other 5.0 resource view to date; the converter's
  Apply in the companion spec is the only write path, and it is out of scope
  here).
- No `IngressClass` ↔ `Ingress` deep-link (4.1's Ingress list linked the
  IngressClass cell to `/network/ingress-class` via a hidden form; this spec
  is the destination, and the Ingress list's link is the companion
  `ingress-gateway-api-views` spec's concern).
- No Gateway API `Gateway` / `HTTPRoute` / `ReferenceGrant` views — those are
  the companion `ingress-gateway-api-views` spec's concern (this spec owns
  only the GatewayClass kind + seam).
- No all-namespaces LIST mode on any page (both kinds are cluster-scoped;
  there is only one list each).
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title strings `IngressClass List` and `GatewayClass List` are the only
  smoke-relevant contracts.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` query-param navigation (cluster-scoped — NO `?namespace=`); no
   4.1 hidden form / POST / `session['ns_select']`; no list-then-filter on
   the data page.
2. **`/network/gateway-class` is NEW** — 4.1 has no Gateway API at all (only
   IngressClass); the GatewayClass views + the owned CRD seam are 5.0
   additions, not a 4.1 port.
3. **This spec owns the GatewayClass CRD seam** (ratified 2026-10-28) — the
   companion `ingress-gateway-api-views` spec (not yet landed) reuses
   `list_gateway_classes`/`get_gateway_class` + the `_KINDS` row; when it
   lands, the shared method/row is deduplicated (not re-added).
4. **The IngressClass data GAINS the full-object JSON block** (4.1's data
   page had none — only the metadata table + the Parameters table).
5. **The GatewayClass list uses a human-readable Age column, not 4.1's
   Created timestamp** — 4.1 had no Gateway API; the Age convention follows
   the 5.0 cluster-scoped CRD list pattern (the companion spec's Gateway
   Classes tab uses the same). The full `creation_timestamp` is in the data
   page's Created row + the JSON block.
6. **`trimAnnotations` is NOT replicated** — annotations render verbatim
   (the JSON block has the full object, and 5.0 has no trim helper).
7. **The IngressClass data "Lables" typo (4.1's `ingress-class-data.html.j2`
   line 65) is not replicated** — 5.0 renders `Labels`.
8. **The Parameters table renders the `LocalObjectReference` fields
   explicitly** (Kind / Name / API Version), not 4.1's raw dict iteration —
   the `to_dict` form of `spec.parameters` is a `LocalObjectReference`
   (`{ api_version, kind, name }`), and rendering the present fields is the
   truthful display (4.1's `parameters.items()` iteration would render
   `api_version`/`kind`/`name` rows, which is the same content, but 5.0's
   explicit fields are clearer and handle the absent-field case with `—`).
9. **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
   `list_ingress_class`; 5.0's client uses the pool's configured timeout.
