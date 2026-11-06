# IngressClass + GatewayClass Views — ADR

## Decision Summary

Port 4.1's IngressClass views (`/network/ingress-class`) and add NEW
GatewayClass views (`/network/gateway-class`) as two SAR-gated, read-only,
cluster-scoped list + data pairs. IngressClass is a cluster-scoped core kind
(`networking.k8s.io/v1`) — the `list_nodes` / `list_priority_classes` /
`list_runtime_classes` pattern (the namespace is accepted and ignored), wired
through the existing generic route's `_KINDS`/`_GETTERS` with two new
`K8sClient` methods (`list_ingress_classes` / `get_ingress_class`) and ONE
new `__init__` attribute (`self._networking`, if absent). GatewayClass is a
cluster-scoped CRD (`gateway.networking.k8s.io/v1`) — the VPA/Cilium CRD seam
(`get_crd_served` version + scope authority, full custom object,
CRD-absent → `[]`), with two new `K8sClient` methods
(`list_gateway_classes` / `get_gateway_class`) and NO new `__init__`
attribute. **This change owns the GatewayClass seam** (ratified 2026-10-28 —
the companion `ingress-gateway-api-views` spec, which also lists
GatewayClasses in a tab, has NOT landed; it reuses / dedupes the shared
method + `_KINDS` row). Both nav leaves are **ADDED** to the Network group
(`/network/ingress-class` resolves a 4.1 port; `/network/gateway-class` is
NEW — 4.1 had no Gateway API). Data pages follow the ratified 5.0 shape: the
4.1 curated CTable + the full-object `JSON.stringify(item, null, 2)` block
with the `json` hljs grammar (the truthful-classifier rule ratified for
PriorityClassData, final review 2026-10-28).

## Decision Context

- **Two cluster-scoped kinds, one generic route.** Both IngressClass and
  GatewayClass are cluster-scoped — no namespace selector, no `?namespace=`
  on the list or data URLs. The existing generic resource route already
  serves list AND `?name=` for a kind via `_KINDS`/`_GETTERS`; this change
  adds two kinds. IngressClass is a core API (a `NetworkingV1Api` generated
  model, `to_dict` snake_case); GatewayClass is a CRD (full custom object,
  camelCase). The cluster-scoped pattern is established: IngressClass mirrors
  `list_runtime_classes` / `get_runtime_class`; GatewayClass mirrors the VPA
  seam's cluster-scoped branch.
- **The owned GatewayClass seam.** The companion `ingress-gateway-api-views`
  spec (a tabbed page whose first tab is GatewayClasses) owns the full
  Gateway API read surface (Gateway / HTTPRoute / ReferenceGrant) but has NOT
  landed. This spec is the only landed owner of the GatewayClass kind, so it
  owns `list_gateway_classes` / `get_gateway_class` + the `_KINDS` row —
  flagged in the method docstrings so the companion spec dedupes rather than
  re-adds. The standalone `/network/gateway-class` leaf is canonical; the
  companion spec's GatewayClasses tab links to it when both ship.
- **The IngressClass data GAINS the JSON block.** 4.1's data page had only
  the metadata table + the Parameters table — no full-object block. The
  ratified 5.0 shape adds the `JSON.stringify(item, null, 2)` block (the
  truthful-classifier rule): the data page shows the curated table AND the
  complete object.
- **The Parameters table.** 4.1's data page rendered a conditional Parameters
  table by iterating `parameters.items()` (the dict's keys). In the
  `to_dict` form, `spec.parameters` is a `LocalObjectReference`
  (`{ api_version, kind, name }`). 5.0 renders the present fields explicitly
  (Kind / Name / API Version, `—` when absent) — the same content, clearer,
  and it handles the absent-field case.
- **`trimAnnotations` not replicated; the "Lables" typo not replicated.** The
  4.1 data template's inline last-applied-configuration filter and the
  "Lables" typo (line 65) are 4.1 artifacts; 5.0 renders annotations
  verbatim and the label row as "Labels".
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  `list_ingress_class`; 5.0's client uses the pool's configured timeout (the
  house rule ratified across the 4.1→5.0 ports).

## ADR Manifest

| ADR | Relevance to this change |
|---|---|
| 0004 | Per-object SAR (`list` / `get` on the kind, cluster-scoped namespace `None`) gates both the IngressClass read (`networking.k8s.io`) and the GatewayClass read (`gateway.networking.k8s.io`); deny → 403 `RBAC_DENIED`, the SAR before the K8s call, the client call never made on deny. |
| 0009 | SSE is the push channel — not used by these read-only views (the list fetches are TanStack Query polls). |
| 0010 | Read path — the list/data fetches are per-request REST (these are the resource views; the informer-cache read path applies to the watch-driven surfaces, not this generic route). |
| 0020 | Air-gap — no new npm/Python dependency; the views reuse `KubeDataTable` + CoreUI + `react-syntax-highlighter` (the `json` grammar already registered). |
| 0021 | The cluster binding gate (404 unbound) and the local-admin/cluster model the SAR reads assume. |
| 0022 | The Network group nav shape the two leaves are ADDED to (4.1 parity structure, Plugins group dropped). |

## Deviations (from 4.1)

1. **`?name=` query-param navigation** (cluster-scoped — NO `?namespace=`);
   no 4.1 hidden form / POST / `session['ns_select']`; no list-then-filter on
   the data page (a single `?name=` request).
2. **`/network/gateway-class` is NEW** — 4.1 has no Gateway API at all; the
   GatewayClass views + the owned CRD seam are 5.0 additions.
3. **This spec owns the GatewayClass CRD seam** (ratified 2026-10-28) — the
   companion `ingress-gateway-api-views` spec (not yet landed) reuses
   `list_gateway_classes` / `get_gateway_class` + the `_KINDS` row; deduped,
   not re-added, when it lands.
4. **The IngressClass data GAINS the full-object JSON block** (4.1 had only
   the metadata + Parameters tables).
5. **The GatewayClass list uses a human-readable Age column** (not a Created
   timestamp) — the 5.0 cluster-scoped CRD list convention (the companion
   spec's Gateway Classes tab uses the same); the full timestamp is in the
   data page + JSON block.
6. **`trimAnnotations` is NOT replicated** — annotations render verbatim.
   **OVERRIDE 2026-11-05 (user decision, the storage-batch T2):** the trim IS
   now replicated — the two machine-managed keys
   (`kubectl.kubernetes.io/last-applied-configuration`,
   `autoscaling.alpha.kubernetes.io/conditions`) are dropped from the
   rendered annotations table (the HPA view already trims, 46929a10; the
   JSON block still renders the full object).
7. **The 4.1 "Lables" typo is not replicated** — 5.0 renders "Labels".
8. **The Parameters table renders the `LocalObjectReference` fields
   explicitly** (Kind / Name / API Version), not 4.1's raw dict-key
   iteration.
9. **No per-request `_request_timeout=1`.** 5.0's client uses the pool's
   configured timeout.

## Out of Scope

- Create / edit / delete for IngressClasses or GatewayClasses (read-only;
  the companion spec's converter Apply is the only write path, out of scope
  here).
- `Gateway` / `HTTPRoute` / `ReferenceGrant` views (the companion
  `ingress-gateway-api-views` spec's concern).
- The `Ingress` ↔ `IngressClass` deep-link (the companion
  `ingress-gateway-api-views` spec's Ingress list owns that link; this spec
  is the destination).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations #1) is
**SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation`
(ADR-0040): object identity lives in tab-private `sessionStorage` (the
`kd_object_refs` registry + `kd_object_active` pointer); list name cells open
the detail via `openObject(...)`; the URL never carries object identity. The
backend REST `?name=` filtering param on
`/api/v1/clusters/:id/resources/<kind>` is unchanged (GET filtering, not
navigation).

## Execution Notes (2026-11-06)

The frontend executed per the 2026-10-29 session-object-navigation contract
(the blueprint's `/.../data?name=` route shape is not built):

- ONE clean route per kind — `/network/ingress-class` and
  `/network/gateway-class` — each an `ObjectRoute` (list when no active ref,
  detail when the ref's registry kind matches: `ingressclass` /
  `gatewayclass`). NO `/.../data` route, NO `OldDataRedirect`: both kinds
  were unshipped (no 4.1-parity URL and no 5.0 stub ever served a `/data`
  URL), so there is no legacy route to redirect.
- The data views trim machine-managed annotations (the 2026-11-05 T2
  override recorded in Deviations #6), not the 2026-10-28 "render verbatim"
  deviation.
