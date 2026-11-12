# Cert-Manager + External Load Balancer Views — ADR

## Decision Summary

Port 4.1's two plugin views (`/plugins/cert-manager`,
`/plugins/external-loadbalancer`) to 5.0 as two Network-group views at
`/network/cert-manager` and `/network/external-loadbalancer` (the /plugins/ →
/network/ move, ratified 2026-10-29 — folded into Network, NOT a Plugins group
revived; ADR-0022's "minus Plugins" stays intact). Both are CRD-based 4-tab
list + per-type data views on the existing `get_crd_served` seam (the
VPA/Cilium pattern — the CRD's OWN served version + scope is the authority,
CRD-absent → `[]`, any other failure → 502). **Cert-Manager** reads 4
cert-manager.io/v1 CRDs (`clusterissuers` cluster-scoped, `issuers` /
`certificaterequests` / `certificates` namespaced) — the 4 tabs are Cluster
Issuer / Issuer / Certificate Request / Certificates. **External Load
Balancer** reads MetalLB (v1beta1) CRDs with a Cilium (v2alpha1) fallback
(ratified 2026-10-29 — the 4.1 provider-detection seam: try MetalLB, fall back
to Cilium, else empty; `bgpadvertisements` is MetalLB-only) — the 4 tabs are
IP Address Pools / L2 Advertisements / BGP Peers / BGP Advertisements. Each
returned external-LB item is tagged with a `provider` field (the view's `Type`
column). The data pages follow the ratified 5.0 shape: 4.1's curated per-type
metadata table + the full-object `JSON.stringify(item, null, 2)` block with the
`json` hljs grammar. The two nav leaves are ADDED to the Network group (with
the 4.1 `Beta` badge); the 4.1 `/plugins/...` routes are dropped; no stubs are
removed (neither path was a stub).

## Decision Context

- **The /plugins/ → /network/ move (ratified 2026-10-29).** ADR-0022 locked the
  5.0 nav as "4.1 parity minus Plugins" — the whole Plugins group was dropped.
  This change does NOT revive the Plugins group; it promotes the two CRD-backed
  plugin views into the existing Network group as two new leaves. The
  placement is a decision (recorded here), not a reversal of ADR-0022 — the
  *group* stays dropped; these two specific views are Network concerns (cert-
  manager issues certs for Ingress/Services; the external LB is the LB
  provider for Services). The other 4.1 plugins (registry, helm, flux,
  gateway-api, application-catalog, proxy) remain out of scope.
- **Both are CRD-based — the `get_crd_served` seam is the right fit.** 4.1
  hardcoded the `api_version` (`cert-manager.io/v1`, `metallb.io/v1beta1`,
  `cilium.io/v2alpha1`) and called `list_*_custom_object` directly, treating a
  404 as "empty." 5.0 uses the CRD's OWN served version + scope as the
  authority (`get_crd_served`), CRD-absent → `[]` (the first-class empty state
  — the plugin's CRDs aren't installed), any other failure →
  `ClusterUnreachableError` 502. This is the same seam as the VPA + Cilium
  kinds already in `_KINDS` — the 8 new kinds are additive rows on it.
- **The external-LB provider-detection is a first-class seam.** 4.1's `*Test`
  helper functions (try the MetalLB read, on error fall back to the Cilium
  read, else empty) are re-implemented INSIDE the `K8sClient` method:
  `get_crd_served("metallb.io", <plural>)` → if present, the namespaced
  MetalLB read; else `get_crd_served("cilium.io", <cilium-plural>)` → if
  present, the cluster-scoped Cilium read; else `[]`. The `bgpadvertisements`
  kind has no Cilium branch (no Cilium equivalent in 4.1). Each returned item
  is tagged with a `provider` field (`"metallb"` / `"cilium"`) — the view's
  `Type` column (4.1 hardcoded `type: "metallb"` / `"cilium"` per read; 5.0
  derives it from the detection).
- **The data page is a `?type=&name=&namespace=` fetch, not 4.1's form-POST.**
  4.1's data route was a POST that `ast.literal_eval(object_data)` the hidden-
  form object (the whole object was a form field). 5.0 re-fetches by
  `?type=&name=&namespace=` (a single `?name=` request, the house rule) — the
  `type` selects the CRD kind + the per-type metadata row set + the JSON
  block. No form, no `ast.literal_eval`, no `session['ns_select']`.
- **The per-type metadata table + the JSON block.** 4.1's data pages were a
  per-`object_type` metadata table only (no full-object block). 5.0 keeps the
  curated table (the 4.1 row set per type) and ADDS the full-object
  `JSON.stringify(item, null, 2)` block (the truthful-classifier rule ratified
  for PriorityClassData) — the data page shows the curated table AND the
  complete object (the provider-specific `spec` fields that the curated table
  doesn't surface).
- **The deep-links go to LANDED kinds only.** The Certificates Secret cell
  deep-links to the landed Secret data view (`/security/secret/data`); the
  Certificate Ingress-owner cell deep-links to the Ingress list only when that
  view is landed (the not-yet-landed `ingress-gateway-api-views` spec), else
  plain text (the "deep-link to landed kinds" pattern from the other 5.0
  ports).
- **The 4.1 label typos are fixed.** 4.1's menu label is `Cert-Manager` but
  its breadcrumb is `Cer-Manager` (a typo); 5.0 uses `Cert-Manager`
  consistently. 4.1's `GenerateIssuerData` classifies `spec.selfSigned` as
  `"Sel Signed"` (a typo); 5.0 renders `Self Signed`.
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  every CRD read; 5.0's client uses the pool's configured timeout (the house
  rule).

## ADR Manifest

| ADR | Relevance to this change |
|---|---|
| 0004 | Per-object SAR (`list` / `get` on the plural, the provider group, the namespace — `None` for the cluster-scoped `clusterissuers` + the Cilium fallbacks) gates all 8 reads; deny → 403 `RBAC_DENIED`, the SAR before the K8s call, the client call never made on deny. |
| 0009 | SSE is the push channel — not used by these read-only views (the list/data fetches are TanStack Query polls). |
| 0010 | Read path — the list/data fetches are per-request REST on the CRD seam (these are the resource views; the informer-cache read path applies to the watch-driven surfaces, not this generic route). |
| 0020 | Air-gap — no new npm/Python dependency; the views reuse `KubeDataTable` + `CTabs` + CoreUI + `react-syntax-highlighter` (the `json` grammar already registered). |
| 0021 | The cluster binding gate (404 unbound) and the local-admin/cluster model the SAR reads assume. |
| 0022 | **The nav placement this change works within** — ADR-0022 locked the nav as "4.1 parity minus Plugins"; this change keeps the Plugins group dropped and folds the two views into the existing Network group (two new leaves, the 4.1 `Beta` badge). The placement is a decision, not a reversal of the ADR. |

## Deviations (from 4.1)

1. **The paths move from `/plugins/...` to `/network/...`** (ratified
   2026-10-29) — the 4.1 routes are dropped; the views are re-implemented at
   `/network/cert-manager` + `/network/external-loadbalancer` and folded into
   the Network group (no Plugins group revived).
2. **`?name=` + `?namespace=` + `?type=` query-param navigation** — no 4.1
   hidden form / POST / `session['ns_select']` / `ast.literal_eval(object_data)`
   (the data page is a single `?name=` request, not 4.1's form-POST round-trip).
3. **The CRD reads use the 5.0 `get_crd_served` seam** — 4.1 hardcoded the
   `api_version` + called `list_*_custom_object` directly (404 → empty); 5.0
   uses the CRD's OWN served version + scope as the authority, CRD-absent →
   `[]` (first-class empty state), any other failure → 502.
4. **The data pages GAIN the full-object JSON block** (4.1's data pages had
   only the curated per-type metadata table).
5. **The external-LB provider detection is a first-class seam** — 4.1's `*Test`
   functions (try MetalLB, fall back to Cilium) are re-implemented inside the
   `K8sClient` method (the `get_crd_served` result picks the provider group +
   the namespaced/cluster-scoped call); the `Type` column shows the detected
   `provider` (`metallb` / `cilium`).
6. **The deep-links go to LANDED kinds only** — Secrets → the landed Secret
   data view; the Certificate Ingress-owner → the Ingress list only when that
   view is landed (the not-yet-landed `ingress-gateway-api-views` spec), else
   plain text.
7. **No per-request `_request_timeout=1`.** 5.0's client uses the pool's
   configured timeout.
8. **The 4.1 `Cer-Manager` breadcrumb typo is not replicated** — 5.0 uses
   `Cert-Manager` consistently (the menu label, not the breadcrumb typo).
9. **The 4.1 `Sel Signed` type-label typo is not replicated** — 5.0 renders
   `Self Signed` (the correct term).

## Out of Scope

- Create / edit / delete for any of the 8 CRD kinds (read-only, as in every
  other 5.0 resource view to date; 4.1's plugins are read-only too).
- Re-introduction of the Plugins nav group (the two views are folded into
  Network; the other 4.1 plugins — registry, helm, flux, gateway-api,
  application-catalog, proxy — remain out of scope).
- The MetalLB `communities` / `bfdprofiles` CRDs (4.1 reads them in
  `metallb.py` but the 4.1 template only exposes the 4 tabs — they are not
  surfaced in 4.1's UI; not ported).
- Cilium BGP Advertisements (no Cilium equivalent in 4.1 — the BGP
  Advertisements tab is MetalLB-only).
- The Ingress-owner deep-link in the Certificates tab (the Ingress view is the
  not-yet-landed `ingress-gateway-api-views` spec — the deep-link is added when
  it lands; until then plain text).
