# Cert-Manager + External Load Balancer Views (moved from /plugins/ to /network/) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-29-certmanager-external-loadbalancer-views`
**Date:** 2026-10-29
**Backlog:** TBD (created with the spec commit)
**ADR:** ADR-0022 locked the 5.0 nav as "4.1 parity **minus Plugins**" — this
change promotes the two CRD-backed plugin views into the Network group. That
placement decision is recorded in `adr.md` (it does not reverse ADR-0022's
"minus Plugins" — the *group* stays dropped; these two specific views are
promoted into Network, not a Plugins group revived). No other new ADR.

## Intent

4.1 ships two **plugin** views under `/plugins/` (the `Plugins` nav group,
gated by `config.plugins[...]`):

1. **`/plugins/cert-manager`** — a 4-tab page over the **cert-manager.io/v1**
   CRDs. 4.1 source: `src/kubedash/plugins/cert_manager/` (`__init__.py` the
   routes, `functions.py` the four reads, `helper.py` `GenerateIssuerData`,
   `templates/cert-manager.html.j2` the 4-tab list,
   `templates/cert-manager-data.html.j2` the per-type data). The four tabs:
   **Cluster Issuer** (cluster-scoped `clusterissuers`), **Issuer**
   (namespaced `issuers`), **Certificate Request** (namespaced
   `certificaterequests`), **Certificates** (namespaced `certificates`). Each
   tab is a table (Status / Name / Type-or-Issuer-or-Secret / Owner); the data
   page is a per-`object_type` metadata table (4.1 passes the whole object as
   a hidden form field — `ast.literal_eval(object_data)`).
2. **`/plugins/external-loadbalancer`** — a 4-tab page over **MetalLB OR
   Cilium** LB CRDs (a provider-detection seam: try MetalLB, fall back to
   Cilium, else empty). 4.1 source:
   `src/kubedash/plugins/external_loadbalancer/` (`__init__.py` the routes,
   `metallb.py` the 4 MetalLB reads, `cilium.py` the 3 Cilium reads,
   `helper.py` the provider-detection `*Test` functions, `templates/` the
   4-tab list + per-type data). The four tabs: **IP Address Pools** (MetalLB
   `ipaddresspools` / Cilium `ciliumloadbalancerippools`), **L2 Advertisements**
   (MetalLB `l2advertisements` / Cilium `ciliuml2announcementpolicies`),
   **BGP Peers** (MetalLB `bgppeers` / Cilium `ciliumbgppeeringpolicies`),
   **BGP Advertisements** (MetalLB `bgpadvertisements` — MetalLB only, no
   Cilium equivalent). Each tab is a table (Type / Name / <kind-specific>); the
   data page is a per-`object_type` metadata table.

**5.0 has NO Plugins group** (ADR-0022 dropped it) and **no stubs** for either
path (neither is in `views/Stub/routes.ts`). This change **moves** the two
plugin views into the **Network** group as two new nav leaves:
`/network/cert-manager` and `/network/external-loadbalancer` (ratified
2026-10-29 — folded into Network, NOT a Plugins group revived). The 4.1
`/plugins/...` routes are dropped (the views are re-implemented at the new
`/network/...` paths; the 4.1 plugin blueprint + Jinja templates are the
source of truth for the page shapes, not a carried-over module).

Both views are **CRD-based** — they read custom resources via the 5.0
`get_crd_served` seam (the VPA/Cilium CRD pattern: the CRD's OWN served
version + scope is the authority, CRD-absent → `[]` first-class empty state,
any other read failure → `ClusterUnreachableError` 502). The data pages follow
the ratified 5.0 shape: 4.1's curated per-type metadata table + the full-object
`JSON.stringify(item, null, 2)` block with the `json` hljs grammar (the
truthful-classifier rule ratified for PriorityClassData, final review
2026-10-28).

Deliver: a real 4-tab list + per-type data at `/network/cert-manager`
(resolving the cert-manager.io CRDs) and a real 4-tab list + per-type data at
`/network/external-loadbalancer` (resolving the MetalLB/Cilium LB CRDs, provider-
detected), so the two 4.1 plugin views resolve to first-class Network-group
views.

## Requirements

### R1 — A SAR-gated cert-manager.io CRD read seam (4 kinds)

The backend MUST read the four cert-manager.io/v1 CRDs through the
`get_crd_served` seam (the VPA/Cilium pattern — `self._custom` +
`get_crd_served(group, plural)`, the CRD's OWN served version + scope is the
authority, CRD-absent → `[]`):
- **`clusterissuers`** (cluster-scoped) — `list_cluster_custom_object`.
- **`issuers`** (namespaced) — `list_namespaced_custom_object`.
- **`certificaterequests`** (namespaced) — `list_namespaced_custom_object`.
- **`certificates`** (namespaced) — `list_namespaced_custom_object`.

Each read is SAR-gated per ADR-0004: `list` on the plural, group
`cert-manager.io`, the namespace (`None` for the cluster-scoped `clusterissuers`,
the query namespace for the namespaced kinds); on deny → 403 `RBAC_DENIED`
naming the resource, the SAR before the K8s call; unbound → 404. The reads
return FULL custom objects (camelCase, `spec`/`status` intact — the wire form,
like the VPA/Cilium CRDs, NOT a lossy projection). The per-`?name=` lookups
return a 0/1-item list (hit = the full object, miss = `[]`, CRD-absent = `[]`).

**Shape:** these are CRD kinds on the existing generic resource route
(`_KINDS`/`_GETTERS`), the same as the VPA/Cilium kinds — the kind identifiers
are the plurals (`clusterissuers`, `issuers`, `certificaterequests`,
`certificates`); the singular forms are rejected with
`RESOURCE_KIND_NOT_SUPPORTED`. NO new HTTP route — the kinds are wired through
`_KINDS` + `_GETTERS` + the four `K8sClient` list/get method pairs.

### R2 — The Cert-Manager list page (the 4-tab shape)

`/network/cert-manager` MUST render a 4-tab page (CoreUI `CTabs`) titled
`Cert-Manager Objects` (4.1's card title, kept verbatim — the e2e-smoke
contract). The four tabs (the 4.1 order): **Cluster Issuer** / **Issuer** /
**Certificate Request** / **Certificates**. Each tab is a `KubeDataTable` of
the CRD's items (cluster-scoped tab: no namespace selector applies; namespaced
tabs: the selected namespace):

- **Cluster Issuer** tab (columns Status / Name / Type): Status = the last
  `status.conditions[]` entry's `reason` (badge: green when `status == "True"`,
  red otherwise — 4.1's mapping); Name links to
  `/network/cert-manager/data?type=cluster_issuer&name=<name>` (cluster-scoped:
  NO namespace param); Type = the issuer type (the 4.1 `GenerateIssuerData`
  classification: `Sel Signed` / `CA` / `ACME` / `Vault` — derived from
  `spec.selfSigned` / `spec.ca` / `spec.acme` / `spec.vault`).
- **Issuer** tab (columns Status / Name / Type): same as Cluster Issuer but
  namespaced; Name links to
  `/network/cert-manager/data?type=issuer&name=<name>&namespace=<ns>`.
- **Certificate Request** tab (columns Status / Name / Issuer / Owner): Status
  = the last `status.conditions[]` `reason` (badge); Name links to
  `/network/cert-manager/data?type=certificate_request&name=<name>&namespace=<ns>`;
  Issuer = `spec.issuerRef` (`<kind>/<name>`, a link to the matching Issuer /
  Cluster Issuer tab — 4.1's `goToTab` in-page tab switch, 5.0 re-implements it
  as a tab-switch + row-highlight); Owner = the last `metadata.ownerReferences`
  (`<kind>/<name>`, plain text).
- **Certificates** tab (columns Status / Name / Secret / Owner): Status = the
  last `status.conditions[]` `reason` (badge); Name links to
  `/network/cert-manager/data?type=certificate&name=<name>&namespace=<ns>`;
  Secret = `spec.secretName` (deep-link to the landed Secret data view
  `/security/secret/data?name=<n>&namespace=<ns>` — the "deep-link to landed
  kinds" pattern); Owner = the last `metadata.ownerReferences` (`<kind>/<name>`;
  a link to the Ingress list when `kind == "Ingress"` and the Ingress view is
  landed, else plain text — the Ingress view is the not-yet-landed
  `ingress-gateway-api-views` spec).

States: no cluster selected → `No cluster selected.`; no namespace selected
(namespaced tabs) → the namespace selector state; loading → `Loading cert-
manager objects...`; error → red error line; empty tab → the per-tab empty
state (`No cluster issuers found` / `No issuers found` / `No certificate
requests found` / `No certificates found` — first-class, NOT an error; CRD-
absent renders the SAME empty state).

### R3 — The Cert-Manager data page (the per-type shape + JSON block)

`/network/cert-manager/data?type=<t>&name=<name>[&namespace=<ns>]` MUST fetch
the object with a **single `?name=` request** (the `type` selects the CRD kind
+ scope). Empty `items` is a not-found **STATE** — pinned copy `No <type>
'<name>' found` (muted, not an error; also the CRD-absent state). The card
title is `Cert-Manager <Type>` (e.g. `Cert-Manager Cluster Issuer`). The page
renders the 4.1 per-`object_type` metadata CTable:

- **Cluster Issuer / Issuer**: Name / Status (badge) / Status message (the
  last `status.conditions[]` `message`) / Issuer Type (the 4.1 classification)
  / Issuer Data (the 4.1 `GenerateIssuerData` `issuer_data` — the `CA` secret /
  `ACME` email+server+challenges / `Vault` auth detail / `Sel Signed` (none)).
  Cluster Issuer has the `Issuer Type` row; Issuer does not (4.1's shape).
- **Certificate Request**: Name / Status (badge) / Status message / Issuer
  (`spec.issuerRef` `<kind>/<name>`) / Owner (the last `ownerReferences`
  `<kind>/<name>`).
- **Certificate**: Name / Status (badge) / Status message / Validity Not After
  (`status.notAfter`) / Certificate (`spec.secretName`, deep-link to the
  landed Secret data view) / Hostnames (`spec.dnsNames`, one per line).

Below the table: the full object as a syntax-highlighted block:
`JSON.stringify(item, null, 2)` with the `json` hljs grammar (style
`anOldHope`). Missing `name` param → `Error: <type> name not provided`.

### R4 — A SAR-gated external-LB CRD read seam (MetalLB primary + Cilium fallback)

The backend MUST read the external-LB CRDs through the `get_crd_served` seam
with a **provider-detection** rule (ratified 2026-10-29 — faithful 4.1: try
MetalLB, fall back to Cilium, else empty):
- **IP Address Pools**: MetalLB `ipaddresspools` (namespaced, `metallb.io/v1beta1`)
  **primary**; on CRD-absent, fall back to Cilium
  `ciliumloadbalancerippools` (cluster-scoped, `cilium.io/v2alpha1`); both
  absent → `[]`.
- **L2 Advertisements**: MetalLB `l2advertisements` (namespaced,
  `metallb.io/v1beta1`) **primary**; fall back to Cilium
  `ciliuml2announcementpolicies` (cluster-scoped, `cilium.io/v2alpha1`); both
  absent → `[]`.
- **BGP Peers**: MetalLB `bgppeers` (namespaced, `metallb.io/v1beta1`)
  **primary**; fall back to Cilium `ciliumbgppeeringpolicies` (cluster-scoped,
  `cilium.io/v2alpha1`); both absent → `[]`.
- **BGP Advertisements**: MetalLB `bgpadvertisements` (namespaced,
  `metallb.io/v1beta1`) **only** (no Cilium equivalent in 4.1); absent → `[]`.

Each read is SAR-gated per ADR-0004: `list` on the served plural, the provider
group, the namespace (`None` for the cluster-scoped Cilium fallback, the query
namespace for the namespaced kinds); deny → 403, the SAR before the K8s call;
unbound → 404. The reads return FULL custom objects (camelCase, `spec`/`status`
intact) tagged with a `provider` field (`"metallb"` / `"cilium"`) so the view
can render the `Type` column. The per-`?name=` lookups return a 0/1-item list.

**Shape:** four kinds on the generic resource route (`_KINDS`/`_GETTERS`) —
`ipaddresspools`, `l2advertisements`, `bgppeers`, `bgpadvertisements` — each a
provider-detecting `K8sClient` method pair (list + get). The provider group
+ the namespaced/cluster-scoped call are chosen inside the method by the
`get_crd_served` result (MetalLB present → the namespaced MetalLB call; else
Cilium present → the cluster-scoped Cilium call; else `[]`).

### R5 — The External Load Balancer list page (the 4-tab shape)

`/network/external-loadbalancer` MUST render a 4-tab page (CoreUI `CTabs`)
titled `LoadBalancer Objects` (4.1's card title, kept verbatim — the e2e-smoke
contract). The four tabs (the 4.1 order): **IP Address Pools** / **L2
Advertisements** / **BGP Peers** / **BGP Advertisements**. Each tab is a
`KubeDataTable` (Type / Name / <kind-specific column>):

- **IP Address Pools** tab (Type / Name / Addresses): Type = the `provider`
  (`metallb` / `cilium`); Name links to
  `/network/external-loadbalancer/data?type=ipaddresspool&name=<name>[&namespace=<ns>]`;
  Addresses = the pool's address range (MetalLB `spec.addresses` / Cilium
  `spec.cidrs` — the provider-specific field, the same column for both).
- **L2 Advertisements** tab (Type / Name / Pools): Type = the `provider`; Name
  links to `/network/external-loadbalancer/data?type=l2advertisement&name=<name>
  [&namespace=<ns>]`; Pools = the pool references (MetalLB
  `spec.ipAddressPools` / Cilium `spec.serviceSelector` — the provider-
  specific "what this L2 policy applies to" field).
- **BGP Peers** tab (Type / Name / Peer): Type = the `provider`; Name links to
  `/network/external-loadbalancer/data?type=bgppeers&name=<name>[&namespace=<ns>]`;
  Peer = the peer identity (MetalLB `spec.peerAddress` / Cilium the first
  `spec.virtualRouters[].neighbors[].peerAddress` — the provider-specific
  peer field).
- **BGP Advertisements** tab (Type / Name / Pools): Type = the `provider`
  (always `metallb` — no Cilium equivalent); Name links to
  `/network/external-loadbalancer/data?type=bgpadvertisement&name=<name>&namespace=<ns>`;
  Pools = `spec.ipAddressPools`.

States: no cluster → `No cluster selected.`; no namespace (namespaced tabs) →
the selector state; loading → `Loading load-balancer objects...`; error → red
error line; empty tab → the per-tab empty state (`No IP address pools found` /
`No L2 advertisements found` / `No BGP peers found` / `No BGP advertisements
found` — first-class; both-providers-absent renders the SAME empty state).

### R6 — The External Load Balancer data page (the per-type shape + JSON block)

`/network/external-loadbalancer/data?type=<t>&name=<name>[&namespace=<ns>]`
MUST fetch the object with a **single `?name=` request** (the `type` selects
the CRD kind + the provider). Empty `items` is a not-found **STATE** — pinned
copy `No <type> '<name>' found` (muted; also the CRD-absent state). The card
title is `<Type> Objects` (4.1's shape, e.g. `ipaddresspool Objects`). The page
renders the 4.1 per-`object_type` metadata CTable (the provider-specific rows):

- **IP Address Pools** (Type + the provider rows): MetalLB → Addresses / Auto
  assign / Avoid buggy IPs / Allocation Namespaces / Allocation Namespace
  Selectors / Service Selectors / Allocation Service Selectors (the 4.1
  `serviceAllocation` fields, `—` when absent); Cilium → Blocks (`spec.cidrs`)
  / Allow First Last IPs / Disabled / IP Family Policy / IP Families (the
  provider-specific fields).
- **L2 Advertisements** (Type + the provider rows): MetalLB → IP Address Pools
  / Interfaces / Node Selectors / IP Address Pool Selectors; Cilium → Service
  Selector / Node Selector / Interfaces / External IPs / Load Balancer IPs.
- **BGP Peers** (Type + the provider rows): MetalLB → My ASN / Peer Address /
  Peer ASN / Node Selectors (+ the optional `sourceAddress`/`peerPort`/
  `holdTime`/`keepaliveTime`/`connectTime`/`routerID`/`vrf`/`ebgpMultiHop`/
  `disableMP`/`passwordSecret`/`bfdProfile`, `—` when absent); Cilium → the
  `virtualRouters` (localASN / exportPodCIDR / neighbors with peerAddress /
  peerASN).
- **BGP Advertisements** (Type = `metallb` + the rows): Aggregation Length /
  Aggregation Length V6 / Local Pref / Communities / IP Address Pools / IP
  Address Pool Selectors / Node Selectors / Peers (the 4.1 `bgpadvertisements`
  fields, `—` when absent).

Below the table: the full-object JSON block. Missing `name` param →
`Error: <type> name not provided`.

### R7 — Routing + nav (the /plugins/ → /network/ move)

- `App.tsx` wires both view pairs (the cert-manager list + data; the external-
  loadbalancer list + data) as `ProtectedRoute` views.
- The two nav leaves are **ADDED** to the Network group in `_nav.tsx`
  (after the Ingress leaf): `leaf('Cert-Manager', '/network/cert-manager')`
  (with the 4.1 `Beta` badge) and `leaf('External Load Balancer',
  '/network/external-loadbalancer')` (with the 4.1 `Beta` badge). NO new
  Plugins group (ratified 2026-10-29 — folded into Network; ADR-0022's "minus
  Plugins" stays intact).
- No stub removal — neither `/network/cert-manager` nor
  `/network/external-loadbalancer` is in `views/Stub/routes.ts` (both are new
  leaves; the 4.1 `/plugins/...` paths are dropped, not stubs).
- The data routes are not nav entries.

## Non-goals

- No create / edit / delete for any of the 8 CRD kinds (read-only, as in every
  other 5.0 resource view to date; 4.1's plugins are read-only too).
- No re-introduction of the Plugins nav group (ratified 2026-10-29 — the two
  views are folded into Network; the other 4.1 plugins — registry, helm, flux,
  gateway-api, application-catalog, proxy — remain out of scope, still under
  the dropped Plugins group).
- No MetalLB `communities` / `bfdprofiles` CRDs (4.1 reads them in
  `metallb.py` but the 4.1 template only exposes the 4 tabs — `communities`
  and `bfdprofiles` are not surfaced in 4.1's UI; not ported).
- No Cilium BGP Advertisements (no Cilium equivalent in 4.1 — the BGP
  Advertisements tab is MetalLB-only).
- No in-page deep-link of the Certificate Request Issuer cell to a different
  tab's row (4.1's `goToTab` JS tab-switch + row-highlight) — 5.0 re-implements
  it as a tab-switch + row-highlight (the same UX, the 5.0 `CTabs` API).
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title strings `Cert-Manager Objects` and `LoadBalancer Objects` are the only
  smoke-relevant contracts.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. **The paths move from `/plugins/...` to `/network/...`** (ratified
   2026-10-29) — the 4.1 `/plugins/cert-manager` + `/plugins/external-
   loadbalancer` routes are dropped; the views are re-implemented at
   `/network/cert-manager` + `/network/external-loadbalancer` and folded into
   the Network group (no Plugins group revived — ADR-0022's "minus Plugins"
   stays intact).
2. **`?name=` + `?namespace=` + `?type=` query-param navigation** — no 4.1
   hidden form / POST / `session['ns_select']` / `ast.literal_eval(object_data)`
   (4.1 passed the whole object as a hidden form field; 5.0 re-fetches by
   `?type=&name=&namespace=`). The data page is a single `?name=` request (not
   4.1's form-POST round-trip).
3. **The CRD reads use the 5.0 `get_crd_served` seam** — 4.1 hardcoded the
   `api_version` (`cert-manager.io/v1`, `metallb.io/v1beta1`, `cilium.io/
   v2alpha1`) and the `list_*_custom_object` calls; 5.0 uses the CRD's OWN
   served version + scope as the authority (the VPA/Cilium pattern), CRD-
   absent → `[]` (first-class empty state), any other failure → 502.
4. **The data pages GAIN the full-object JSON block** (4.1's data pages had
   none — only the curated per-type metadata table).
5. **The external-LB provider detection is a first-class seam** — 4.1's
   `*Test` functions (try MetalLB, fall back to Cilium) are re-implemented as
   the `K8sClient` method's provider-detection (the `get_crd_served` result
   picks the provider group + the namespaced/cluster-scoped call); the `Type`
   column shows the detected provider (`metallb` / `cilium`).
6. **The Certificate Secret + the Certificate Ingress-owner deep-link to
   LANDED kinds only** (Secrets → the landed Secret data view; Ingress owner →
   the Ingress list only when that view is landed, else plain text) — the same
   "deep-link to landed kinds" pattern as the other 5.0 ports.
7. **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
   every CRD read; 5.0's client uses the pool's configured timeout.
8. **The 4.1 `Cert-Manager` nav label keeps its hyphen** (4.1's menu label is
   `Cert-Manager`; the breadcrumb is `Cer-Manager` — a 4.1 typo; 5.0 uses
   `Cert-Manager` consistently, the menu label, not the breadcrumb typo).
9. **The cert-manager `Sel Signed` type label keeps 4.1's spacing** (4.1's
   `GenerateIssuerData` classifies `spec.selfSigned` as `"Sel Signed"` — a 4.1
   typo for "Self Signed"; 5.0 renders `Self Signed`, the correct term).
