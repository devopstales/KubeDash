# Cert-Manager + External Load Balancer Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive CRD kinds on the existing generic route (the
`get_crd_served` seam) + two 4-tab frontend views; the two nav leaves are
ADDED to the Network group; no migration, no new dependency, no public-API
break. Larger surface than a single-kind spec (8 CRD kinds across 2 views) but
each kind is the same additive pattern.

**Classification:** `low-risk` (read-only, SAR-gated, all 8 kinds are CRDs on
the existing `get_crd_served` seam — the VPA/Cilium pattern already in-repo.
The provider-detection seam (MetalLB→Cilium) is the one non-trivial piece; it
is a pure `get_crd_served`-driven branch, no new infra).

**Build shape:** Tracer thread — Task 1 proves the 4 cert-manager CRD kinds
end-to-end in the backend (service methods → `_KINDS`/`_GETTERS` rows → API
route → SAR deny → CRD-absent → `[]`) before any frontend; Task 2 the 4
external-LB CRD kinds (the provider-detection seam); Task 3 the Cert-Manager
4-tab view + per-type data; Task 4 the External LB 4-tab view + per-type data;
Task 5 the routing + the two nav leaves. Each task is independently revertable.

**Goal:** Resolve the two 4.1 plugin views (`/plugins/cert-manager`,
`/plugins/external-loadbalancer`) to first-class Network-group views at
`/network/cert-manager` and `/network/external-loadbalancer` (the /plugins/ →
/network/ move, ratified 2026-10-29).

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`, and ALREADY hosts CRD kinds on
the `get_crd_served` seam (the VPA + Cilium kinds). This change adds EIGHT CRD
kinds, all on that seam (`self._custom` + `get_crd_served`, CRD-absent → `[]`,
any other failure → `ClusterUnreachableError` 502):
- **cert-manager.io/v1** (4 kinds): `clusterissuers` (cluster-scoped),
  `issuers` (namespaced), `certificaterequests` (namespaced),
  `certificates` (namespaced) — each a `K8sClient` list/get method pair that
  calls `get_crd_served("cert-manager.io", <plural>)` and dispatches to
  `list_cluster_custom_object` / `list_namespaced_custom_object` by the CRD's
  OWN scope.
- **MetalLB v1beta1 / Cilium v2alpha1** (4 kinds, provider-detected):
  `ipaddresspools`, `l2advertisements`, `bgppeers`, `bgpadvertisements` — each
  a `K8sClient` list/get method pair that tries MetalLB (`get_crd_served
  ("metallb.io", <plural>)`); on CRD-absent falls back to Cilium
  (`get_crd_served("cilium.io", <cilium-plural>)`); both absent → `[]`. The
  `bgpadvertisements` kind is MetalLB-only (no Cilium fallback). Each returned
  item is tagged with a `provider` field (`"metallb"` / `"cilium"`) so the
  view renders the `Type` column.

Frontend: two 4-tab views (CoreUI `CTabs` — the Gateway-API-tabbed-page
pattern from the companion `ingress-gateway-api-views` spec) + two per-type
data pages (the `?type=` param selects the CRD kind + the metadata row set +
the JSON block), 8 item types, App.tsx routes, the two nav leaves ADDED to the
Network group (with the 4.1 `Beta` badge).

**Tech Stack:** `kubernetes` `CustomObjectsApi` (all 8 kinds — `self._custom`
already exists, the `get_crd_served` seam is in-repo), Flask + Smoarest
(existing route), React + CoreUI (`CTabs`/`CTab`/`CTabContent` — confirmed
present) + TanStack Query + MSW (existing), no new npm/Python dependency
(air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R7).
**Findings:** 4.1 audit — `4.1:src/kubedash/plugins/cert_manager/__init__.py`
(the `/plugins/cert-manager` + `/plugins/cert-manager/data` routes — the data
route is a POST that `ast.literal_eval(object_data)` the hidden-form object),
`4.1:src/kubedash/plugins/cert_manager/functions.py` (the four reads:
`ClusterIssuerGet` `list_cluster_custom_object("cert-manager.io","v1",
"clusterissuers")`, `IssuerGet` `list_namespaced_custom_object(...,"issuers")`,
`CertificateRequestsGet` `list_namespaced_custom_object(...,
"certificaterequests")` (generates `name`/`status`(last condition status)/
`reason`(last condition reason)/`message`(last condition message)/`issuer`
(spec.issuerRef.name)/`issuer_type`(spec.issuerRef.kind)/`owner`+`owner_type`
(last ownerReference)), `CertificatesGet` `list_namespaced_custom_object(...,
"certificates")` (generates `name`/`status`/`reason`/`message`/
`cert_valid`(status.notAfter)/`secret_name`(spec.secretName)/
`hostnames`(spec.dnsNames)/`owner`+`owner_type`)),
`4.1:src/kubedash/plugins/cert_manager/helper.py` (`GenerateIssuerData`: the
`status`(last condition status)/`reason`(last condition reason)/
`message`(last condition message, `"`-stripped) + the `type` classification
(`Sel Signed`/`CA`/`ACME`/`Vault` from `spec.selfSigned`/`spec.ca`/`spec.acme`/
`spec.vault`) + the `issuer_data` (the CA secret / ACME email+server+challenges
/ Vault auth detail)), `4.1:src/kubedash/plugins/cert_manager/templates/cert-
manager.html.j2` (the 4-tab list: Cluster Issuer (Status/Name/Type) / Issuer
(Status/Name/Type) / Certificate Request (Status/Name/Issuer/Owner) /
Certificates (Status/Name/Secret/Owner); the Status badge green when
`status=='True'` else red; the Name cell is a hidden-form POST carrying
`object_data`+`object_type`; the Certificate Request Issuer cell is a
`goToTab` in-page tab-switch; the Certificates Secret cell is a hidden-form
POST to `/secrets`; the Certificates Owner cell links to `/ingress` when
`owner_type=='Ingress'`; card title EXACTLY `Cert-Manager Objects`),
`4.1:src/kubedash/plugins/cert_manager/templates/cert-manager-data.html.j2`
(the per-`object_type` data: Cluster Issuer (Name/Status/Status message/Issuer
Type/Issuer Data) / Issuer (Name/Status/Status message/Issuer Data) /
Certificate Request (Name/Status/Status message/Issuer/Owner) / Certificate
(Name/Status/Status message/Validity Not After/Certificate/Hostnames); card
title `Cert-Manager`),
`4.1:src/kubedash/plugins/external_loadbalancer/__init__.py` (the
`/plugins/external-loadbalancer` + `/data` routes — the same hidden-form
`ast.literal_eval(object_data)` data pattern),
`4.1:src/kubedash/plugins/external_loadbalancer/helper.py` (the provider-
detection `*Test` functions: `ipaddresspoolTest` try `ipaddresspoolsGet`
(MetalLB) fall back `ciliumloadbalancerippoolsGet` (Cilium); `l2advertisements-
Test` try `l2advertisementsGet` fall back `ciliuml2announcementpoliciesGet`;
`bgpadvertisementsTest` MetalLB only; `bgppeersTest` try `bgppeersGet` fall
back `ciliumbgppeeringpoliciesGet`),
`4.1:src/kubedash/plugins/external_loadbalancer/metallb.py` (the 4 MetalLB
reads: `ipaddresspoolsGet` `list_namespaced_custom_object("metallb.io",
"v1beta1", ns, "ipaddresspools")` (generates `type:metallb`/`name`/
`addresses`(spec.addresses)/`autoAssign`/`avoidBuggyIPs` + the optional
`serviceAllocation` fields), `l2advertisementsGet` (generates `name`/
`ipAddressPools`(spec.ipAddressPools)/+optional `interfaces`/
`ipAddressPoolSelectors`/`nodeSelectors`), `bgppeersGet` (generates `name`/
`myASN`/`peerASN`/`peerAddress` + optional fields), `bgpadvertisementsGet`
(generates `name` + optional `aggregationLength`/`localPref`/`communities`/
`ipAddressPools`/`peers` etc.)),
`4.1:src/kubedash/plugins/external_loadbalancer/cilium.py` (the 3 Cilium reads:
`ciliumloadbalancerippoolsGet` `list_cluster_custom_object("cilium.io",
"v2alpha1", "ciliumloadbalancerippools")` (generates `type:cilium`/`name`/
`blocks`(spec.cidrs)/`allowFirstLastIPs`/+optional fields),
`ciliuml2announcementpoliciesGet` `list_cluster_custom_object(...,
"ciliuml2announcementpolicies")`, `ciliumbgppeeringpoliciesGet`
`list_cluster_custom_object(..., "ciliumbgppeeringpolicies")` (generates the
`virtual_routers` with `localASN`/`exportPodCIDR`/`neighbors`)),
`4.1:src/kubedash/plugins/external_loadbalancer/templates/external-loadbalancer
.html.j2` (the 4-tab list: IP Address Pools (Type/Name/Addresses) / L2
Advertisements (Type/Name/Pools) / BGP Peers (Type/Name/Peer) / BGP
Advertisements (Type/Name/Pools); card title EXACTLY `LoadBalancer Objects`),
`4.1:src/kubedash/plugins/external_loadbalancer/templates/external-
loadbalancer-data.html.j2` (the per-`object_type` data: ipaddresspool
(Addresses/Auto assign/Avoid buggy IPs/Allocation Namespaces/Allocation
Namespace Selectors/Service Selectors/Allocation Service Selectors) /
l2advertisement (IP Address Pools/Interfaces/Node Selectors/IP Address Pool
Selectors) / bgppeers (My ASN/Peer Address/Peer ASN/Node Selectors + optional)
/ bgpadvertisement (the MetalLB fields); card title `<object_type> Objects`).
In-repo precedents — `backend/app/services/k8s_client.py:655`
(`get_crd_served` — the seam both plugins use: the CRD's OWN served version +
scope, CRD-absent → `None`), `backend/app/services/k8s_client.py:690`
(`list_cilium_network_policies` — the CRD-seam list method to mirror:
`get_crd_served` → `[]` on None, the `list_namespaced_custom_object` /
`list_cluster_custom_object` dispatch by scope, the `_crd_body` item
extraction), the VPA methods (`list_vertical_pod_autoscalers` /
`get_vertical_pod_autoscaler` — the namespaced-CRD get pattern),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` (the VPA/Cilium rows to
mirror for the 8 new kinds), `backend/tests/api/test_resources.py` (the VPA +
Cilium API test blocks to mirror: 200 full custom object, CRD-absent → `[]`,
get-by-name, SAR deny, binding 404, singular rejected — ×8 kinds),
`frontend/src/views/OtherResource/VerticalPodAutoscaler*.tsx` +
`frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx` (the CRD-seam
list/data view patterns to clone), `frontend/src/views/Security/Secret.tsx`
(line 51, the landed Secret data link shape
`/security/secret/data?name=<n>&namespace=<ns>` — the deep-link destination
for the Certificates Secret cell), `frontend/src/_nav.tsx:94-97` (the Network
group — where the two leaves are ADDED, after the Ingress leaf),
`frontend/src/views/Stub/routes.ts` (neither path is a stub — no removal).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0009, ADR-0010, ADR-0020,
ADR-0021, ADR-0022. None created (the /plugins/ → /network/ placement is
recorded in `adr.md` as a decision, not a new ADR).

## Terms

None (the spec's vocabulary; "Cert-Manager" / "MetalLB" / "Cilium" are the
CRD provider names, not new terms).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- The 4 cert-manager kinds are SAR-gated on `list` (group `cert-manager.io`):
  `GET .../resources/clusterissuers` → 200 `kind: "clusterissuers"` (cluster-
  scoped, namespace `None`); `GET .../resources/issuers?namespace=<ns>` → 200
  `kind: "issuers"`; `GET .../resources/certificaterequests?namespace=<ns>` →
  200; `GET .../resources/certificates?namespace=<ns>` → 200 — each with FULL
  custom objects (camelCase, `spec`/`status` intact)
  (`certmanager-clusterissuers-list-200`, `certmanager-issuers-list-200`,
  `certmanager-certificaterequests-list-200`,
  `certmanager-certificates-list-200`).
- CRD-absent → 200 `items: []` for all 4 cert-manager kinds (the first-class
  empty state — cert-manager not installed)
  (`certmanager-crd-absent-empty`).
- The per-`?name=` lookups return a 0/1-item list (hit = the full object, miss
  = `[]`, CRD-absent = `[]`) for all 4 kinds
  (`certmanager-get-by-name`).
- The singular cert-manager kinds are rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`certmanager-kind-singular-rejected`).
- The 4 external-LB kinds are SAR-gated on `list` with the provider group:
  `GET .../resources/ipaddresspools?namespace=<ns>` → 200 (the provider-
  detected read — MetalLB present → the namespaced MetalLB call; else Cilium
  present → the cluster-scoped Cilium call; both absent → `[]`); the returned
  items carry a `provider` field (`metallb` / `cilium`)
  (`exlb-ipaddresspools-list-200-provider-detect`).
- The provider-detection fallback: MetalLB CRD absent + Cilium CRD present →
  the Cilium read (cluster-scoped); both absent → `items: []`
  (`exlb-provider-fallback-cilium`, `exlb-provider-absent-empty`).
- `bgpadvertisements` is MetalLB-only (no Cilium fallback) — MetalLB absent →
  `items: []` (`exlb-bgpadvertisements-metallb-only`).
- The per-`?name=` lookups return a 0/1-item list for all 4 external-LB kinds
  (`exlb-get-by-name`).
- The singular external-LB kinds are rejected
  (`exlb-kind-singular-rejected`).
- The Cert-Manager list view: card title EXACTLY `Cert-Manager Objects`; four
  `CTabs` (Cluster Issuer / Issuer / Certificate Request / Certificates); the
  Status cell is the last `status.conditions[]` `reason` (badge green when
  `status=="True"` else red); the Name cell links to
  `/network/cert-manager/data?type=<t>&name=<n>[&namespace=<ns>]`; the
  Certificate Request Issuer cell is a tab-switch + row-highlight; the
  Certificates Secret cell deep-links to
  `/security/secret/data?name=<n>&namespace=<ns>` (landed)
  (`certmanager-list-renders-4tabs`, `certmanager-list-status-badge`,
  `certmanager-list-name-links`, `certmanager-list-certificate-secret-deep-link`).
- The Cert-Manager data view: card title `Cert-Manager <Type>`; the per-type
  metadata CTable (the 4.1 row set per type) + the JSON block; a miss is the
  pinned state `No <type> '<name>' found` — never an error style (also the
  CRD-absent state) (`certmanager-data-renders-per-type`,
  `certmanager-data-not-found-state`).
- The External LB list view: card title EXACTLY `LoadBalancer Objects`; four
  `CTabs` (IP Address Pools / L2 Advertisements / BGP Peers / BGP
  Advertisements); the Type cell shows the `provider`; the Name cell links to
  `/network/external-loadbalancer/data?type=<t>&name=<n>[&namespace=<ns>]`
  (`exlb-list-renders-4tabs`, `exlb-list-type-column`,
  `exlb-list-name-links`).
- The External LB data view: card title `<Type> Objects`; the per-type +
  provider-specific metadata CTable (the 4.1 row set per type + provider) +
  the JSON block; a miss is the pinned state `No <type> '<name>' found` (also
  the CRD-absent state) (`exlb-data-renders-per-type`,
  `exlb-data-not-found-state`).
- The two nav leaves are ADDED to the Network group (after the Ingress leaf,
  with the 4.1 `Beta` badge); NO new Plugins group; both view pairs are routed;
  no stub removal (`nav-leaves-added-to-network`, `no-plugins-group`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — 8 method pairs (the cert-manager
  kinds + the provider-detected external-LB kinds) + the provider constants
  (modified).
- `backend/app/api/resources.py` — 8 `_KINDS` + 8 `_GETTERS` rows (modified).
- `backend/tests/services/test_k8s_client_certmanager.py` (new).
- `backend/tests/services/test_k8s_client_external_lb.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 32 new tests
  (modified).
- `frontend/src/lib/types.ts` — 8 item types (modified).
- `frontend/src/views/Network/CertManager.tsx` (new) — the 4-tab list.
- `frontend/src/views/Network/CertManagerData.tsx` (new) — the per-type data.
- `frontend/src/views/Network/ExternalLoadBalancer.tsx` (new) — the 4-tab list.
- `frontend/src/views/Network/ExternalLoadBalancerData.tsx` (new) — the
  per-type data.
- `frontend/tests/views/certmanager.test.tsx` (new).
- `frontend/tests/views/certmanager_data.test.tsx` (new).
- `frontend/tests/views/external_loadbalancer.test.tsx` (new).
- `frontend/tests/views/external_loadbalancer_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/_nav.tsx`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior per kind: the same
  route branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows land
  in the same commit as the service methods (16 rows + 16 methods total).
- **All 8 kinds are CRDs on the `get_crd_served` seam** — `self._custom` +
  `get_crd_served(group, plural)`, CRD-absent → `[]`, the `list_cluster_
  custom_object` / `list_namespaced_custom_object` dispatch by the CRD's OWN
  scope (the `list_cilium_network_policies` pattern). The `_crd_body` item
  extraction is the existing idiom (match it exactly).
- **The cert-manager kinds are all `cert-manager.io/v1`** — but the scope
  differs: `clusterissuers` is cluster-scoped (`list_cluster_custom_object`,
  namespace `None`), the other three are namespaced (`list_namespaced_
  custom_object`, the query namespace). The scope comes from `get_crd_served`
  (the CRD's OWN authority), not hardcoded — but the 4.1 mapping is the
  expected value (verify against the CRD's `spec.scope`).
- **The external-LB provider-detection is inside the `K8sClient` method** —
  `list_ipaddresspools(namespace)`: `served_ml = get_crd_served("metallb.io",
  "ipaddresspools")`; if `served_ml` → the MetalLB read (namespaced); else
  `served_cil = get_crd_served("cilium.io", "ciliumloadbalancerippools")`; if
  `served_cil` → the Cilium read (cluster-scoped) + tag `provider: "cilium"`;
  else `[]`. The `bgpadvertisements` method has NO Cilium branch (MetalLB
  only). The `provider` tag is added to each returned item (the view's `Type`
  column).
- **The `provider` tag is the view's `Type` column** — the external-LB list
  renders `item.provider` (the detected provider) in the `Type` column (4.1's
  `type` field was the hardcoded `"metallb"` / `"cilium"`; 5.0 derives it from
  the detection).
- **The Certificates Secret cell deep-links to the LANDED Secret view** —
  `/security/secret/data?name=<n>&namespace=<ns>` (landed); the Certificate
  Ingress-owner cell deep-links to the Ingress list ONLY when that view is
  landed (the not-yet-landed `ingress-gateway-api-views` spec), else plain
  text (the "deep-link to landed kinds" pattern).
- **The Certificate Request Issuer cell is a tab-switch + row-highlight** —
  4.1's `goToTab(issuer_type, name)` JS (switch to the Issuer/Cluster Issuer
  tab + highlight the matching row) re-implemented with the 5.0 `CTabs` API
  (a tab-switch on click + a row-highlight on the target tab). This is an
  in-page interaction, not a navigation.
- **The data page's `?type=` param selects the CRD kind + the row set** — the
  data route parses `?type=` (the kind identifier: `cluster_issuer` / `issuer`
  / `certificate_request` / `certificate` / `ipaddresspool` / `l2advertisement`
  / `bgppeers` / `bgpadvertisement`) + `?name=` (+ `?namespace=` for the
  namespaced kinds) → fetches the single object → renders the per-type
  metadata CTable (the row set is keyed by the `type`) + the JSON block. The
  `type` → CRD-kind mapping is the same for list + data (a shared constant).
- **The list view's name-link href is the SOLE producer of the data page's
  `?type=&name=&namespace=` query strings** — the data page parses the params,
  never constructs one (the HPA contract; keep it).
- **The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract** (`[]` on 404 / CRD-absent) — the data view must NOT treat
  `items: []` as an API error (the `NOT_FOUND`-as-throw-not-found-state
  pattern).
- **The 4.1 hidden-form `object_data` is NOT replicated** — 4.1's data route
  was a POST that `ast.literal_eval(object_data)` the hidden-form object; 5.0
  re-fetches by `?type=&name=&namespace=` (a single `?name=` request, the
  house rule). No form, no `ast.literal_eval`, no `session['ns_select']`.
- **The two nav leaves are ADDED to the Network group** (after the Ingress
  leaf, with the 4.1 `Beta` badge) — NO new Plugins group (ratified 2026-10-29;
  ADR-0022's "minus Plugins" stays intact). The `Stub.test.tsx` `viewPaths` set
  MUST gain the two paths (the leaves are added to the nav; without the
  addition the test expects them to be stubs — RED).

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive; the `get_crd_served` seam is
existing).

## Global Constraints

- No new Python dependency — `CustomObjectsApi` is already in the kubernetes
  client; `self._custom` + `get_crd_served` already exist (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported (the `json` grammar already registered); `CTabs`/`CTab`/
  `CTabContent` + `KubeDataTable` + CoreUI are existing.
- All 8 kinds are CRDs (group `cert-manager.io` ×4, `metallb.io`/`cilium.io`
  ×4): the list URL + data URL carry `namespace=<ns>` for the namespaced
  kinds (the cluster-scoped `clusterissuers` + the Cilium fallbacks are
  cluster-scoped — NO namespace param); SAR group = the provider group,
  namespace = the query value (or `None` for the cluster-scoped kinds); the
  reads use `get_crd_served` + the `list_cluster_custom_object` /
  `list_namespaced_custom_object` dispatch by scope.
- The external-LB provider-detection: MetalLB primary, Cilium fallback
  (ratified 2026-10-29); `bgpadvertisements` is MetalLB-only. Each returned
  item carries a `provider` field.
- The full-object blocks are `JSON.stringify(item, null, 2)` with hljs grammar
  `json`, style `anOldHope` (the truthful-classifier rule).
- Card titles EXACTLY: `Cert-Manager Objects`, `LoadBalancer Objects` (the
  e2e-smoke contracts). The data card titles: `Cert-Manager <Type>`, `<Type>
  Objects`.
- Pinned copy (do not reword): `No cluster issuers found`, `No issuers found`,
  `No certificate requests found`, `No certificates found`, `No <type> '<name>'
  found`, `Error: <type> name not provided`, `No IP address pools found`, `No
  L2 advertisements found`, `No BGP peers found`, `No BGP advertisements
  found`, `No cluster selected.`, `Loading cert-manager objects...`, `Loading
  load-balancer objects...`.
- Conventional commits; spec-zone commits precede code-zone commits; WHY-
  comments on load-bearing invariants (the provider-detection, the CRD-scope
  dispatch, the deep-link-to-landed-kinds).
- `fe-build` runs `tsc --noEmit` over TEST files too — type any new test
  params explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — the 8 method pairs + the
  provider constants (`_CERT_MANAGER_GROUP`, `_METALLB_GROUP`,
  `_CILIUM_GROUP` — the last two may already exist for the Cilium kinds).
- `backend/app/api/resources.py` (modify) — the 8 `_KINDS` + 8 `_GETTERS` rows.
- `backend/tests/services/test_k8s_client_certmanager.py` (new) — the
  `get_crd_served` mocked + the `self._custom` fake for the 4 cert-manager
  kinds.
- `backend/tests/services/test_k8s_client_external_lb.py` (new) — the
  provider-detection tests (MetalLB present / Cilium fallback / both absent /
  the `bgpadvertisements` MetalLB-only) + the `provider` tag.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains the 8
  methods; 32 new tests (4 per kind).
- `frontend/src/lib/types.ts` (modify) — the 8 item types (the cert-manager
  types + the external-LB types with the `provider` field).
- `frontend/src/views/Network/CertManager.tsx` (new) — the 4-tab list.
- `frontend/src/views/Network/CertManagerData.tsx` (new) — the per-type data.
- `frontend/src/views/Network/ExternalLoadBalancer.tsx` (new) — the 4-tab list.
- `frontend/src/views/Network/ExternalLoadBalancerData.tsx` (new) — the
  per-type data.
- `frontend/tests/views/certmanager.test.tsx` (new).
- `frontend/tests/views/certmanager_data.test.tsx` (new).
- `frontend/tests/views/external_loadbalancer.test.tsx` (new).
- `frontend/tests/views/external_loadbalancer_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — the four routes + the four imports.
- `frontend/src/_nav.tsx` (modify) — ADD the two leaves to the Network group.
- `frontend/tests/views/Stub.test.tsx` (modify) — add the two paths to the
  `viewPaths` set.

---

### Task 1: Backend — the 4 cert-manager CRD kinds (service + `_KINDS` + API tests)

**SATISFIES:** `certmanager-clusterissuers-list-200`,
`certmanager-issuers-list-200`, `certmanager-certificaterequests-list-200`,
`certmanager-certificates-list-200`, `certmanager-crd-absent-empty`,
`certmanager-get-by-name`, `certmanager-kind-singular-rejected`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_certmanager.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing (first code task).
- Produces: `K8sClient.list_clusterissuers(_namespace)` /
  `get_clusterissuer(_namespace, name)` / `list_issuers(namespace)` /
  `get_issuer(namespace, name)` / `list_certificaterequests(namespace)` /
  `get_certificaterequest(namespace, name)` / `list_certificates(namespace)` /
  `get_certificate(namespace, name)` — the exact names `_KINDS`/`_GETTERS`
  reference via `getattr`.
- Seam: the `get_crd_served` seam (the `list_cilium_network_policies` pattern)
  + the `pool` factory (the FakeK8s injection seam).
- Deletion test: delete the 8 `_KINDS`/`_GETTERS` rows → the 4 kinds 404 with
  `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing cert-manager service tests** —
  `backend/tests/services/test_k8s_client_certmanager.py` (mirror the Cilium
  CRD-seam test pattern, `get_crd_served` mocked + the `self._custom` fake):
  - the 4 kinds: the served-version authority, the scope dispatch
    (`clusterissuers` → `list_cluster_custom_object`, the namespaced three →
    `list_namespaced_custom_object`), CRD-absent → `[]`, getter 404 → `[]`,
    full custom-object shape (camelCase, `spec`/`status` intact).
- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_certmanager.py -q`.
  Expected: FAIL (no methods).
- [ ] **Step 3: Implement the 4 cert-manager service methods** —
  `k8s_client.py`, next to the Cilium methods (the CRD-seam pattern):
  ```python
  _CERT_MANAGER_GROUP = "cert-manager.io"

  def list_clusterissuers(self, _namespace: str | None) -> list[dict[str, Any]]:
      """ClusterIssuer items (cert-manager.io, CLUSTER-scoped), full custom-
      object shape. CRD absent (cert-manager not installed) -> [] (expected);
      other failures -> ClusterUnreachableError (502)."""
      served = self.get_crd_served(self._CERT_MANAGER_GROUP, "clusterissuers")
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          resp = custom.list_cluster_custom_object(
              self._CERT_MANAGER_GROUP, version, "clusterissuers")
      except ApiException as e:
          self._unreachable("list_clusterissuers", e)
          raise AssertionError("unreachable") from e
      items = self._crd_body(resp).get("items", [])
      return [i.to_dict() if hasattr(i, "to_dict") else i for i in items]

  def get_clusterissuer(self, _namespace: str, name: str) -> list[dict[str, Any]]:
      """One ClusterIssuer as a 0/1-item full custom object; [] on 404 or
      CRD-absent. Cluster-scoped (get_cluster_custom_object)."""
      served = self.get_crd_served(self._CERT_MANAGER_GROUP, "clusterissuers")
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          item = custom.get_cluster_custom_object(
              self._CERT_MANAGER_GROUP, version, "clusterissuers", name)
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_clusterissuer", e)
          raise AssertionError("unreachable") from e
      return [item.to_dict() if hasattr(item, "to_dict") else item]
  ```
  (the 3 namespaced kinds — `issuers` / `certificaterequests` /
  `certificates` — mirror `list_cilium_network_policies`: the
  `list_namespaced_custom_object` / `get_namespaced_custom_object` dispatch;
  the `_crd_body` item extraction is the existing idiom.)
- [ ] **Step 4: Wire the 4 kinds + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # cert-manager.io CRDs (the 4.1 cert-manager plugin, moved to /network/ by
  # the certmanager-external-loadbalancer-views change; ADR-0022 minus Plugins
  # stays intact — the view is a Network leaf, not a Plugins group).
  "clusterissuers": ("list_clusterissuers", "clusterissuers", "cert-manager.io"),
  "issuers": ("list_issuers", "issuers", "cert-manager.io"),
  "certificaterequests": ("list_certificaterequests", "certificaterequests", "cert-manager.io"),
  "certificates": ("list_certificates", "certificates", "cert-manager.io"),
  ```
  in `_KINDS`, and the 4 `get_*` rows in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the Cilium block ×4):
  - FakeK8s gains the 8 methods (a `get_crd_served` that returns
    `("v1", "Namespaced")` / `("v1", "Cluster")` + a `self._custom` fake).
  - 16 new tests (4 per kind: `list_200` (full custom object),
    `crd_absent_empty` (the fake's `get_crd_served` → None → `items: []`),
    `get_by_name` (hit + miss), `sar_denied` (assert the SAR on the plural,
    group `cert-manager.io`, the namespace), `binding_404`, `singular_rejected`
    — trimmed to 4 per kind for the 16 total).
- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_certmanager.py tests/api/test_resources.py -q`.
- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_certmanager.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): cert-manager.io CRD kinds (4-tab plugin moved to /network/)"`

### Task 2: Backend — the 4 external-LB CRD kinds (provider-detection) + API tests

**SATISFIES:** `exlb-ipaddresspools-list-200-provider-detect`,
`exlb-provider-fallback-cilium`, `exlb-provider-absent-empty`,
`exlb-bgpadvertisements-metallb-only`, `exlb-get-by-name`,
`exlb-kind-singular-rejected`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_external_lb.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: Task 1's pattern (the CRD-seam method shape).
- Produces: `K8sClient.list_ipaddresspools(namespace)` /
  `get_ipaddresspool(namespace, name)` / `list_l2advertisements(namespace)` /
  `get_l2advertisement(namespace, name)` / `list_bgppeers(namespace)` /
  `get_bgppeer(namespace, name)` / `list_bgpadvertisements(namespace)` /
  `get_bgpadvertisement(namespace, name)` — each provider-detecting (MetalLB
  primary, Cilium fallback, `bgpadvertisements` MetalLB-only), each tagging
  the `provider` field.
- Seam: the `get_crd_served` seam (the provider-detection is the
  `get_crd_served`-driven branch).
- Deletion test: delete the 8 rows → the 4 kinds 404 again; delete the
  methods → the service tests fail.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing external-LB service tests** —
  `backend/tests/services/test_k8s_client_external_lb.py` (the provider-
  detection tests, `get_crd_served` mocked for both providers + the
  `self._custom` fake):
  - MetalLB present → the namespaced MetalLB read, `provider: "metallb"`.
  - MetalLB absent + Cilium present → the cluster-scoped Cilium read,
    `provider: "cilium"`.
  - Both absent → `[]`.
  - `bgpadvertisements`: MetalLB absent → `[]` (NO Cilium branch).
  - getter 404 → `[]`, CRD-absent → `[]`, full custom-object shape.
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Implement the 4 external-LB service methods** —
  `k8s_client.py`, next to the Cilium methods. The provider-detection pattern:
  ```python
  _METALLB_GROUP = "metallb.io"
  _CILIUM_GROUP = "cilium.io"  # may already exist for the Cilium kinds

  def list_ipaddresspools(self, namespace: str | None) -> list[dict[str, Any]]:
      """IP Address Pools — provider-detected (MetalLB primary, Cilium
      fallback, ratified 2026-10-29): MetalLB ipaddresspools (namespaced,
      metallb.io) if present; else Cilium ciliumloadbalancerippools
      (cluster-scoped, cilium.io); both absent -> []. Each item is tagged
      with a ``provider`` field (metallb / cilium) for the view's Type column."""
      served_ml = self.get_crd_served(self._METALLB_GROUP, "ipaddresspools")
      if served_ml is not None:
          version, _scope = served_ml
          custom = self._custom()
          try:
              resp = custom.list_namespaced_custom_object(
                  self._METALLB_GROUP, version, namespace, "ipaddresspools")
          except ApiException as e:
              self._unreachable("list_ipaddresspools", e)
              raise AssertionError("unreachable") from e
          items = self._crd_body(resp).get("items", [])
          return [{**i, "provider": "metallb"} for i in
                  (x.to_dict() if hasattr(x, "to_dict") else x for x in items)]
      served_cil = self.get_crd_served(self._CILIUM_GROUP, "ciliumloadbalancerippools")
      if served_cil is not None:
          version, _scope = served_cil
          custom = self._custom()
          try:
              resp = custom.list_cluster_custom_object(
                  self._CILIUM_GROUP, version, "ciliumloadbalancerippools")
          except ApiException as e:
              self._unreachable("list_ipaddresspools", e)
              raise AssertionError("unreachable") from e
          items = self._crd_body(resp).get("items", [])
          return [{**i, "provider": "cilium"} for i in
                  (x.to_dict() if hasattr(x, "to_dict") else x for x in items)]
      return []
  ```
  (the other 3 kinds mirror this — `l2advertisements` → Cilium
  `ciliuml2announcementpolicies`; `bgppeers` → Cilium
  `ciliumbgppeeringpolicies`; `bgpadvertisements` → MetalLB-only, NO Cilium
  branch; the getters mirror the same detection + `get_*_custom_object`.)
- [ ] **Step 4: Wire the 4 kinds + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # MetalLB / Cilium external-LB CRDs (the 4.1 external-loadbalancer plugin,
  # moved to /network/ by the certmanager-external-loadbalancer-views change;
  # provider-detected: MetalLB primary, Cilium fallback).
  "ipaddresspools": ("list_ipaddresspools", "ipaddresspools", "metallb.io"),
  "l2advertisements": ("list_l2advertisements", "l2advertisements", "metallb.io"),
  "bgppeers": ("list_bgppeers", "bgppeers", "metallb.io"),
  "bgpadvertisements": ("list_bgpadvertisements", "bgpadvertisements", "metallb.io"),
  ```
  in `_KINDS` (the SAR group is `metallb.io` — the primary; the Cilium
  fallback is inside the method, not the SAR group), and the 4 `get_*` rows in
  `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the Cilium block ×4, with
  the provider-detection fakes): 16 new tests (4 per kind: `list_200`
  (provider-detect, the `provider` tag), `provider_fallback_cilium` /
  `provider_absent_empty`, `get_by_name`, `sar_denied` (group `metallb.io`),
  `binding_404`, `singular_rejected` — trimmed to 4 per kind for the 16
  total).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(resources): external-LB CRD kinds (MetalLB/Cilium provider-detect, moved to /network/)"`

### Task 3: Frontend — Cert-Manager 4-tab view + per-type data + tests

**SATISFIES:** `certmanager-list-renders-4tabs`,
`certmanager-list-status-badge`, `certmanager-list-name-links`,
`certmanager-list-certificate-secret-deep-link`, `certmanager-data-renders-
per-type`, `certmanager-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts` (the 4 cert-manager types)
- Create: `frontend/src/views/Network/CertManager.tsx`
- Create: `frontend/src/views/Network/CertManagerData.tsx`
- Test: `frontend/tests/views/certmanager.test.tsx` (new)
- Test: `frontend/tests/views/certmanager_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the 4 cert-manager kind URLs).
- Produces: the data-page links
  `/network/cert-manager/data?type=<t>&name=<n>[&namespace=<ns>]` (the sole
  producer).
- Seam: `apiFetch` + TanStack Query + the selected-namespace store + `CTabs`.
- Deletion test: deleting the views → the routes (Task 5) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the 4 types** — `frontend/src/lib/types.ts` (the
  cert-manager item types — the full custom-object shape, camelCase:
  `metadata`/`spec`/`status` + the provider-specific fields).
- [ ] **Step 2: Write the failing view tests** — clone the VPA + HPA test
  patterns + the Gateway-API-tabbed-page pattern:
  - list: card title `Cert-Manager Objects`; four tabs (Cluster Issuer /
    Issuer / Certificate Request / Certificates); the Status badge (green when
    `status=="True"` else red, the last `status.conditions[]` `reason`); the
    Name links (`?type=&name=` + `&namespace=` for the namespaced kinds); the
    Certificate Request Issuer cell (a tab-switch + row-highlight); the
    Certificates Secret cell (deep-link to
    `/security/secret/data?name=<n>&namespace=<ns>`); no-cluster, no-namespace,
    empty tab, CRD-absent → the empty state.
  - data: card title `Cert-Manager <Type>`; the per-type metadata CTable (the
    4.1 row set per type: Cluster Issuer (Name/Status/Status message/Issuer
    Type/Issuer Data) / Issuer (Name/Status/Status message/Issuer Data) /
    Certificate Request (Name/Status/Status message/Issuer/Owner) / Certificate
    (Name/Status/Status message/Validity Not After/Certificate/Hostnames)) +
    the JSON block; the Secret cell deep-link; not-found state; missing-name.
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `CertManager.tsx` (the 4-tab `CTabs` page — each
  tab a `KubeDataTable`; the Status badge helper (the last `status.conditions[]`
  `reason`, green/red); the Name links; the Issuer tab-switch + row-highlight;
  the Certificate Secret deep-link); `CertManagerData.tsx` (parse `?type=` +
  `?name=` + `?namespace=` → fetch the single object → the per-type metadata
  CTable (the row set keyed by the `type`) + the JSON block; the NOT_FOUND
  state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): cert-manager 4-tab list + per-type data views (moved to /network/)"`

### Task 4: Frontend — External LB 4-tab view + per-type data + tests

**SATISFIES:** `exlb-list-renders-4tabs`, `exlb-list-type-column`,
`exlb-list-name-links`, `exlb-data-renders-per-type`,
`exlb-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts` (the 4 external-LB types with the
  `provider` field)
- Create: `frontend/src/views/Network/ExternalLoadBalancer.tsx`
- Create: `frontend/src/views/Network/ExternalLoadBalancerData.tsx`
- Test: `frontend/tests/views/external_loadbalancer.test.tsx` (new)
- Test: `frontend/tests/views/external_loadbalancer_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 2's API (the 4 external-LB kind URLs).
- Produces: the data-page links
  `/network/external-loadbalancer/data?type=<t>&name=<n>[&namespace=<ns>]`.
- Seam: `apiFetch` + TanStack Query + the selected-namespace store + `CTabs`.
- Deletion test: deleting the views → the routes (Task 5) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the 4 types** — `frontend/src/lib/types.ts` (the external-
  LB item types — the full custom-object shape + the `provider` field + the
  provider-specific fields: MetalLB `spec.addresses`/`autoAssign`/etc. +
  Cilium `spec.cidrs`/`allowFirstLastIPs`/etc.).
- [ ] **Step 2: Write the failing view tests** — clone the VPA + HPA test
  patterns + the Gateway-API-tabbed-page pattern:
  - list: card title `LoadBalancer Objects`; four tabs (IP Address Pools / L2
    Advertisements / BGP Peers / BGP Advertisements); the Type cell = the
    `provider`; the Name links; the kind-specific column (Addresses / Pools /
    Peer / Pools — the provider-specific field); no-cluster, no-namespace,
    empty tab, both-providers-absent → the empty state.
  - data: card title `<Type> Objects`; the per-type + provider-specific
    metadata CTable (the 4.1 row set per type + provider) + the JSON block;
    not-found state (also the CRD-absent state); missing-name.
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `ExternalLoadBalancer.tsx` (the 4-tab `CTabs`
  page — each tab a `KubeDataTable`; the Type cell = `item.provider`; the Name
  links; the kind-specific column); `ExternalLoadBalancerData.tsx` (parse
  `?type=` + `?name=` + `?namespace=` → fetch the single object → the per-type
  + provider-specific metadata CTable (the row set keyed by the `type` + the
  `provider`) + the JSON block; the NOT_FOUND state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): external-LB 4-tab list + per-type data views (provider-detect, moved to /network/)"`

### Task 5: Routing + nav leaves + full verification

**SATISFIES:** `nav-leaves-added-to-network`, `no-plugins-group`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/_nav.tsx`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 3–4's view components.
- Produces: the resolved nav leaves (the goal).
- Seam: react-router `Route` + the nav `leaf()` calls + the `viewPaths` set.
- Deletion test: delete the four `Route`s → the paths 404; delete the nav
  leaves → the pages are unreachable.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the four view imports + the
  four routes:
  ```tsx
  <Route path="/network/cert-manager" element={<ProtectedRoute><CertManagerView /></ProtectedRoute>} />
  <Route path="/network/cert-manager/data" element={<ProtectedRoute><CertManagerDataView /></ProtectedRoute>} />
  <Route path="/network/external-loadbalancer" element={<ProtectedRoute><ExternalLoadBalancerView /></ProtectedRoute>} />
  <Route path="/network/external-loadbalancer/data" element={<ProtectedRoute><ExternalLoadBalancerDataView /></ProtectedRoute>} />
  ```
- [ ] **Step 2: Add the nav leaves** — `_nav.tsx`: in the Network group
  (after the Ingress leaf, line ~96), add (with the 4.1 `Beta` badge):
  ```tsx
  { component: CNavItem, name: 'Cert-Manager', to: '/network/cert-manager', badge: { color: 'warning', text: 'Beta' } },
  { component: CNavItem, name: 'External Load Balancer', to: '/network/external-loadbalancer', badge: { color: 'warning', text: 'Beta' } },
  ```
  Verify with `git diff --stat` that ONLY the two leaves were added (NO new
  Plugins group).
- [ ] **Step 3: Update Stub.test.tsx** — add `/network/cert-manager` +
  `/network/external-loadbalancer` to the `viewPaths` set in `expectedStubs()`
  (the leaves are ADDED to the nav; without the addition the test expects them
  to be stubs — RED). Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.
- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build).
  - `task fe-check` (air-gap — no new external refs).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures are the baseline).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).
- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/_nav.tsx frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire cert-manager + external-LB routes, add nav leaves to Network"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_certmanager.py tests/services/test_k8s_client_external_lb.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/certmanager.test.tsx tests/views/certmanager_data.test.tsx tests/views/external_loadbalancer.test.tsx tests/views/external_loadbalancer_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` shows ONLY the two added leaves (NO new Plugins group); no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (cert-manager kinds) ──► Task 3 (Cert-Manager views) ──► Task 5 (routing + nav)
Task 2 (external-LB kinds)  ──► Task 4 (External LB views)  ──┘
```

Tasks 1 and 2 are independent of each other (both are backend CRD kinds on the
same seam; either can run first or in parallel). Task 3 consumes Task 1; Task
4 consumes Task 2. Task 5 last (it wires the routes + nav, so the views must
exist first).

## Rollback

Each task is one conventional commit and independently revertable (no schema,
no dependency, no public contract change). Reverting Task 5 reverts the routes
+ nav + test (self-contained). Reverting Task 1 reverts the 4 cert-manager
kinds (the cert-manager view 404s); reverting Task 2 reverts the 4 external-LB
kinds (the external-LB view 404s). Tasks 3 and 4 are independent reverts (the
Cert-Manager and External LB views are separate commits). All 8 kinds are on
the existing `get_crd_served` seam (no new infra) — reverting any task is a
clean removal of the added methods + rows + views.
