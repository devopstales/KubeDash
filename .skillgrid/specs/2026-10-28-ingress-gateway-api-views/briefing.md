# Ingress + Gateway API Views (and the Ingress→Gateway API converter) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-ingress-gateway-api-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** ADR-0004 (RBAC via SAR) is EXTENDED by the new generic
`POST /resources/apply` mutation endpoint (the first generic create path — a
one-way door; see `adr.md`). No other ADR is created.

## Intent

This change resolves TWO nav concerns under Network and adds the
**Ingress→Gateway API converter**:

1. **`/network/ingress`** — a 4.1-parity port. 4.1 has real templates:
   `network/ingress.html.j2` (list: **Name / IngressClass / Hostname**) and
   `network/ingress-data.html.j2` (data: Name / ingressClass / Created /
   Annotations / Labels + a "Routs" table — Host/Path/Type/Service/Port/TLS).
   Ingress is a core API (`ingresses`, group `networking.k8s.io`,
   **namespaced**); the 4.1 read is `k8sIngressListGet`
   (`4.1:src/kubedash/lib/k8s/network.py:56`):
   `NetworkingV1Api().list_namespaced_ingress(ns, _request_timeout=1)` — a
   generated core-API model, so the `to_dict` form is snake_case.
2. **`/network/gateway-api`** — NEW (4.1 has NO Gateway API). A **single
   tabbed page** (ratified 2026-10-28) with four tabs (GatewayClasses /
   Gateways / HTTPRoutes / ReferenceGrants), each backed by the **VPA CRD
   seam** (the `get_crd_served` full-custom-object pattern — the Gateway API
   CRDs are optional; a cluster without them is a first-class empty state,
   not an error). The 5.0 nav has no `/network/gateway-api` leaf yet, so the
   leaf is ADDED (a nav change, not a stub-removal).
3. **The Ingress→Gateway API converter** (ratified 2026-10-28): a **Python
   backend endpoint** (no published npm library does this — the ecosystem is
   Go CLIs; per the user's call, JS-only if an existing library exists, else
   Python) that ports `ing-switch`'s Gateway API migrator
   (`github.com/saiyam1814/ing-switch` `pkg/migrator/gatewayapi/`) — the
   NGINX-annotation → Gateway API mapping (path rewrite → URLRewrite, canary
   → weighted backendRefs, CORS → CORS filter, ssl-redirect → split
   redirect/backend HTTPRoutes, timeouts → backendRequest). The converter UI
   (on the Ingress data page) converts a selected Ingress and **applies the
   generated resources to the cluster** (ratified — not just preview).

Deliver: a real Ingress list + data pair (the 4.1 port), a real four-tab
Gateway API page, the converter endpoint + UI, and the nav leaf — so
`/network/ingress` resolves to first-class views and `/network/gateway-api`
resolves to a new first-class page with the converter.

## Requirements

### R1 — A SAR-gated Ingress list endpoint

`GET /api/v1/clusters/<id>/resources/ingresses?namespace=<ns>` MUST return the
Ingress list for that namespace (`kind: "ingresses"`, items in kubernetes
`to_dict` snake_case form, `metadata`/`spec`/`status` intact). With a
`namespace` param the read is `list_namespaced_ingress` (NetworkingV1Api);
without one the list spans all namespaces
(`list_ingress_for_all_namespaces` — the `list_secrets` branch). **No field
stripping**: a Service's/Ingress's `spec` (rules, tls, ingress_class_name)
and `status` (load_balancer) are public, so the full `to_dict` goes to the
view. The read is SAR-gated per ADR-0004: `list` on `ingresses`, group
`networking.k8s.io`, namespace = the query namespace or `None`; on deny the
response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked
BEFORE any K8s client call. An unbound user is 404 from the binding gate.
The kind identifier is the plural `ingresses`; the singular `ingress` is
rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/ingresses?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders a
not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup (the data page ALWAYS sends it).
No new HTTP route is added for the read: the kind is wired through
`_KINDS` + `_GETTERS` only.

### R3 — The Ingress list page

`/network/ingress` MUST render a `KubeDataTable` in the header-selected
namespace (`useClusterStore.selectedNamespace ?? 'default'`) with columns
**Name / IngressClass / Hostname**. The card title is EXACTLY `Ingress List`
(4.1's title, kept verbatim — the e2e-smoke contract). The Name cell links to
`/network/ingress/data?name=<name>&namespace=<ns>` — the list view is the
sole producer of those query strings.

- **IngressClass** = `spec.ingress_class_name` (`—` when absent).
- **Hostname** = the `spec.rules[].host` values joined with `, ` (the 4.1
  template rendered them one-per-line with `<br>`; 5.0 renders a comma list —
  `—` when there are no rules or no host).

States: no cluster selected → `No cluster selected.`; loading → `Loading
ingresses...`; error → red error line; empty list → `No ingresses found`
(first-class, not an error).

### R4 — The Ingress detail page (+ the converter entry point)

`/network/ingress/data?name=<name>&namespace=<ns>` MUST fetch the object with
a **single `?name=&namespace=` request** (not 4.1's list-then-filter). Empty
`items` is a not-found **STATE** — pinned copy `No Ingress '<name>' found`,
muted, not an error. The page renders:

- A CTable (Name / IngressClass / Created / Labels / Annotations):
  - **IngressClass** = `spec.ingress_class_name` (`—` when absent).
  - **Labels** and **Annotations** as key/value sub-tables (`No labels` /
    `No annotations` when empty), rendered VERBATIM (no `trimAnnotations` —
    the 4.1 inline last-applied-configuration filter is NOT replicated).
  - **Created** = `formatTimestamp` of `metadata.creation_timestamp`.
- A **Rules** table (a CTable, `No rules` when `spec.rules` is absent or
  empty) — one row per `spec.rules[].http.paths[]` entry (the 4.1 "Routs"
  table, the typo fixed to "Rules"): **Host** (`rule.host`, `—` when absent)
  / **Path** (`path.path`, `—` when empty) / **PathType** (`path.path_type`,
  `—` when absent) / **Service** (`path.backend.service.name`, `—` when
  absent) / **Port** (`path.backend.service.port.number` if present else
  `path.backend.service.port.name` else `—`) / **TLS** (`yes`/`—` — 4.1
  rendered the TLS secret name; 5.0 renders `yes` when `spec.tls` is
  non-empty, `—` otherwise — the TLS detail is in the JSON block).
- The full object as a syntax-highlighted block: `JSON.stringify(item, null,
  2)` with the `json` hljs grammar (style `anOldHope`).
- **A "Convert to Gateway API" button** — the converter entry point (R6).
  Clicking it opens the converter flow (a CoreUI modal, or a sub-panel
  below the CTable): it calls the R7 convert endpoint with this Ingress's
  `name` + `namespace`, shows the generated resources (R7), and offers
  Apply (R8).

Missing `name` param → `Error: ingress name not provided`. Missing
`namespace` param → the page falls back to the header-selected namespace.

### R5 — A four-tab Gateway API page

`/network/gateway-api` MUST render a **single page with four CoreUI `CTabs`**
(ratified 2026-10-28 — GatewayClasses / Gateways / HTTPRoutes /
ReferenceGrants), each tab a `KubeDataTable` of that kind via the existing
generic `/resources` route (the **VPA CRD seam** — full custom objects,
camelCase, the CRD's OWN served version + scope as authority, **CRD-absent →
`[]`** the first-class empty state). The nav leaf `/network/gateway-api`
(label `Gateway API`) is **ADDED** to the Network group in `_nav.tsx` (4.1
had no Gateway API; this is a nav change, not a stub-removal).

Each tab's columns (the kind's most-identifying fields):
- **GatewayClasses** (cluster-scoped): **Name / Controller / Age** —
  `spec.controllerName` (`—` when absent), Age from
  `metadata.creationTimestamp`.
- **Gateways** (namespaced): **Name / GatewayClass / Listeners** —
  `spec.gatewayClassName` (`—` when absent), Listeners = the
  `spec.listeners[].name:protocol:port` entries joined with `, ` (`—` when
  no listeners).
- **HTTPRoutes** (namespaced): **Name / Hostnames / ParentRefs** —
  `spec.hostnames` joined with `, ` (`—` when absent), ParentRefs = the
  `spec.parentRefs[].name` (+ `namespace` if present, else the route's own
  namespace) joined with `, ` (`—` when absent).
- **ReferenceGrants** (cluster-scoped): **Name / From / To** — a summary of
  `spec.from[].group:kind` → `spec.to[].group:kind` (`—` when absent).

Each tab's name cell links to
`/network/gateway-api/data?name=<name>&namespace=<ns>&kind=<kind>` (cluster-
scoped kinds — GatewayClass, ReferenceGrant — send NO `namespace`; the data
page tolerates its absence) — the list views are the sole producers of those
query strings. Card title EXACTLY `Gateway API` (the page title; the tabs are
the section headers). States per tab: no cluster selected → `No cluster
selected.`; loading → `Loading <kind>...`; error → red error line; empty →
`No <kind> found` (this is ALSO the CRD-absent state — the tab does not
distinguish "CRD absent" from "none exist", both render the same copy).

### R6 — The Gateway API detail page

`/network/gateway-api/data?name=<name>&namespace=<ns>&kind=<kind>` MUST fetch
the single object via the existing generic route's `?name=` branch (the
`_GETTERS` for the kind), rendering the same curated CTable as the list tab's
row set (the kind's fields) + a key/value Labels/Annotations sub-table + the
full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
grammar. `kind` ∈ {`gatewayclasses`, `gateways`, `httproutes`,
`referencegrants`} — validated against the closed set BEFORE the fetch (a
bad kind renders an error line, never hits the network). Empty `items` is a
not-found **STATE** — pinned copy `No <Kind> '<name>' found`, muted, not an
error. Missing `kind` → `Error: gateway api kind not provided`. Missing
`name` → `Error: gateway api name not provided`. For cluster-scoped kinds
(`gatewayclasses`, `referencegrants`) the `namespace` param is accepted and
ignored (the CRD's scope is the authority).

### R7 — The Ingress→Gateway API converter endpoint

`POST /api/v1/clusters/<id>/gateway-api/convert` (body `{ "ingressName":
string, "namespace": string }`) MUST return the Gateway API resources
generated from the named Ingress, by porting `ing-switch`'s Gateway API
migrator (`pkg/migrator/gatewayapi/`) to Python. Response shape:
`{ cluster, namespace, source: "ingress", gatewayClassName, resources: [
{ kind, apiVersion, metadata: { name, namespace }, spec }, ... ] }`.

The converter (a pure Python service, `backend/app/services/gateway_convert.py`,
**no kubernetes import in the converter itself** — it takes a parsed Ingress
dict and returns a list of resource dicts):
- **Reads** the Ingress via the existing `get_ingress` (the `_GETTERS`
  contract) — the endpoint does the read, the converter is pure.
- **Emits**, per `ing-switch`'s `Migrate()` (the controller + install +
  verify + cleanup files are OUT of scope — only the k8s resources):
  - ONE **GatewayClass** (`gateway.networking.k8s.io/v1`,
    `kind: GatewayClass`, `spec.controllerName`) — the provider is a
    request param `provider` ∈ {`envoy`, `traefik`} (default `envoy`),
    mapping to `ing-switch`'s `EnvoyProvider`/`TraefikProvider`
    (`eg`/`gateway.envoyproxy.io/gatewayclass-controller` or
    `traefik`/`traefik.io/gateway-controller`). The GatewayClass name is the
    provider's `GatewayClassName` (`eg` or `traefik`).
  - ONE **Gateway** (`kind: Gateway`, the ingress's namespace,
    `spec.gatewayClassName` = the provider's class) with an HTTP listener
    (port 80, `allowedRoutes.namespaces.from: All`) and, for each distinct
    TLS secret in the ingress's `spec.tls`, an HTTPS listener (port 443,
    `tls.mode: Terminate`, `certificateRefs` to the secret,
    `hostname` = the first host of that TLS entry) — 4.1's/ing-switch's
    `generateGateway`.
  - ONE **HTTPRoute** per ingress rule path (`kind: HTTPRoute`,
    `spec.parentRefs` → the generated Gateway, `spec.hostnames` = the
    ingress hosts, `spec.rules` = one rule per path): the NGINX-annotation
    mapping table, ported 1:1 from `ing-switch`'s `httproute.go`:
    - **path** → `matches[].path` (`PathPrefix` default, `Exact` when
      `path.pathType == "Exact"`, `RegularExpression` when
      `use-regex` is set OR the path contains `()[]{}`| chars) —
      `buildPathMatch`.
    - **canary-by-header** / **canary-by-header-value** → `matches[].headers`
      (`Present` when no value) — `buildHeaderMatches`.
    - **rewrite-target** → `filters[]` `URLRewrite`
      (`path.type: ReplaceFullPath`) — `buildBackendFilters`.
    - **enable-cors** (`cors-allow-origin`/`-methods`/`-headers`/
      `-credentials`/`-expose-headers`/`-max-age`) → `filters[]` `CORS` —
      `buildCORSFilter`.
    - **canary** + **canary-weight** → `backendRefs[]` with `weight` —
      `buildBackendRefs`.
    - **force-ssl-redirect** / **ssl-redirect** → a SECOND, redirect-only
      HTTPRoute (`<name>-redirect`, `sectionName: http`,
      `filters[]: RequestRedirect scheme: https statusCode: 301`/`302`)
      SEPARATE from the backend route (`sectionName: https-N`) — the
      split-route pattern (avoids redirect loops) —
      `generateSplitHTTPRoutes`.
    - **proxy-read-timeout** → `timeouts.backendRequest` — `buildTimeouts`.
    - `spec.tls[].secretName` → the Gateway's HTTPS listener
      `certificateRefs`.
    - **unsupported** NGINX annotations (rate-limit, forward-auth, IP
      allow-list, custom headers) are NOT converted to a Gateway API
      standard filter (they are provider-specific — Envoy ExtensionHTTPFilter
      or Traefik Middleware, which `ing-switch` emits as separate policy
      files); the converter DROPS them and records them in a top-level
      `warnings: string[]` on the response (so the UI can surface
      "N annotations have no Gateway API equivalent and were dropped").
- **SAR**: the endpoint reads the Ingress (gated on `get ingresses`, the R2
  gate) — the convert itself is a pure computation, so no additional gate
  beyond the Ingress read + the binding gate. (The APPLY of the generated
  resources is gated separately, R8.)
- **404** from the binding gate; **404** `RESOURCE_KIND_NOT_SUPPORTED` if the
  Ingress does not exist (the `get_ingress` 0/1-item contract — `[]` → 404
  "Ingress '<name>' not found"); **502** on a transport failure of the
  Ingress read.

### R8 — Apply the generated resources to the cluster

`POST /api/v1/clusters/<id>/resources/apply` (body `{ "namespace": string,
"objects": [{ kind, apiVersion, metadata, spec }, ...] }`) MUST create the
given objects in the cluster, ONE per object, via a generic
`apply_namespaced_*`/`apply_*` call resolved from the object's `kind` +
`apiVersion` (the Gateway API kinds: GatewayClass, Gateway, HTTPRoute,
ReferenceGrant — and extensible to any kind). This is the **first generic
mutation endpoint** (a one-way door — see `adr.md`):

- **SAR per object**: `create` on the object's resource + group (ADR-0004) —
  asked BEFORE each apply; a deny is a 403 `RBAC_DENIED` naming the
  resource. The endpoint is ALL-or-NOTHING per request in the SAR check
  phase (if ANY object's `create` is denied, 403 before anything is
  applied), then applies in order.
- **Idempotency**: each apply is a get-or-create (the `_apply` pattern
  already in `k8s_client.py` for roles — `create` / `except 409 ->
  patch`), so re-applying the same converted resources is a no-op (no
  duplicate-Gateway errors on a second Apply).
- **Response**: `{ applied: [{ kind, name, namespace, status:
  "created" | "unchanged" }], errors: [{ kind, name, message }] }` — a
  per-object result (a partial failure is 200 with the `errors` array
  populated, NOT a 500 — the UI shows which resources applied and which
  failed). A transport failure of an individual apply is in `errors`; a
  transport failure of the cluster connection is a 502.
- **404** from the binding gate. **403** on any SAR deny. **502** on a
  cluster-connection failure.

The converter UI's Apply button calls R7 (convert) then R8 (apply) with the
generated `resources`, then re-fetches the Gateway API tabs (so the newly
applied Gateway/HTTPRoutes appear) and shows the per-object result.

### R9 — Routing, nav, and stub removal

- `App.tsx` wires: `/network/ingress` + `/network/ingress/data` (the 4.1
  port), `/network/gateway-api` (the tabbed page) +
  `/network/gateway-api/data` (the detail).
- `/network/ingress` is removed from `views/Stub/routes.ts`.
- The `/network/gateway-api` leaf is ADDED to `_nav.tsx` (Network group,
  after the Ingress leaf) — `leaf('Gateway API', '/network/gateway-api')`.
- The Ingress nav leaf is UNCHANGED (path and label). The data routes and the
  gateway-api data route are not nav entries.

## Non-goals

- No create/edit/delete for Ingresses or Gateway API resources EXCEPT the
  converter's Apply (R8) — the converter is the only write path in this
  change; all the list/data views are read-only (as in 4.1 and every other
  5.0 resource view).
- No Gateway API `GRPCRoute` / `TCPRoute` / `TLSRoute` / `UDPRoute` tabs —
  only the four ratified kinds (GatewayClass, Gateway, HTTPRoute,
  ReferenceGrant); the other route kinds are a follow-up.
- No Traefik / Envoy-specific policy resources (Middleware,
  ExtensionHTTPFilter) in the converter output — the unsupported NGINX
  annotations are DROPPED with a `warnings` entry, not converted to a
  provider-specific CRD (the provider-specific policies are a follow-up;
  `ing-switch` emits them as separate policy files, which this change does
  not).
- No controller/install/verify/cleanup files (the `ing-switch`
  `01-install-*`, `02-install-*`, verify script, cleanup) — the converter
  emits only the k8s resources (GatewayClass, Gateway, HTTPRoute), not the
  Helm install scripts.
- No Traefik IngressRoute source (the converter ports `ing-switch`'s
  Gateway API target from an **Ingress** object only; `ing-switch` also
  scans Traefik/Kong/HAProxy/Istio sources, which are out of scope).
- No all-namespaces LIST mode on any page: the Ingress + Gateway API tabs
  always show the header-selected namespace (cluster-scoped tabs —
  GatewayClass, ReferenceGrant — have only one list); the all-namespaces
  list branch exists for the API and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title strings `Ingress List` and `Gateway API` are the only
  smoke-relevant contracts.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. **`/network/gateway-api` is NEW** — 4.1 has no Gateway API at all (only
   Ingress + IngressClass); the tabbed page + the converter are 5.0
   additions, not a 4.1 port.
3. **The Gateway API page is a single tabbed page** (ratified 2026-10-28),
   not four nav leaves (the kind-per-leaf convention is relaxed for the four
   Gateway API kinds — they are one conceptual surface).
4. **The Gateway API kinds use the VPA CRD seam** (full custom objects,
   `get_crd_served` version authority, CRD-absent → `[]`), NOT the core-API
   seam — the Gateway API CRDs are optional (a cluster without them is a
   first-class empty state, not an error).
5. **The Ingress data "Routs" table is renamed "Rules"** (the 4.1 typo is
   fixed).
6. **The Rules table's Service/Port cells are plain text, not 4.1's
   hidden-form links** (4.1 linked the service to `/network/service` and the
   TLS secret to `/security/secret` via hidden forms; 5.0's Service page
   lands separately and the secret link is a non-goal, so both render plain
   text — the full object is in the JSON block).
7. **The Ingress data GAINS the full-object JSON block** (4.1's data page had
   no full-object block — only the metadata table + the Routs table).
8. **The converter is a Python backend endpoint** (ratified 2026-10-28) —
   no published npm library does Ingress→Gateway API (the ecosystem is Go
   CLIs: `ing-switch`, `ingress2gateway`, AWS LBC toolkit); per the user's
   call (JS-only if an existing library exists, else Python), the mapping is
   ported from `ing-switch`'s Go to a pure Python service.
9. **The converter's Apply is a NEW generic `POST /resources/apply`
   endpoint** (the first generic mutation path — a one-way door): the
   converter is not read-only (ratified — preview + apply-to-cluster); the
   apply is SAR-gated on `create` per object and idempotent
   (get-or-create).
10. **The converter DROPS provider-specific NGINX annotations** (rate-limit,
    forward-auth, IP allow-list, custom headers) with a `warnings` entry,
    rather than emitting provider-specific policy CRDs (Middleware /
    ExtensionHTTPFilter) — those are a follow-up.
11. **`trimAnnotations` is NOT replicated** — annotations render verbatim
    (the JSON block has the full object, and 5.0 has no trim helper).
12. **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout
    to `list_namespaced_ingress`; 5.0's client uses the pool's configured
    timeout.
