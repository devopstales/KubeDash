# Ingress + Gateway API Views (and the converter) — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | **FOLLOWS AND EXTENDS.** The Ingress kind and the four Gateway API kinds are SAR-gated like every other resource: `list`/`get` on the kind, the correct group (`networking.k8s.io` for Ingress, `gateway.networking.k8s.io` for the Gateway API kinds), namespace = the query namespace or `None`; the SAR is asked BEFORE the client call; 403 names the denied resource. The converter's Ingress read is gated on `get ingresses`. **EXTENSION:** the new `POST /resources/apply` endpoint is the first generic mutation — it is SAR-gated on `create` per object (asked BEFORE the apply phase, atomic: any deny → 403 before anything is applied). This extends ADR-0004's read-only SAR model to a generic write path (the one-way door). No change to the `can()` mechanism. |
| ADR-0003 (observability query-only) | Unchanged — the converter is a pure computation (no observability source); the Gateway API CRD-absent → `[]` is the VPA seam's first-class empty state (not an observability degrade, but the same "absent is expected, not an error" principle). |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — the Ingress is a core kind (the `NetworkingV1Api`), the Gateway API kinds are CRDs (the VPA CRD seam — `get_crd_served` + the full-custom-object read); no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: `NetworkingV1Api` + `CustomObjectsApi` are already in the kubernetes client (`self._v1`/`self._custom` exist, possibly one new `self._networking` attribute); the converter is stdlib-only (`json`, `string`); the frontend reuses `KubeDataTable`, CoreUI (`CTabs`/`CTab`/`CTabContent` already in the vendored `@coreui/react`), and the already-vendored `react-syntax-highlighter` (`json` + `yaml` grammars already registered by `SecretData.tsx`). |
| ADR-0022 (other-resources placement) | The views live under Network (the 4.1 `network` blueprint grouping) — the ratified nav-placement deviation. The Ingress leaf already exists; the Gateway API leaf is ADDED to the Network group (4.1 had no Gateway API). |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kinds + the apply/convert endpoints via the existing route pattern. |

## Decision created by this change

**One — the `POST /resources/apply` endpoint is the first generic mutation
path (a one-way door).** The 5.0 API was read-only (every resource route is a
`GET`); this change adds a generic `create` path (SAR-gated on `create` per
object, idempotent get-or-create). It is a one-way door because: (a) it
changes the API surface from read-only to read-write for arbitrary kinds, (b)
it is the enabling mechanism for the converter's Apply action (the ratified
preview + apply-to-cluster), and (c) removing it later would break the
converter UI. The Ingress + Gateway API kinds are ADDITIVE (not one-way
doors). The converter service is pure (not a one-way door — it has no
cluster state).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's Ingress list page POSTed a hidden form per
  row (`i_name`) and the data page re-listed then filtered in Python. 5.0
  reaches the data page by query param and does a single `?name=&namespace=`
  read.
- **`/network/gateway-api` is NEW** — 4.1 has no Gateway API at all (only
  Ingress + IngressClass); the four-tab page + the converter are 5.0
  additions, not a 4.1 port.
- **The Gateway API page is a single tabbed page** (ratified 2026-10-28) —
  the kind-per-leaf convention is relaxed for the four Gateway API kinds
  (they are one conceptual surface).
- **The Gateway API kinds use the VPA CRD seam** (full custom objects,
  `get_crd_served` version authority, CRD-absent → `[]`), NOT the core-API
  seam — the Gateway API CRDs are optional (a cluster without them is a
  first-class empty state, not an error).
- **The Ingress data "Routs" table is renamed "Rules"** (the 4.1 typo is
  fixed).
- **The Rules table's Service/TLS cells are plain text, not 4.1's
  hidden-form links** (4.1 linked the service to `/network/service` and the
  TLS secret to `/security/secret`; 5.0's Service page lands separately and
  the secret link is a non-goal, so both render plain text — the full object
  is in the JSON block).
- **The Ingress data GAINS the full-object JSON block** (4.1's data page had
  none).
- **The converter is a Python backend endpoint** (ratified 2026-10-28) — no
  published npm library does Ingress→Gateway API (the ecosystem is Go CLIs:
  `ing-switch`, `ingress2gateway`, AWS LBC toolkit); per the user's call
  (JS-only if an existing library exists, else Python), the mapping is ported
  from `ing-switch`'s Go (`pkg/migrator/gatewayapi/`) to a pure Python
  service.
- **The converter's Apply is a NEW generic `POST /resources/apply`
  endpoint** (the one-way door) — the converter is not read-only (ratified —
  preview + apply-to-cluster); the apply is SAR-gated on `create` per object
  and idempotent (get-or-create).
- **The converter DROPS provider-specific NGINX annotations** (rate-limit,
  forward-auth, IP allow-list, custom headers) with a `warnings` entry,
  rather than emitting provider-specific policy CRDs (Middleware /
  ExtensionHTTPFilter) — those are a follow-up (`ing-switch` emits them as
  separate policy files, which this change does not).
- **The converter emits only the k8s resources** (GatewayClass, Gateway,
  HTTPRoute) — not the `ing-switch` controller/install/verify/cleanup files
  (the `01-install-*`, `02-install-*`, verify script, cleanup).
- **`trimAnnotations` is NOT replicated** — annotations render verbatim (the
  JSON block has the full object, and 5.0 has no trim helper).
  **OVERRIDE 2026-11-05 (user decision, the storage-batch T2):** the trim IS
  now replicated — the two machine-managed keys
  (`kubectl.kubernetes.io/last-applied-configuration`,
  `autoscaling.alpha.kubernetes.io/conditions`) are dropped from the rendered
  annotations tables (the HPA view already trims, 46929a10; the JSON block
  still renders the full object).
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  `list_namespaced_ingress`; 5.0's client uses the pool's configured timeout.

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.

## Execution Notes (2026-11-06)

The frontend executed per the 2026-10-29 session-object-navigation contract
(the blueprint's `/.../data?name=&namespace=&kind=` route shape is not
built):

- ONE clean route per kind — `/network/ingress` (an `ObjectRoute`, registry
  kind `ingress`) and `/network/gateway-api` (a multi-kind dispatcher in the
  `NetworkPolicyRoute` pattern, registry kinds `gateway` / `httproute` /
  `referencegrant`, rendered as a four-tab page with the GatewayClasses tab
  linking to the standalone `/network/gateway-class` route). NO `/.../data`
  routes, NO `OldDataRedirect`: `/network/ingress` was a stub (the `/data`
  URL never shipped) and `/network/gateway-api` is new, so there is no
  legacy route to redirect.
- The data views trim machine-managed annotations (the 2026-11-05 T2
  override recorded in Recorded deviations), not the 2026-10-28 "render
  verbatim" deviation.
- The `POST /resources/apply` route (blueprint Task 6) landed with this
  execution; the `K8sClient.apply_objects` service method (committed
  earlier, untested) now returns `(applied, errors)` per the blueprint
  response shape and sends the FULL object (not `spec` alone) to the
  apiserver.
