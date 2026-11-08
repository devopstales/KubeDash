# Ingress + Gateway API Views (and the converter) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 (Ingress port + Gateway API CRD views) + T2 (the converter
endpoint + the generic `POST /resources/apply` mutation — the one-way door).

**Classification:** `medium-risk` — the Ingress port and the Gateway API CRD
views follow ratified in-repo patterns (namespaced core kind + the VPA CRD
seam), but the change introduces (a) a NEW nav leaf, (b) a NEW pure-Python
converter service ported from `ing-switch`'s Go, and (c) the FIRST generic
mutation endpoint (`POST /resources/apply`). The converter is pure (unit-
testable without a cluster); the apply endpoint is the riskiest surface (new
SAR `create` gate + idempotency).

**Build shape:** Tracer thread —
- **Task 1**: Ingress kind end-to-end (service + `_KINDS`/`_GETTERS` + API).
- **Task 2**: the four Gateway API CRD kinds via the VPA CRD seam +
  `_KINDS`/`_GETTERS` rows + API.
- **Task 3**: the Ingress list + data views (the 4.1 port, with the
  converter entry-point button wired to a not-yet-built endpoint — Task 3
  ships the UI shell; the convert call is stubbed to a pending state until
  Task 5 lands).
- **Task 4**: the Gateway API tabbed page + data view.
- **Task 5**: the converter service (pure Python, ported from `ing-switch`)
  + the `POST /gateway-api/convert` endpoint.
- **Task 6**: the `POST /resources/apply` endpoint + the `K8sClient.apply`
  method (the one-way door).
- **Task 7**: the converter UI (convert → preview → apply → re-fetch) +
  routing + nav leaf + stub removal + full verification.

Each task is independently revertable.

**Goal:** Resolve `/network/ingress` to a real 4.1-parity list + data pair,
resolve `/network/gateway-api` to a real four-tab CRD page (NEW), and ship
the Ingress→Gateway API converter (endpoint + apply + UI).

**Architecture:**
- **Ingress**: `K8sClient.list_ingresses` / `get_ingress` (kubernetes
  `NetworkingV1Api`, group `networking.k8s.io`, namespaced — the
  `list_secrets` / `get_resource_quota` pattern, NO field stripping) + two
  dict rows (`_KINDS`/`_GETTERS`).
- **Gateway API**: four CRD kinds via the **VPA CRD seam** (the
  `get_crd_served` full-custom-object pattern — `list_*`/`get_*` methods that
  resolve the CRD's OWN served version + scope, CRD-absent → `[]`):
  `gatewayclasses` (cluster-scoped), `gateways`/`httproutes` (namespaced),
  `referencegrants` (cluster-scoped) — all group `gateway.networking.k8s.io`.
  Four `_KINDS`/`_GETTERS` rows. NO new `__init__` attribute (`self._custom`
  already exists).
- **Converter**: a PURE Python service `backend/app/services/gateway_convert.py`
  (NO kubernetes import — it takes a parsed Ingress dict + a `provider` and
  returns a list of resource dicts) + a `POST /gateway-api/convert` endpoint
  that reads the Ingress (via `get_ingress`) and calls the converter.
- **Apply**: a NEW generic `POST /resources/apply` endpoint + a
  `K8sClient.apply_objects(namespace, objects)` method that resolves each
  object's `kind`+`apiVersion` to the right `apply_*`/`create_*` call,
  SAR-gated on `create` per object, idempotent (get-or-create).
- **Frontend**: two Ingress views (clone `Security/Secret.tsx` +
  `SecretData.tsx` shape), one four-tab Gateway API page (CoreUI `CTabs` —
  the `CTabs`/`CTab`/`CTabContent` already confirmed in the vendored
  `@coreui/react`), one shared Gateway API data view, and the converter UI
  (a CoreUI modal/panel on the Ingress data page: convert → per-resource YAML
  preview → Apply → re-fetch + per-object result).

**Tech Stack:** kubernetes `NetworkingV1Api` (Ingress — already a
dependency) + `CustomObjectsApi` (the Gateway API CRDs — `self._custom`
already exists), a NEW pure-Python converter service (stdlib only — `json`,
`string` — no new dep), Flask + Smorest (the existing resources blueprint + a
new gateway-api route), React + CoreUI + TanStack Query + MSW (existing), no
new npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R9).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/network/ingress.html.j2`
(list: Name/IngressClass/Hostname — card title EXACTLY `Ingress List`; the
name cell is a hidden-form POST link carrying `i_name` + `ns_select`; the
IngressClass cell links to `/network/ingress-class`; the Hostname cell joins
`spec.rules[].host` one-per-line), `4.1:src/kubedash/templates/network/
ingress-data.html.j2` (data: Name/ingressClass/Created/Annotations(inline
last-applied filter)/Labels("Lables" typo) + a "Routs" table — Host/Path/
Type/Service/Port/TLS — the Service cell links to `/network/service`, the
Port cell is `port.number` else `port.name` else `None`, the TLS cell links
to `/security/secret`; the data page is list-then-filter by `i_name`;
`ingress.status.load_balancer.ingress` is read for the endpoint — a latent
500 on an ingress with no LB ingress), `4.1:src/kubedash/lib/k8s/network.py:56`
(`k8sIngressListGet`: `NetworkingV1Api().list_namespaced_ingress(ns,
_request_timeout=1)`, generates `name`/`ingressClass`/`rules`/`created`/
`annotations`(trimmed)/`labels`/`tls`/`status`/`endpoint`/`hosts`),
`4.1:src/kubedash/blueprint/network.py:70` (the list + data routes). 4.1 has
NO Gateway API (no templates, no reads). In-repo precedents —
`backend/app/services/k8s_client.py:750-790` (the VPA CRD seam —
`list_vertical_pod_autoscalers`/`get_vertical_pod_autoscaler` + the
`_VPA_GROUP`/`_VPA_PLURAL` constants + `get_crd_served` — the EXACT pattern to
clone for the four Gateway API kinds), `backend/app/services/
k8s_client.py:1006-1100` (the `_apply` get-or-create pattern for roles + the
`apply_role`/`apply_role_binding`/`apply_cluster_role`/
`apply_cluster_role_binding` methods — the idempotency pattern to extend for
`apply_objects`), `backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the
`name` branch + the `create_namespace`/`delete_namespace` mutation routes
(the existing mutation pattern to mirror for `POST /resources/apply`),
`frontend/src/views/Security/Secret.tsx` + `SecretData.tsx` (the namespaced
list/data views to clone for Ingress), `frontend/src/views/
OtherResource/VerticalPodAutoscaler.tsx` + `VerticalPodAutoscalerData.tsx`
(if present) or the VPA test files (the CRD-seam view pattern to clone for
the Gateway API tabs), `frontend/src/_nav.tsx:94-96` (the Network group —
where the `Gateway API` leaf is ADDED), `frontend/tests/views/secrets.test.
tsx` + the VPA test files (the test patterns to clone). `ing-switch`
audit — `pkg/migrator/gatewayapi/httproute.go` (the annotation mapping
table — `buildPathMatch`/`buildHeaderMatches`/`buildBackendFilters`/
`buildCORSFilter`/`buildBackendRefs`/`buildTimeouts`/
`generateSplitHTTPRoutes`/`buildHostnameToSection`),
`pkg/migrator/gatewayapi/gateway.go` (the GatewayClass + Gateway generation
— `generateGatewayClass`/`generateGateway`/`buildHostnameList` + the
`EnvoyProvider`/`TraefikProvider` constants), `pkg/migrator/types.go` (the
`Migrator` interface), `pkg/scanner/types.go` (the `IngressInfo`/`PathInfo`
shape — the converter's input contract).

**In-force ADRs:** per `adr.md` — ADR-0003, ADR-0004 (EXTENDED by the apply
endpoint), ADR-0009, ADR-0010, ADR-0020, ADR-0021, ADR-0022.

## Terms

- **Converter** — the pure-Python `gateway_convert.py` service that maps an
  Ingress dict to Gateway API resource dicts (the ported `ing-switch`
  mapping).
- **Apply** — the `K8sClient.apply_objects` method + the
  `POST /resources/apply` endpoint that creates the converter's output in the
  cluster (idempotent get-or-create).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/ingresses?namespace=<ns>` → 200,
  `kind: "ingresses"`, items in `to_dict` snake_case form WITH
  `spec`/`status` present, SAR-gated on `list ingresses` (group
  `networking.k8s.io`, the query namespace), 403 names the resource
  (`ingresses-list-200`, `ingresses-sar-denied`).
- The singular `ingress` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`ingress-kind-singular-rejected`).
- Each Gateway API kind (`gatewayclasses`/`gateways`/`httproutes`/
  `referencegrants`) → 200 with full custom objects (camelCase,
  `spec`/`status` intact) via the VPA CRD seam; CRD-absent → 200 `items: []`
  (first-class empty state); SAR-gated on `list <plural>` (group
  `gateway.networking.k8s.io`) (`gateway-api-kinds-list`,
  `gateway-api-crd-absent-empty`).
- `POST /gateway-api/convert` with a valid Ingress → 200 with a
  `resources` array containing a GatewayClass, a Gateway, and one HTTPRoute
  per rule path (the `ing-switch` mapping); unsupported annotations produce a
  `warnings` entry; a missing Ingress → 404
  (`convert-emits-gatewayclass-gateway-httproute`,
  `convert-warnings-for-unsupported-annotations`, `convert-missing-ingress-404`).
- The converter's annotation mapping is 1:1 with `ing-switch`'s
  `httproute.go` (path type, header match, URLRewrite, CORS, canary weight,
  ssl-redirect split routes, timeouts) (`convert-annotation-mapping-parity`).
- `POST /resources/apply` with the converter's output → 200 with an
  `applied` array (one per object, `created`/`unchanged`); re-applying the
  same objects → `unchanged` (idempotent); a SAR deny on any object → 403
  before anything is applied; a partial failure → 200 with the `errors`
  array (`apply-creates-objects`, `apply-idempotent`,
  `apply-sar-denied-atomic`, `apply-partial-failure`).
- The Ingress list view: card title EXACTLY `Ingress List`; columns
  Name/IngressClass/Hostname; name links to
  `/network/ingress/data?name=&namespace=` (`ingress-list-renders-rows`).
- The Ingress data view: CTable (Name/IngressClass/Created/Labels/
  Annotations) + the Rules table (Host/Path/PathType/Service/Port/TLS) + the
  JSON block + a "Convert to Gateway API" button (`ingress-data-renders`).
- The Gateway API page: four `CTabs` (GatewayClasses/Gateways/HTTPRoutes/
  ReferenceGrants), each a `KubeDataTable` in the VPA-seam shape; card title
  EXACTLY `Gateway API`; the `/network/gateway-api` leaf is ADDED to
  `_nav.tsx` (`gateway-api-tabbed-page`).
- The converter UI: convert → per-resource YAML preview → Apply → re-fetch
  the Gateway API tabs + show the per-object result
  (`converter-ui-convert-apply`).
- `/network/ingress` is gone from `views/Stub/routes.ts`; both Ingress views
  + the gateway-api page + both data routes are routed; the Ingress nav leaf
  is byte-identical; the Gateway API leaf is ADDED
  (`ingress-stub-removed-and-routes-wired`, `gateway-api-leaf-added`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `list_ingresses`, `get_ingress`
  (new); `list_gateway_classes`/`get_gateway_class`,
  `list_gateways`/`get_gateway`, `list_http_routes`/`get_http_route`,
  `list_reference_grants`/`get_reference_grant` (new, the VPA CRD seam);
  `apply_objects` (new, the mutation).
- `backend/app/api/resources.py` — the six `_KINDS`/`_GETTERS` rows (new);
  the `POST /resources/apply` route (new).
- `backend/app/api/gateway_api.py` (new) — the `POST /gateway-api/convert`
  route (or in `resources.py` if it fits the existing blueprint).
- `backend/app/services/gateway_convert.py` (new) — the pure-Python
  converter (the ported `ing-switch` mapping).
- `backend/tests/services/test_k8s_client_ingresses.py` (new).
- `backend/tests/services/test_k8s_client_gateway_api.py` (new).
- `backend/tests/services/test_gateway_convert.py` (new) — the converter's
  pure-function tests (the mapping-table parity).
- `backend/tests/api/test_resources.py` (extend) — the Ingress + Gateway API
  kind tests + the apply endpoint tests.
- `frontend/src/lib/types.ts` — `IngressItem`, `GatewayClassItem`,
  `GatewayItem`, `HTTPRouteItem`, `ReferenceGrantItem`, `ConvertedResource`
  (modified).
- `frontend/src/views/Network/Ingress.tsx` (new).
- `frontend/src/views/Network/IngressData.tsx` (new).
- `frontend/src/views/Network/GatewayApi.tsx` (new) — the four-tab page.
- `frontend/src/views/Network/GatewayApiData.tsx` (new).
- `frontend/src/views/Network/GatewayConverter.tsx` (new) — the converter
  UI (convert → preview → apply).
- `frontend/tests/views/ingresses.test.tsx` (new).
- `frontend/tests/views/ingress_data.test.tsx` (new).
- `frontend/tests/views/gateway_api.test.tsx` (new).
- `frontend/tests/views/gateway_converter.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/src/_nav.tsx`, `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior per kind (the
  same route branch serves list AND `?name=`); six kinds land as six pairs
  in the same commit as their service methods.
- The four Gateway API kinds use the VPA CRD seam — `get_crd_served`
  resolves the CRD's OWN served version + scope; CRD-absent → `[]` (the
  first-class empty state). The cluster-scoped kinds (`gatewayclasses`,
  `referencegrants`) use `list_cluster_custom_object` /
  `get_cluster_custom_object`; the namespaced kinds (`gateways`,
  `httproutes`) use `list_namespaced_custom_object` /
  `get_namespaced_custom_object` when the scope is Namespaced (the VPA
  seam's scope authority).
- The converter is PURE (no kubernetes import) — it takes a parsed Ingress
  dict + a `provider` string and returns a list of resource dicts. The
  endpoint does the Ingress read (via `get_ingress`) and the converter does
  the mapping — the unit tests exercise the converter without a cluster.
- The converter's annotation mapping is 1:1 with `ing-switch`'s
  `httproute.go` — the parity test (`convert-annotation-mapping-parity`)
  asserts each mapping (path type, header, URLRewrite, CORS, canary weight,
  ssl-redirect split, timeouts) against a known Ingress fixture.
- The Apply endpoint is the FIRST generic mutation — it resolves each
  object's `kind`+`apiVersion` to the right `apply_*`/`create_*` call. The
  SAR gate is `create` per object, asked BEFORE the apply phase (atomic: any
  deny → 403 before anything is applied); the apply is idempotent
  (get-or-create, the `_apply` pattern).
- The converter UI's Apply flow: convert (R7) → apply (R8) → re-fetch the
  Gateway API tabs (so the new resources appear) → show the per-object
  result (`applied`/`errors`). The re-fetch is the load-bearing link (the
  applied resources must appear without a manual refresh).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set: removing `/network/ingress` from `stubRoutes`
  WITHOUT adding it to `viewPaths` is a RED suite; ADDING the
  `/network/gateway-api` leaf to the nav requires the Gateway API path in
  `viewPaths` (else the new leaf is expected to be a stub).

**One-way-door decisions:** the `POST /resources/apply` endpoint is the
first generic mutation path (the cluster-registry schema and the
`KUBEDASH_SECRET_KEY` encryption are the existing one-way doors; the apply
endpoint is a new one — it changes the API from read-only to read-write for
arbitrary kinds). The Ingress + Gateway API kinds are additive (not one-way
doors).

## Global Constraints

- No new Python dependency — `NetworkingV1Api` + `CustomObjectsApi` are
  already in the kubernetes client; the converter is stdlib-only (`json`,
  `string`); `self._v1` + `self._custom` already exist (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by `SecretData.tsx` (the `json` grammar already registered);
  `@coreui/react` already exports `CTabs`/`CTab`/`CTabContent` (confirmed).
- The Gateway API group is `gateway.networking.k8s.io`; the CRD plurals are
  `gatewayclasses` (cluster-scoped), `gateways`/`httproutes` (namespaced),
  `referencegrants` (cluster-scoped).
- The Ingress kind is `ingresses`, group `networking.k8s.io`, namespaced
  (the `NetworkingV1Api` — a core-API model, snake_case `to_dict`).
- The converter output resources use `apiVersion:
  gateway.networking.k8s.io/v1` (the Standard channel, `ing-switch`'s
  target).
- The Apply endpoint is the first generic mutation — the SAR gate is
  `create` per object (ADR-0004 EXTENDED), asked before the apply phase
  (atomic); the apply is idempotent (get-or-create).
- The full-object blocks are `JSON.stringify(item, null, 2)` with hljs
  grammar `json`, style `anOldHope` (the truthful-classifier rule).
- Card titles EXACTLY: `Ingress List`, `Gateway API` (the e2e-smoke
  contracts).
- Pinned copy (do not reword): `No ingresses found`,
  `No Ingress '<name>' found`, `Error: ingress name not provided`,
  `No <kind> found`, `No <Kind> '<name>' found`,
  `Error: gateway api kind not provided`, `Error: gateway api name not
  provided`, `No cluster selected.`, `Loading ingresses...`, `Loading
  <kind>...`, `No labels`, `No annotations`, `No rules`,
  `No pods match this service's selector` (n/a here — keep per-view).
- Conventional commits; spec-zone commits precede code-zone commits;
  WHY-comments on load-bearing invariants (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too — type any new test
  params explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_ingresses`/
  `get_ingress` next to `list_secrets`/`get_secret` (line ~822/839); the four
  Gateway API CRD-seam methods next to the VPA methods (line ~750); the
  `apply_objects` method next to the `_apply`/`apply_*` family (line ~1006).
- `backend/app/api/resources.py` (modify) — the six `_KINDS`/`_GETTERS` rows;
  the `POST /resources/apply` route (after `delete_namespace`, line ~240).
- `backend/app/api/gateway_api.py` (new) — the `POST /gateway-api/convert`
  route (a new Smorest `Api` in the existing resources namespace, or a route
  in `resources.py` — the blueprint prefers a new `gateway_api.py` for the
  domain separation).
- `backend/app/services/gateway_convert.py` (new) — the pure-Python
  converter (the ported `ing-switch` mapping table).
- `backend/tests/services/test_k8s_client_ingresses.py` (new).
- `backend/tests/services/test_k8s_client_gateway_api.py` (new).
- `backend/tests/services/test_gateway_convert.py` (new) — the converter's
  pure-function tests.
- `backend/tests/api/test_resources.py` (modify) — the Ingress + Gateway API
  kind tests + the apply endpoint tests.
- `frontend/src/lib/types.ts` (modify) — the five k8s item types + the
  `ConvertedResource` type.
- `frontend/src/views/Network/Ingress.tsx` (new).
- `frontend/src/views/Network/IngressData.tsx` (new).
- `frontend/src/views/Network/GatewayApi.tsx` (new) — the four-tab page.
- `frontend/src/views/Network/GatewayApiData.tsx` (new).
- `frontend/src/views/Network/GatewayConverter.tsx` (new) — the converter UI.
- `frontend/tests/views/ingresses.test.tsx` (new).
- `frontend/tests/views/ingress_data.test.tsx` (new).
- `frontend/tests/views/gateway_api.test.tsx` (new).
- `frontend/tests/views/gateway_converter.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — the four routes + the imports.
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 16
  (`/network/ingress`).
- `frontend/src/_nav.tsx` (modify) — ADD the `Gateway API` leaf to the
  Network group (after the Ingress leaf).
- `frontend/tests/views/Stub.test.tsx` (modify) — add `/network/ingress` +
  `/network/gateway-api` to the `viewPaths` set.

---

### Task 1: Backend — Ingress kind (service + `_KINDS` + API tests)

**SATISFIES:** `ingresses-list-200`, `ingresses-sar-denied`,
`ingress-kind-singular-rejected`, `ingresses-get-by-name`,
`ingresses-binding-404`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_ingresses.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing (first code task).
- Produces: `K8sClient.list_ingresses(namespace: str | None) -> list[dict]`
  and `K8sClient.get_ingress(namespace: str, name: str) -> list[dict]` —
  the exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory.
- Deletion test: delete the two rows → the kind 404s again; delete the
  methods → the service tests fail.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** — mirror the secrets
  pattern with `object.__new__` + `SimpleNamespace` (a `NetworkingV1Api`
  fake for `list_namespaced_ingress` / `read_namespaced_ingress` /
  `list_ingress_for_all_namespaces`): assert the namespaced branch, the
  all-namespaces branch, `to_dict` form with `spec`/`status` present (NOT
  stripped), 404 → `[]` on the getter, 500 → `ClusterUnreachableError`.
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Implement** — `list_ingresses` next to `list_secrets`
  (line ~822, using `self._networking` — verify the attribute exists, else
  add `self._networking = k8s_client.NetworkingV1Api(api_client)` to
  `__init__`):
  ```python
  def list_ingresses(self, namespace: str | None) -> list[dict[str, Any]]:
      """Ingress list in the standard kubernetes dict form (``to_dict``) for
      one namespace, or across all namespaces when ``None`` (the
      ``list_secrets`` branch). UNLIKE ``list_secrets`` this does NOT strip
      any field: an Ingress's ``spec`` (rules, tls, ingress_class_name) and
      ``status`` (load_balancer) are public, and the data page's Rules table
      + the converter read them — stripping would break both. A transport
      ApiException maps to ``ClusterUnreachableError`` (502)."""
      try:
          resp = (
              self._networking.list_namespaced_ingress(namespace)
              if namespace
              else self._networking.list_ingress_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_ingresses", e)
          raise AssertionError("unreachable") from e
      return [i.to_dict() for i in resp.items]

  def get_ingress(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One Ingress (full ``spec``/``status`` intact) as a 0/1-item list;
      ``[]`` on 404. Any other ApiException maps to
      ``ClusterUnreachableError`` (502), matching ``get_secret``'s contract."""
      try:
          return [self._networking.read_namespaced_ingress(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_ingress", e)
          raise AssertionError("unreachable") from e
  ```
- [ ] **Step 4: Wire the kind + write the failing API tests** —
  ```python
  # Ingress (networking.k8s.io, namespaced) — the 4.1-parity nav leaf
  # resolved by the ingress-gateway-api-views change. The 4.1 route name was
  # "ingress"; the API kind is the plural.
  "ingresses": ("list_ingresses", "ingresses", "networking.k8s.io"),
  ```
  in `_KINDS`, `"ingresses": "get_ingress"` in `_GETTERS`. Then 5 API tests
  (200, all-namespaces, get-by-name, SAR deny with group
  `networking.k8s.io` + namespace, binding 404, singular rejected).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(resources): ingresses kind (networking.k8s.io, namespaced, SAR-gated)"`

### Task 2: Backend — four Gateway API CRD kinds (VPA seam + `_KINDS` + API tests)

**SATISFIES:** `gateway-api-kinds-list`, `gateway-api-crd-absent-empty`,
`gateway-api-sar-denied`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_gateway_api.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: Task 1's `pool` seam (independent — the Gateway API kinds are a
  separate CRD-seam family).
- Produces: `list_gateway_classes`/`get_gateway_class`,
  `list_gateways`/`get_gateway`, `list_http_routes`/`get_http_route`,
  `list_reference_grants`/`get_reference_grant` — the exact names
  `_KINDS`/`_GETTERS` reference.
- Seam: the VPA CRD seam (`get_crd_served` + `self._custom`).
- Deletion test: delete the eight rows → the four kinds 404 again; delete
  the methods → the service tests fail.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing service tests** — clone the VPA service
  test pattern (`get_crd_served` mocked to a served version + scope; the
  `self._custom()` fake for `list_namespaced_custom_object` /
  `list_cluster_custom_object` / `get_*`): for each of the four kinds,
  assert the served-version authority, the namespaced vs cluster-scoped
  branch (the scope from `get_crd_served`), CRD-absent → `[]`, getter 404 →
  `[]`, full custom-object shape (camelCase, `spec` intact).
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Implement** — next to the VPA methods (line ~750), the
  `_GATEWAY_API_GROUP = "gateway.networking.k8s.io"` constant + the four
  pairs (clone `list_vertical_pod_autoscalers` /
  `get_vertical_pod_autoscaler` 1:1, swapping the plural + the scope
  authority — `gatewayclasses`/`referencegrants` are cluster-scoped,
  `gateways`/`httproutes` are namespaced, but the SEAM uses the CRD's OWN
  scope as the authority, so the same method shape works for all four):
  ```python
  _GATEWAY_API_GROUP = "gateway.networking.k8s.io"
  _GATEWAY_CLASSES_PLURAL = "gatewayclasses"   # cluster-scoped
  _GATEWAYS_PLURAL = "gateways"                # namespaced
  _HTTP_ROUTES_PLURAL = "httproutes"           # namespaced
  _REFERENCE_GRANTS_PLURAL = "referencegrants"  # cluster-scoped

  def _list_gateway_api_kind(self, plural: str, namespace: str | None) -> list[dict[str, Any]]:
      """Shared VPA-seam list for a Gateway API kind (full custom object,
      the CRD's OWN served version + scope as authority, CRD-absent ->
      ``[]``). The four kinds share this; the plural is the only varying
      input."""
      served = self.get_crd_served(self._GATEWAY_API_GROUP, plural)
      if served is None:
          return []
      version, scope = served
      custom = self._custom()
      try:
          resp = (
              custom.list_namespaced_custom_object(
                  self._GATEWAY_API_GROUP, version, namespace, plural
              )
              if namespace and scope == "Namespaced"
              else custom.list_cluster_custom_object(
                  self._GATEWAY_API_GROUP, version, plural
              )
          )
      except ApiException as e:
          self._unreachable(f"list_{plural}", e)
          raise AssertionError("unreachable") from e
      items = resp.get("items") or []
      return [item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else item) for item in items]

  # the four public wrappers (the _KINDS names) + the four getters
  # (the same shape, using get_namespaced_custom_object /
  # get_cluster_custom_object, 404 -> [])
  def list_gateway_classes(self, namespace: str | None) -> list[dict[str, Any]]:
      return self._list_gateway_api_kind(self._GATEWAY_CLASSES_PLURAL, namespace)
  # ... etc for gateways / httproutes / referencegrants
  ```
- [ ] **Step 4: Wire the kinds + write the failing API tests** — six rows
  (four `_KINDS` + four `_GETTERS`), group `gateway.networking.k8s.io`. API
  tests per kind: 200 (full custom object), CRD-absent → `items: []`, SAR
  deny (group + the namespace or None), binding 404, singular rejected
  (e.g. `/resources/gatewayclass` → 404).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(resources): gateway api crd kinds (gatewayclass/gateway/httproute/referencegrant, VPA seam)"`

### Task 3: Frontend — Ingress list + data views + tests

**SATISFIES:** `ingress-list-renders-rows`, `ingress-data-renders`,
`ingress-data-not-found-state`, `ingress-data-missing-name`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Network/Ingress.tsx`
- Create: `frontend/src/views/Network/IngressData.tsx`
- Test: `frontend/tests/views/ingresses.test.tsx` (new)
- Test: `frontend/tests/views/ingress_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `ingresses` list + `?name=&namespace=` URLs).
- Produces: the data-page link
  `/network/ingress/data?name=<name>&namespace=<ns>` (the sole producer).
- Seam: `apiFetch` + TanStack Query + `useClusterStore`.
- Deletion test: deleting the views → the routes (Task 7) 404 / the tests
  fail at import.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `IngressItem` next to `K8sSecret`:
  ```ts
  /** An Ingress item (kubernetes to_dict, snake_case; namespaced, networking.k8s.io). spec/status present (NOT stripped). */
  export interface IngressItem {
    metadata?: { name?: string; namespace?: string; creation_timestamp?: string;
      resource_version?: string; labels?: Record<string, string>;
      annotations?: Record<string, string> }
    spec?: {
      ingress_class_name?: string
      rules?: { host?: string; http?: { paths?: {
        path?: string; path_type?: string;
        backend?: { service?: { name?: string; port?: { number?: number; name?: string } } } } } }[]
      tls?: { hosts?: string[]; secret_name?: string }[]
    }
    status?: { load_balancer?: { ingress?: { ip?: string; hostname?: string }[] } }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone `secrets.test.tsx`:
  list (card title `Ingress List`, columns Name/IngressClass/Hostname,
  name link, Hostname = `spec.rules[].host` joined, no-cluster, empty) +
  data (CTable + Rules table + JSON block + the Convert button present,
  not-found state, missing-name).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `Ingress.tsx` (clone `Security/Secret.tsx`,
  the Hostname column = `item.spec?.rules?.map(r => r.host).filter(Boolean)
  .join(', ') || '—'`); `IngressData.tsx` (clone `Security/SecretData.tsx`
  shape — the CTable + KeyValueTable sub-tables + the Rules table
  (Host/Path/PathType/Service/Port/TLS) + the JSON block + a
  "Convert to Gateway API" `CButton` that renders the
  `GatewayConverter` component (Task 7) — in Task 3 the button is present
  but the converter is a placeholder until Task 7).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): ingress list + data views (4.1 port, rules table)"`

### Task 4: Frontend — Gateway API tabbed page + data view + tests

**SATISFIES:** `gateway-api-tabbed-page`, `gateway-api-data-renders`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Network/GatewayApi.tsx`
- Create: `frontend/src/views/Network/GatewayApiData.tsx`
- Test: `frontend/tests/views/gateway_api.test.tsx` (new)

**Interfaces:**
- Consumes: Task 2's API (the four Gateway API kind URLs).
- Produces: the data-page links
  `/network/gateway-api/data?name=&namespace=&kind=` (the sole producers).
- Seam: `apiFetch` + TanStack Query (four queries, one per tab) +
  `useClusterStore`.
- Deletion test: deleting the views → the routes (Task 7) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the types** — `GatewayClassItem`/`GatewayItem`/
  `HTTPRouteItem`/`ReferenceGrantItem` (full custom objects, camelCase —
  the CRD-seam shape, like `VerticalPodAutoscalerItem`).
- [ ] **Step 2: Write the failing view tests** — the four tabs render their
  columns (GatewayClasses: Name/Controller/Age; Gateways: Name/
  GatewayClass/Listeners; HTTPRoutes: Name/Hostnames/ParentRefs;
  ReferenceGrants: Name/From/To); CRD-absent → the empty state per tab;
  the data view renders the kind's fields + the JSON block; a bad `kind`
  param → the error line.
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `GatewayApi.tsx` (a CoreUI `CTabs` page, four
  `CTab`s, each a `KubeDataTable` against its kind's URL — the cluster-
  scoped tabs send NO `namespace`, the namespaced tabs send
  `?namespace=`); `GatewayApiData.tsx` (reads `?name=&namespace=&kind=`,
  validates `kind` against the closed set, fetches via the kind's URL,
  renders the kind's CTable + Labels/Annotations + the JSON block;
  NOT_FOUND as a state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): gateway api tabbed page + data view (VPA seam)"`

### Task 5: Backend — converter service + convert endpoint

**SATISFIES:** `convert-emits-gatewayclass-gateway-httproute`,
`convert-annotation-mapping-parity`,
`convert-warnings-for-unsupported-annotations`,
`convert-missing-ingress-404`

**Files:**
- Create: `backend/app/services/gateway_convert.py` (new)
- Create: `backend/app/api/gateway_api.py` (new)
- Test: `backend/tests/services/test_gateway_convert.py` (new)
- Test: `backend/tests/api/test_gateway_api.py` (new)

**Interfaces:**
- Consumes: Task 1's `get_ingress` (the endpoint reads the Ingress).
- Produces: the pure converter `convert_ingress(ingress: dict, provider:
  str) -> tuple[list[dict], list[str]]` (resources + warnings) + the
  `POST /gateway-api/convert` route.
- Seam: the converter is PURE (no kubernetes import) — unit-testable
  without a cluster; the endpoint uses the `pool` seam for the Ingress read.
- Deletion test: delete the converter → the endpoint 500s; delete the
  endpoint → the UI's convert call 404s.
- Adapters: 1 (the endpoint); the converter is a pure function (no adapter).

- [ ] **Step 1: Write the failing converter tests** — the parity suite
  (the load-bearing task): known Ingress fixtures → assert the generated
  resources 1:1 with `ing-switch`'s mapping:
  - a simple Ingress (one host, one path, one service) → a GatewayClass + a
    Gateway + one HTTPRoute (the `backendRefs` to the service).
  - an Ingress with `rewrite-target` → the HTTPRoute has a `URLRewrite`
    filter (`ReplaceFullPath`).
  - an Ingress with `canary: true` + `canary-weight: 30` → the backendRef
    has `weight: 30`.
  - an Ingress with `enable-cors: true` + the cors-* annotations → a `CORS`
    filter (allowOrigins/allowMethods/allowHeaders/allowCredentials/maxAge).
  - an Ingress with `force-ssl-redirect: true` + a TLS secret → TWO
    HTTPRoutes (the `<name>-redirect` with `RequestRedirect` on
    `sectionName: http` + the backend route on `sectionName: https-0`).
  - an Ingress with `proxy-read-timeout: 30s` → `timeouts.backendRequest`.
  - an Ingress with a regex path (`use-regex` or `()` chars) →
    `path.type: RegularExpression`.
  - an Ingress with `canary-by-header` → `matches[].headers`.
  - an Ingress with an unsupported annotation (e.g. `limit-rps`) → a
    `warnings` entry (the annotation is dropped, not converted).
  - the `provider` param: `envoy` (default) → `eg` GatewayClass; `traefik`
    → `traefik` GatewayClass.
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Implement the converter** — `gateway_convert.py` (pure
  Python, porting `ing-switch`'s `httproute.go`/`gateway.go` mapping table —
  the functions `build_path_match`/`build_header_matches`/
  `build_backend_filters`/`build_cors_filter`/`build_backend_refs`/
  `build_timeouts`/`generate_gateway`/`generate_gateway_class`/
  `generate_http_route`/`generate_split_http_routes`/
  `build_hostname_to_section`): the entry point
  `convert_ingress(ingress: dict, provider: str = "envoy") ->
  tuple[list[dict], list[str]]` (the resources list + the warnings list).
  The provider constants (the `EnvoyProvider`/`TraefikProvider` mapping).
- [ ] **Step 4: Implement the endpoint** — `gateway_api.py` (a new Smorest
  `Api`, the `POST /clusters/<id>/gateway-api/convert` route): read the
  Ingress via `get_ingress` (SAR `get ingresses`, the R2 gate; `[]` → 404
  "Ingress '<name>' not found"), call `convert_ingress`, return
  `{ cluster, namespace, source: "ingress", gatewayClassName, resources,
  warnings }`.
- [ ] **Step 5: Write the endpoint tests** — the happy path (a bound user,
  a fixture Ingress → 200 with the resources), the missing-Ingress 404, the
  SAR deny 403 (on the Ingress read), the binding 404.
- [ ] **Step 6: Run, confirm GREEN.**
- [ ] **Step 7: Commit** —
  `git commit -m "feat(gateway-api): ingress->gateway api converter (port of ing-switch mapping)"`

### Task 6: Backend — `POST /resources/apply` endpoint + `apply_objects` (the one-way door)

**SATISFIES:** `apply-creates-objects`, `apply-idempotent`,
`apply-sar-denied-atomic`, `apply-partial-failure`

**Files:**
- Modify: `backend/app/services/k8s_client.py` (`apply_objects`)
- Modify: `backend/app/api/resources.py` (the `POST /resources/apply` route)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: the `pool` seam + the `rbac.can` gate.
- Produces: `K8sClient.apply_objects(namespace: str, objects: list[dict]) ->
  tuple[list[dict], list[dict]]` (applied + errors) + the route.
- Seam: the `_apply` get-or-create pattern (line ~1006) extended to resolve
  arbitrary `kind`+`apiVersion`.
- Deletion test: delete `apply_objects` → the route 500s; delete the route
  → the UI's apply call 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing API tests** — a FakeK8s with
  `apply_objects`: the happy path (two objects → `applied` with
  `created`), idempotency (re-apply → `unchanged`), the SAR deny (a denied
  `create` → 403 before anything is applied — assert the
  `apply_objects` was NEVER called when any object is denied), the partial
  failure (one object errors → 200 with the `errors` array), the binding
  404.
- [ ] **Step 2: Run, confirm RED.**
- [ ] **Step 3: Implement `apply_objects`** — resolve each object's
  `kind`+`apiVersion` to the right `apply_*`/`create_*` call (the Gateway
  API kinds: `apply_gateway_class`/`apply_gateway`/`apply_http_route`/
  `apply_reference_grant` — or a generic `CustomObjectsApi`
  `create_namespaced_custom_object`/`patch` for the CRD kinds); idempotent
  (get-or-create, the `_apply` pattern); return the per-object result
  (`created`/`unchanged`/error).
- [ ] **Step 4: Implement the route** — `POST /resources/apply` (body
  `{ namespace, objects }`): the binding gate; the SAR `create` per object
  (atomic: any deny → 403 BEFORE the apply phase); call `apply_objects`;
  return `{ applied, errors }` (a partial failure is 200 with `errors`, NOT
  a 500).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(resources): generic apply endpoint (create SAR-gated, idempotent) — one-way door"`

### Task 7: Frontend — converter UI + routing + nav leaf + stub removal + full verification

**SATISFIES:** `converter-ui-convert-apply`,
`ingress-stub-removed-and-routes-wired`, `gateway-api-leaf-added`

**Files:**
- Create: `frontend/src/views/Network/GatewayConverter.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/src/_nav.tsx`
- Modify: `frontend/tests/views/Stub.test.tsx`
- Test: `frontend/tests/views/gateway_converter.test.tsx` (new)

**Interfaces:**
- Consumes: Tasks 3–6 (the Ingress data view's Convert button, the convert
  endpoint, the apply endpoint, the Gateway API tabs for the re-fetch).
- Produces: the resolved nav leaves (the goal).
- Seam: `apiFetch` + `useSearchParams` + TanStack Query (invalidate the
  Gateway API tab queries after apply).
- Deletion test: delete the routes → the paths 404; delete the nav leaf →
  the Gateway API page is unreachable.
- Adapters: 0 (the UI) + the convert/apply fetches.

- [ ] **Step 1: Implement the converter UI** —
  `GatewayConverter.tsx` (rendered by the Ingress data view's Convert
  button, a CoreUI `CModal` or a sub-panel):
  - a `provider` select (`envoy`/`traefik`, default `envoy`).
  - a "Convert" `CButton` → `POST /gateway-api/convert` with the Ingress's
    `name` + `namespace` → render the generated resources as per-resource
    YAML tabs (GatewayClass / Gateway / each HTTPRoute) in a
    `<SyntaxHighlighter language="yaml">` block (register the `yaml`
    grammar — `SecretData.tsx` already does).
  - a `warnings` line (the dropped annotations, if any).
  - an "Apply" `CButton` → `POST /resources/apply` with the `resources` →
    show the per-object result (`applied` green / `errors` red) →
    **invalidate the Gateway API tab queries** (the applied resources
    appear without a manual refresh — the load-bearing re-fetch link) →
    close the modal.
- [ ] **Step 2: Write the converter UI tests** — `gateway_converter.test.
  tsx`: the convert flow (a fixture Ingress → the YAML tabs render), the
  apply flow (the apply response → the per-object result + the tab-query
  invalidation), the warnings line, the provider select.
- [ ] **Step 3: Wire the routes** — `App.tsx`: the four routes
  (`/network/ingress` + `/data`, `/network/gateway-api` + `/data`) + the
  imports.
- [ ] **Step 4: Nav + stub** — `views/Stub/routes.ts`: drop line 16
  (`/network/ingress`). `_nav.tsx`: ADD `leaf('Gateway API',
  '/network/gateway-api')` to the Network group (after the Ingress leaf).
  Verify with `git diff --stat` that ONLY the leaf was added (no other nav
  change).
- [ ] **Step 5: Update Stub.test.tsx** — add `/network/ingress` +
  `/network/gateway-api` to the `viewPaths` set. Re-run
  `corepack pnpm vitest run tests/views/Stub.test.tsx`.
- [ ] **Step 6: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — the new types +
    the converter UI must typecheck).
  - `task fe-check` (air-gap — no new external refs).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures are the baseline).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).
- [ ] **Step 7: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/src/_nav.tsx frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire ingress + gateway-api routes, add gateway api nav leaf, remove ingress stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_ingresses.py tests/services/test_k8s_client_gateway_api.py tests/services/test_gateway_convert.py tests/api/test_resources.py tests/api/test_gateway_api.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/ingresses.test.tsx tests/views/ingress_data.test.tsx tests/views/gateway_api.test.tsx tests/views/gateway_converter.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` shows ONLY the added leaf; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (Ingress kind) ──────────────► Task 3 (Ingress views) ─────────┐
Task 2 (Gateway API kinds) ─────────► Task 4 (Gateway API page) ───────┤
Task 1 (Ingress kind) ──► Task 5 (converter + convert endpoint) ──────┤
Task 5 (converter) ────► Task 6 (apply endpoint) ─────────────────────┤
Task 3 + 4 + 5 + 6 ─────► Task 7 (converter UI + routing + nav) ───────┘
```

Tasks 3 and 4 are independent of each other (both consume Tasks 1/2). Task
5 consumes Task 1 (the Ingress read). Task 6 consumes Task 5 (the converter
output is what it applies). Task 7 last (it wires the routes + nav + the
converter UI, so all the pieces must exist first).

## Rollback

Each task is one conventional commit and independently revertable. The
one-way door is Task 6 (the `POST /resources/apply` endpoint) — reverting
it removes the generic mutation path (the converter UI's Apply button 404s
and degrades to a preview-only state, which is a valid degraded state, not a
broken one). Reverting Task 7 is self-contained (routes + nav + stub + test
in one commit). Reverting Tasks 1–5 individually leaves the other views
working (the stub for the reverted kind's route reappears, or the view 404s
— a degraded state, not a crash).
