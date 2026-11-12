# IngressClass + GatewayClass Views (List + Data) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pairs on existing generic routes; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, both patterns already
ratified in-repo: IngressClass is a cluster-scoped core kind — the
`list_nodes`/`list_priority_classes`/`list_runtime_classes` family;
GatewayClass is a cluster-scoped CRD — the VPA/Cilium CRD seam. The 4.1
template pair is the source of truth for the IngressClass page shape; the
GatewayClass shape follows the 5.0 CRD-list convention).

**Build shape:** Tracer thread — Task 1 proves both kinds end-to-end in the
backend (service methods → `_KINDS`/`_GETTERS` rows → API route → SAR deny)
before any frontend exists; Task 2 is the IngressClass views; Task 3 the
GatewayClass views; Task 4 the routing + nav. Each task is independently
revertable.

**Goal:** Resolve the nav leaves `/network/ingress-class` (the 4.1 port) and
`/network/gateway-class` (NEW) to real, SAR-gated, read-only list + data
pairs.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds TWO kinds:
- **IngressClass** (cluster-scoped core, group `networking.k8s.io`):
  `K8sClient.list_ingress_classes` / `get_ingress_class` (kubernetes
  `NetworkingV1Api`, the `list_runtime_classes`/`get_runtime_class`
  cluster-scoped pattern — the namespace is accepted and ignored) + two dict
  rows. ONE new `__init__` attribute: `self._networking =
  k8s_client.NetworkingV1Api(api_client)` (verify it doesn't already exist —
  the `ingress-gateway-api-views` spec, if it lands first, adds it too; this
  spec adds it if absent, and that spec reuses it).
- **GatewayClass** (cluster-scoped CRD, group `gateway.networking.k8s.io`):
  `K8sClient.list_gateway_classes` / `get_gateway_class` (the **VPA CRD
  seam** — `get_crd_served` version + scope authority, full custom object,
  CRD-absent → `[]`) + two dict rows. NO new `__init__` attribute
  (`self._custom` already exists). **This spec owns these methods + rows**
  (the companion `ingress-gateway-api-views` spec reuses / dedupes them).

Frontend: four views (IngressClass list cloned from
`OtherResource/PriorityClass.tsx` for the cluster-scoped layout, IngressClass
data cloned from `PriorityClassData.tsx` for the CTable + Parameters table +
JSON block; GatewayClass list cloned from the PriorityClass list, GatewayClass
data cloned from the PriorityClass data), `IngressClassItem` +
`GatewayClassItem` types, App.tsx routes, the two nav leaves ADDED.

**Tech Stack:** kubernetes `NetworkingV1Api` (IngressClass — already a
dependency; one possible new attribute `self._networking`) +
`CustomObjectsApi` (GatewayClass — `self._custom` already exists), Flask +
Smoarest (existing route), React + CoreUI + TanStack Query + MSW (existing),
no new npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R9).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/network/ingress-class.
html.j2` (list: Name/Controller/Created — card title EXACTLY `IngressClass
List`; the name cell is a hidden-form POST link carrying `ic_name` +
`ns_select`), `4.1:src/kubedash/templates/network/ingress-class-data.html.j2`
(data: Name/Created/Annotations(inline last-applied filter)/Labels("Lables"
typo line 65)/Controller + a conditional Parameters table — 4.1 iterates
`parameters.items()` (the dict's keys); the data page is list-then-filter by
`ic_name`), `4.1:src/kubedash/lib/k8s/network.py:15`
(`k8sIngressClassListGet`: `NetworkingV1Api().list_ingress_class(
_request_timeout=1)`, generates `name`/`created`/`annotations`(trimmed)/
`labels`/`controller` + conditional `parameters` (the `to_dict` of
`spec.parameters`, a `LocalObjectReference`)), `4.1:src/kubedash/blueprint/
network.py:24` (the list + data routes). 4.1 has NO Gateway API. In-repo
precedents —
`backend/app/services/k8s_client.py:285-296` (the `list_runtime_classes`
cluster-scoped core-kind pattern to mirror for `list_ingress_classes` —
`list_runtime_class` → `list_ingress_class`), `backend/app/services/
k8s_client.py:961-975` (the `get_runtime_class` cluster-scoped getter to
mirror for `get_ingress_class`), `backend/app/services/k8s_client.py:750-800`
(the VPA CRD seam — `list_vertical_pod_autoscalers`/
`get_vertical_pod_autoscaler` + the `_VPA_GROUP`/`_VPA_PLURAL` constants +
`get_crd_served` — the EXACT pattern to mirror for the GatewayClass methods;
the only difference is the group + plural + the cluster-scoped call:
`list_cluster_custom_object` / `get_cluster_custom_object`),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch (line
~104-114, the `namespace = namespace or "default"` fallback — irrelevant for
a cluster-scoped read), `backend/tests/api/test_resources.py` (the
priorityclasses/runtimeclasses API tests to mirror: 200, ignores namespace,
get-by-name, SAR deny with namespace `None`, binding 404, singular kind
rejected), `frontend/src/views/OtherResource/PriorityClass.tsx` +
`PriorityClassData.tsx` (the cluster-scoped list/data views to clone — no
namespace selector, the CTable + sub-tables + JSON block; the
`NOT_FOUND`-as-throw-not-found-state pattern),
`frontend/tests/views/priority_classes.test.tsx` +
`priority_class_data.test.tsx` (the cluster-scoped test patterns to clone),
`frontend/src/_nav.tsx:94-97` (the Network group — where the two leaves are
ADDED).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0009, ADR-0010, ADR-0020,
ADR-0021, ADR-0022. None created.

## Terms

None (the spec's vocabulary; "IngressClass" / "GatewayClass" are the k8s
kinds, not new terms).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/ingressclasses` → 200, `kind: "ingressclasses"`, items
  in `to_dict` snake_case form, SAR-gated on `list ingressclasses` (group
  `networking.k8s.io`, namespace `None`), 403 names the resource and the
  client call is never made on deny (`ingressclasses-list-200`,
  `ingressclasses-sar-denied`).
- A `namespace` param is accepted and ignored (cluster-scoped) — the client
  uses `list_ingress_class` (`ingressclasses-list-ignores-namespace`).
- `?name=` returns a 0/1-item list through the SAME route — hit = the object,
  miss = `[]` (`ingressclasses-get-by-name`).
- The singular `ingressclass` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`ingressclass-kind-singular-rejected`).
- `GET .../resources/gatewayclasses` → 200 with full custom objects
  (camelCase, `spec` intact) via the VPA CRD seam; CRD-absent → 200 `items:
  []`; SAR-gated on `list gatewayclasses` (group `gateway.networking.k8s.io`,
  namespace `None`) (`gatewayclasses-list-200`,
  `gatewayclasses-crd-absent-empty`, `gatewayclasses-sar-denied`).
- `GET .../resources/gatewayclasses?name=<name>` → 0/1-item list (hit = the
  full object, miss = `[]`, CRD-absent = `[]`) (`gatewayclasses-get-by-name`).
- The IngressClass list view: card title EXACTLY `IngressClass List`; columns
  Name/Controller/Created; every name links to
  `/network/ingress-class/data?name=<name>` (NO namespace)
  (`ingressclass-list-renders-rows`).
- The IngressClass data view: CTable (Name/Created/Controller/Labels/
  Annotations) + the Parameters table (Kind/Name/API Version, `No parameters`
  when `spec.parameters` is absent) + the JSON block; a miss is the pinned
  state `No IngressClass '<name>' found` — never an error style
  (`ingressclass-data-renders-detail`,
  `ingressclass-data-missing-parameters`,
  `ingressclass-data-not-found-state`).
- The GatewayClass list view: card title EXACTLY `GatewayClass List`; columns
  Name/Controller/Age; every name links to
  `/network/gateway-class/data?name=<name>` (NO namespace); CRD-absent → the
  `No gateway classes found` empty state (`gatewayclass-list-renders-rows`,
  `gatewayclass-list-crd-absent-empty`).
- The GatewayClass data view: CTable (Name/Controller/Created/Labels/
  Annotations) + the JSON block; a miss is the pinned state `No GatewayClass
  '<name>' found` — never an error style (this is ALSO the CRD-absent state)
  (`gatewayclass-data-renders-detail`, `gatewayclass-data-not-found-state`).
- Both leaves are ADDED to `_nav.tsx` (Network group, after the Ingress
  leaf); both view pairs are routed; no stub is removed (neither path is in
  `stubRoutes`) (`nav-leaves-added-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `self._networking` attribute (if
  absent) + `list_ingress_classes`/`get_ingress_class` +
  `list_gateway_classes`/`get_gateway_class` (modified).
- `backend/app/api/resources.py` — the four dict rows (modified).
- `backend/tests/services/test_k8s_client_ingressclasses.py` (new).
- `backend/tests/services/test_k8s_client_gatewayclasses.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 12 new tests
  (modified).
- `frontend/src/lib/types.ts` — `IngressClassItem`, `GatewayClassItem`
  (modified).
- `frontend/src/views/Network/IngressClass.tsx` (new).
- `frontend/src/views/Network/IngressClassData.tsx` (new).
- `frontend/src/views/Network/GatewayClass.tsx` (new).
- `frontend/src/views/Network/GatewayClassData.tsx` (new).
- `frontend/tests/views/ingressclasses.test.tsx` (new).
- `frontend/tests/views/ingressclass_data.test.tsx` (new).
- `frontend/tests/views/gatewayclasses.test.tsx` (new).
- `frontend/tests/views/gatewayclass_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/_nav.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior per kind: the same
  route branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods (four rows total).
- **IngressClass is cluster-scoped**: `list_ingress_classes` uses
  `list_ingress_class` (no namespace), and `get_ingress_class` uses
  `read_ingress_class` (the `_GETTERS` convention passes `(namespace, name)`;
  the namespace is accepted and ignored — the `list_runtime_classes` /
  `get_runtime_class` cluster-scoped pattern). The `?name=` branch's
  `namespace = "default"` fallback never affects the read.
- **GatewayClass is a cluster-scoped CRD**: `list_gateway_classes` uses
  `list_cluster_custom_object` (NOT `list_namespaced_custom_object`) and
  `get_gateway_class` uses `get_cluster_custom_object` — the CRD's OWN scope
  is the authority (`get_crd_served`), and GatewayClass is cluster-scoped, so
  the cluster-scoped calls are used (the VPA seam's namespaced branch is NOT
  taken — verify the scope from `get_crd_served` is `Cluster`).
- **This spec owns the GatewayClass seam** — the companion
  `ingress-gateway-api-views` spec (not yet landed) reuses
  `list_gateway_classes`/`get_gateway_class` + the `_KINDS`/`_GETTERS` rows;
  when it lands, the shared method/row is deduplicated (not re-added). A
  WHY-comment on the methods notes the ownership (so the companion spec's
  implementer knows not to re-add them).
- The list view's name-link href is the SOLE producer of the data page's
  `?name=` query strings (cluster-scoped: NO `namespace`) — the data page
  parses the param, never constructs one (the priorityclass contract; keep
  it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404 / CRD-absent) — the data view must NOT treat
  `items: []` as an API error (the `NOT_FOUND`-as-throw-not-found-state
  pattern from `PriorityClassData.tsx`).
- The `to_dict` form is snake_case for the IngressClass (a generated core-API
  model — `spec.controller`, `spec.parameters` as a `LocalObjectReference`
  dict `{ api_version, kind, name }`); the GatewayClass is a FULL custom
  object (camelCase — `spec.controllerName`, `metadata.creationTimestamp`).
- **Neither path is a stub** — no `views/Stub/routes.ts` change, no
  `Stub.test.tsx` change (the leaves are ADDED to the nav, not promoted from
  stubs). The `Stub.test.tsx` `expectedStubs()` derives from the nav minus
  `viewPaths`: ADDING the two leaves to the nav WITHOUT adding them to
  `viewPaths` makes the test expect them to be stubs (RED) — so the two paths
  MUST be added to `viewPaths` even though there is no stub to remove.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive; the owned GatewayClass seam is
deduplicated, not a door).

## Global Constraints

- No new Python dependency — `NetworkingV1Api` + `CustomObjectsApi` are
  already in the kubernetes client; at most ONE new attribute
  (`self._networking`) in `K8sClient.__init__` (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by `PriorityClassData`/`SecretData` (the `json` grammar already
  registered); `KubeDataTable` + CoreUI are existing.
- IngressClass is cluster-scoped (group `networking.k8s.io`, v1): the list
  URL and the data URL carry NO `namespace=` param; SAR group =
  `networking.k8s.io`, namespace = `None`; the client methods use
  `list_ingress_class` / `read_ingress_class`.
- GatewayClass is a cluster-scoped CRD (group `gateway.networking.k8s.io`,
  v1): the list URL and the data URL carry NO `namespace=` param; SAR group =
  `gateway.networking.k8s.io`, namespace = `None`; the client methods use
  `list_cluster_custom_object` / `get_cluster_custom_object` (the VPA seam,
  cluster-scoped branch); CRD-absent → `[]`.
- The full-object blocks are `JSON.stringify(item, null, 2)` with hljs
  grammar `json`, style `anOldHope` (the truthful-classifier rule).
- Card titles EXACTLY: `IngressClass List`, `GatewayClass List` (the
  e2e-smoke contracts).
- Pinned copy (do not reword): `No ingress classes found`,
  `No IngressClass '<name>' found`, `Error: ingress class name not provided`,
  `No gateway classes found`, `No GatewayClass '<name>' found`,
  `Error: gateway class name not provided`, `No cluster selected.`,
  `Loading ingress classes...`, `Loading gateway classes...`, `No labels`,
  `No annotations`, `No parameters`.
- Conventional commits; spec-zone commits precede code-zone commits;
  WHY-comments on load-bearing invariants (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too — type any new test
  params explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `self._networking` in
  `__init__` (if absent, next to `self._scheduling`); `list_ingress_classes`
  next to `list_runtime_classes` (line ~285); `get_ingress_class` next to
  `get_runtime_class` (line ~961); `list_gateway_classes`/
  `get_gateway_class` next to the VPA methods (line ~750).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["ingressclasses"]`/`_GETTERS["ingressclasses"]` +
  `_KINDS["gatewayclasses"]`/`_GETTERS["gatewayclasses"]`.
- `backend/tests/services/test_k8s_client_ingressclasses.py` (new) —
  `object.__new__` + `SimpleNamespace` fake (the `NetworkingV1Api` fake).
- `backend/tests/services/test_k8s_client_gatewayclasses.py` (new) — the VPA
  seam test pattern (`get_crd_served` mocked + the `self._custom` fake).
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_ingress_classes`/`get_ingress_class`/`list_gateway_classes`/
  `get_gateway_class`; 12 new tests.
- `frontend/src/lib/types.ts` (modify) — `IngressClassItem` +
  `GatewayClassItem` next to `PriorityClassItem`.
- `frontend/src/views/Network/IngressClass.tsx` (new) — cluster-scoped layout
  from `PriorityClass.tsx`.
- `frontend/src/views/Network/IngressClassData.tsx` (new) — clone of
  `PriorityClassData.tsx` + the 4.1 Parameters table.
- `frontend/src/views/Network/GatewayClass.tsx` (new) — cluster-scoped layout
  from `PriorityClass.tsx` (the Age column instead of Created).
- `frontend/src/views/Network/GatewayClassData.tsx` (new) — clone of
  `PriorityClassData.tsx` (the GatewayClass row set).
- `frontend/tests/views/ingressclasses.test.tsx` (new).
- `frontend/tests/views/ingressclass_data.test.tsx` (new).
- `frontend/tests/views/gatewayclasses.test.tsx` (new).
- `frontend/tests/views/gatewayclass_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — the four routes + the four imports.
- `frontend/src/_nav.tsx` (modify) — ADD the two leaves to the Network group.
- `frontend/tests/views/Stub.test.tsx` (modify) — add the two paths to the
  `viewPaths` set (the leaves are added to the nav; the test must not expect
  them to be stubs).

---

### Task 1: Backend — ingressclasses + gatewayclasses kinds (service + `_KINDS` + API tests)

**SATISFIES:** `ingressclasses-list-200`,
`ingressclasses-list-ignores-namespace`, `ingressclasses-sar-denied`,
`ingressclasses-binding-404`, `ingressclass-kind-singular-rejected`,
`ingressclasses-get-by-name`, `gatewayclasses-list-200`,
`gatewayclasses-crd-absent-empty`, `gatewayclasses-sar-denied`,
`gatewayclasses-binding-404`, `gatewayclass-kind-singular-rejected`,
`gatewayclasses-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_ingressclasses.py` (new)
- Test: `backend/tests/services/test_k8s_client_gatewayclasses.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing (first code task).
- Produces: `K8sClient.list_ingress_classes(_namespace: str | None) ->
  list[dict]`, `K8sClient.get_ingress_class(_namespace: str, name: str) ->
  list[dict]`, `K8sClient.list_gateway_classes(_namespace: str | None) ->
  list[dict]`, `K8sClient.get_gateway_class(_namespace: str, name: str) ->
  list[dict]` — the exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the priorityclasses/runtimeclasses/VPA tests).
- Deletion test: delete the four `_KINDS`/`_GETTERS` rows → the kinds 404
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing IngressClass service tests** —
  `backend/tests/services/test_k8s_client_ingressclasses.py`, mirroring the
  runtimeclasses test pattern with `object.__new__` + `SimpleNamespace` (a
  `NetworkingV1Api` fake for `list_ingress_class` / `read_ingress_class`):
  the cluster-scoped call (namespace ignored), `to_dict` form with
  `spec.controller` + conditional `spec.parameters` (a
  `LocalObjectReference` dict), 404 → `[]` on the getter, 500 →
  `ClusterUnreachableError`.
- [ ] **Step 2: Write the failing GatewayClass service tests** —
  `backend/tests/services/test_k8s_client_gatewayclasses.py`, mirroring the
  VPA test pattern (`get_crd_served` mocked to `("v1", "Cluster")` + the
  `self._custom()` fake for `list_cluster_custom_object` /
  `get_cluster_custom_object`): the served-version authority, the
  CLUSTER-scoped branch (GatewayClass is cluster-scoped — assert
  `list_cluster_custom_object` is used, NOT `list_namespaced_custom_object`),
  CRD-absent → `[]`, getter 404 → `[]`, full custom-object shape
  (camelCase, `spec.controllerName` intact).
- [ ] **Step 3: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_ingressclasses.py tests/services/test_k8s_client_gatewayclasses.py -q`.
  Expected: FAIL (no methods).
- [ ] **Step 4: Implement the IngressClass service methods** —
  `k8s_client.py`. Verify `self._networking` exists in `__init__`; if absent,
  add `self._networking = k8s_client.NetworkingV1Api(api_client)` next to
  `self._scheduling`. Next to `list_runtime_classes` (line ~285):
  ```python
  def list_ingress_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
      """IngressClass list in the standard kubernetes dict form (``to_dict``).
      Cluster-scoped (networking.k8s.io/v1): the namespace argument is
      accepted and ignored (the ``list_runtime_classes`` pattern). No field
      stripping — the view renders ``spec.controller`` and the data page the
      full object (including ``spec.parameters``, a LocalObjectReference). A
      transport ApiException maps to ``ClusterUnreachableError`` (502)."""
      try:
          resp = self._networking.list_ingress_class()
      except ApiException as e:
          self._unreachable("list_ingress_classes", e)
          raise AssertionError("unreachable") from e
      return [ic.to_dict() for ic in resp.items]
  ```
  Next to `get_runtime_class` (line ~961):
  ```python
  def get_ingress_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
      """One IngressClass as a 0/1-item list; ``[]`` on 404. Cluster-scoped:
      the namespace argument is accepted and ignored (the
      ``get_runtime_class`` pattern). Any other ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          return [self._networking.read_ingress_class(name).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_ingress_class", e)
          raise AssertionError("unreachable") from e
  ```
- [ ] **Step 5: Implement the GatewayClass service methods** — next to the
  VPA methods (line ~750), the `_GATEWAY_API_GROUP` +
  `_GATEWAY_CLASSES_PLURAL` constants + the two methods (clone the VPA seam,
  cluster-scoped branch):
  ```python
  # OWNED by the ingressclass-gatewayclass-views change (the companion
  # ingress-gateway-api-views spec reuses these — do NOT re-add them there).
  _GATEWAY_API_GROUP = "gateway.networking.k8s.io"
  _GATEWAY_CLASSES_PLURAL = "gatewayclasses"  # cluster-scoped

  def list_gateway_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
      """GatewayClass items, FULL custom-object shape (spec + status intact,
      camelCase — the wire form, like the VPA CRDs). The CRD's OWN served
      version + scope is the authority (``get_crd_served``); GatewayClass is
      CLUSTER-scoped, so the cluster-scoped call is used. CRD absent (Gateway
      API not installed) -> ``[]`` (the expected state, the VPA absence
      contract); any other read failure -> ``ClusterUnreachableError``
      (502). OWNED by the ingressclass-gatewayclass-views change — the
      companion ingress-gateway-api-views spec reuses this (do NOT re-add)."""
      served = self.get_crd_served(self._GATEWAY_API_GROUP, self._GATEWAY_CLASSES_PLURAL)
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          resp = custom.list_cluster_custom_object(
              self._GATEWAY_API_GROUP, version, self._GATEWAY_CLASSES_PLURAL
          )
      except ApiException as e:
          self._unreachable("list_gateway_classes", e)
          raise AssertionError("unreachable") from e
      items = resp.get("items") or [] if isinstance(resp, dict) else resp.items
      return [item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else item) for item in items]

  def get_gateway_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
      """One GatewayClass as a 0/1-item FULL custom object; ``[]`` on 404 or
      when the CRD is absent. Cluster-scoped (``get_cluster_custom_object``).
      Any other ApiException maps to ``ClusterUnreachableError`` (502).
      OWNED by the ingressclass-gatewayclass-views change."""
      served = self.get_crd_served(self._GATEWAY_API_GROUP, self._GATEWAY_CLASSES_PLURAL)
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          item = custom.get_cluster_custom_object(
              self._GATEWAY_API_GROUP, version, self._GATEWAY_CLASSES_PLURAL, name
          )
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_gateway_class", e)
          raise AssertionError("unreachable") from e
      return [item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else item)]
  ```
  (verify the `list_cluster_custom_object` return shape — the VPA seam's
  item-extraction idiom; match it exactly.)
- [ ] **Step 6: Wire the kinds + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # IngressClass (networking.k8s.io, cluster-scoped) — the 4.1-parity nav
  # leaf resolved by the ingressclass-gatewayclass-views change. The 4.1
  # route name was "ingress-class"; the API kind is the plural.
  "ingressclasses": ("list_ingress_classes", "ingressclasses", "networking.k8s.io"),
  # GatewayClass (gateway.networking.k8s.io, cluster-scoped CRD) — NEW (4.1
  # had no Gateway API); OWNED by this change (the companion
  # ingress-gateway-api-views spec reuses the seam).
  "gatewayclasses": ("list_gateway_classes", "gatewayclasses", "gateway.networking.k8s.io"),
  ```
  in `_KINDS`, and `"ingressclasses": "get_ingress_class"` +
  `"gatewayclasses": "get_gateway_class"` in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the priorityclasses +
  VPA blocks):
  - FakeK8s gains the four methods (the IngressClass fake returns a
    `to_dict`-shaped item with `spec.controller` + a `spec.parameters`
    `LocalObjectReference`; the GatewayClass fake returns a full custom
    object with `spec.controllerName`, and a CRD-absent variant returns `[]`).
  - 12 new tests (6 per kind, same docstring-tag style):
    - IngressClass: `list_200` (kind + to_dict form),
      `list_ignores_namespace` (`?namespace=team-a` → the cluster-scoped
      call), `get_by_name` (hit + miss), `sar_denied` (assert
      `("list", "ingressclasses", None, None, "networking.k8s.io")` in
      `asked` — namespace `None`), `binding_404`, `singular_rejected`.
    - GatewayClass: `list_200` (full custom object), `crd_absent_empty`
      (the fake's `get_crd_served` → None → `items: []`), `get_by_name` (hit
      + miss + CRD-absent), `sar_denied` (assert
      `("list", "gatewayclasses", None, None, "gateway.networking.k8s.io")`
      in `asked`), `binding_404`, `singular_rejected`.
- [ ] **Step 7: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_ingressclasses.py tests/services/test_k8s_client_gatewayclasses.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).
- [ ] **Step 8: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_ingressclasses.py backend/tests/services/test_k8s_client_gatewayclasses.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): ingressclasses + gatewayclasses kinds (cluster-scoped, SAR-gated)"`

### Task 2: Frontend — IngressClass list + data views + tests

**SATISFIES:** `ingressclass-list-renders-rows`,
`ingressclass-data-renders-detail`, `ingressclass-data-missing-parameters`,
`ingressclass-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Network/IngressClass.tsx`
- Create: `frontend/src/views/Network/IngressClassData.tsx`
- Test: `frontend/tests/views/ingressclasses.test.tsx` (new)
- Test: `frontend/tests/views/ingressclass_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `ingressclasses` list + `?name=` URLs,
  cluster-scoped).
- Produces: the data-page link
  `/network/ingress-class/data?name=<name>` (the sole producer, cluster-
  scoped: NO namespace).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` (no
  namespace seam — cluster-scoped).
- Deletion test: deleting the views → the routes (Task 4) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `IngressClassItem` next to
  `PriorityClassItem`:
  ```ts
  /** An IngressClass item (kubernetes to_dict, snake_case; cluster-scoped, networking.k8s.io/v1). */
  export interface IngressClassItem {
    metadata?: { name?: string; creation_timestamp?: string;
      labels?: Record<string, string>; annotations?: Record<string, string> }
    spec?: {
      controller?: string
      parameters?: { api_version?: string; kind?: string; name?: string }
    }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone
  `priority_classes.test.tsx` (the cluster-scoped pattern) +
  `priority_class_data.test.tsx`: list (card title `IngressClass List`,
  columns Name/Controller/Created, name link NO namespace, no-cluster,
  empty) + data (CTable + Parameters table + JSON block; missing-parameters
  → `No parameters`; not-found state; missing-name).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `IngressClass.tsx` (cluster-scoped layout from
  `PriorityClass.tsx`; the Controller column = `spec.controller ?? '—'`; the
  Created column = `formatTimestamp`); `IngressClassData.tsx` (clone
  `PriorityClassData.tsx` + the 4.1 Parameters table — a CTable rendering
  the present `spec.parameters` fields Kind/Name/API Version, `No parameters`
  when absent; the JSON block).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): ingressclass list + data views (4.1 port, cluster-scoped)"`

### Task 3: Frontend — GatewayClass list + data views + tests

**SATISFIES:** `gatewayclass-list-renders-rows`,
`gatewayclass-list-crd-absent-empty`, `gatewayclass-data-renders-detail`,
`gatewayclass-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Network/GatewayClass.tsx`
- Create: `frontend/src/views/Network/GatewayClassData.tsx`
- Test: `frontend/tests/views/gatewayclasses.test.tsx` (new)
- Test: `frontend/tests/views/gatewayclass_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `gatewayclasses` list + `?name=` URLs,
  cluster-scoped CRD).
- Produces: the data-page link
  `/network/gateway-class/data?name=<name>` (the sole producer, cluster-
  scoped: NO namespace).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster`.
- Deletion test: deleting the views → the routes (Task 4) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `GatewayClassItem` next to
  `IngressClassItem`:
  ```ts
  /** A GatewayClass item (FULL custom object, camelCase; cluster-scoped CRD, gateway.networking.k8s.io/v1). */
  export interface GatewayClassItem {
    metadata?: { name?: string; creationTimestamp?: string;
      labels?: Record<string, string>; annotations?: Record<string, string> }
    spec?: { controllerName?: string }
    status?: { conditions?: { type?: string; status?: string; reason?: string; message?: string }[] }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone
  `priority_classes.test.tsx` + `priority_class_data.test.tsx`: list (card
  title `GatewayClass List`, columns Name/Controller/**Age**, name link NO
  namespace, CRD-absent → the `No gateway classes found` empty state, no-
  cluster) + data (CTable + JSON block; not-found state — ALSO the CRD-absent
  state; missing-name).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `GatewayClass.tsx` (cluster-scoped layout from
  `PriorityClass.tsx`; the Controller column = `spec.controllerName ??
  '—'`; the **Age** column = a human-readable age from
  `metadata.creationTimestamp` — a small `formatAge` helper: `Nd`/`Nh`/`Nm`,
  `—` when absent; the full timestamp is in the data page + JSON block);
  `GatewayClassData.tsx` (clone `PriorityClassData.tsx`; the row set
  Name/Controller/Created/Labels/Annotations; the JSON block; the NOT_FOUND
  state is ALSO the CRD-absent state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): gatewayclass list + data views (VPA seam, cluster-scoped CRD)"`

### Task 4: Routing + nav leaves + full verification

**SATISFIES:** `nav-leaves-added-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/_nav.tsx`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 2–3's view components.
- Produces: the resolved nav leaves (the goal).
- Seam: react-router `Route` + the nav `leaf()` calls + the `viewPaths` set.
- Deletion test: delete the four `Route`s → the paths 404; delete the nav
  leaves → the pages are unreachable.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the four view imports +
  the four routes (mirroring the priorityclass route block — the cluster-
  scoped pattern):
  ```tsx
  <Route path="/network/ingress-class" element={<ProtectedRoute><IngressClassView /></ProtectedRoute>} />
  <Route path="/network/ingress-class/data" element={<ProtectedRoute><IngressClassDataView /></ProtectedRoute>} />
  <Route path="/network/gateway-class" element={<ProtectedRoute><GatewayClassView /></ProtectedRoute>} />
  <Route path="/network/gateway-class/data" element={<ProtectedRoute><GatewayClassDataView /></ProtectedRoute>} />
  ```
- [ ] **Step 2: Add the nav leaves** — `_nav.tsx`: in the Network group
  (after the Ingress leaf, line ~96), add:
  ```tsx
  leaf('IngressClass', '/network/ingress-class'),
  leaf('GatewayClass', '/network/gateway-class'),
  ```
  Verify with `git diff --stat` that ONLY the two leaves were added.
- [ ] **Step 3: Update Stub.test.tsx** — add `/network/ingress-class` +
  `/network/gateway-class` to the `viewPaths` set in `expectedStubs()`
  (the leaves are ADDED to the nav; without the addition the test expects
  them to be stubs — RED). Re-run
  `corepack pnpm vitest run tests/views/Stub.test.tsx`.
- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build).
  - `task fe-check` (air-gap — no new external refs).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures are the baseline).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).
- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/_nav.tsx frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire ingressclass + gatewayclass routes, add nav leaves"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_ingressclasses.py tests/services/test_k8s_client_gatewayclasses.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/ingressclasses.test.tsx tests/views/ingressclass_data.test.tsx tests/views/gatewayclasses.test.tsx tests/views/gatewayclass_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` shows ONLY the two added leaves; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend: both kinds) ──► Task 2 (IngressClass views) ──► Task 4 (routing + nav)
                     └────────► Task 3 (GatewayClass views) ──┘
```

Tasks 2 and 3 are independent of each other (both consume Task 1); either
can run first or in parallel. Task 4 last (it wires the routes + nav, so the
views must exist first).

## Rollback

Each task is one conventional commit and independently revertable (no schema,
no dependency, no public contract change). Reverting Task 4 is self-
contained (routes + nav + test in one commit). Reverting Task 1 alone reverts
both kinds (the two leaves 404); Tasks 2 and 3 are independent reverts (the
IngressClass and GatewayClass views are separate commits). The owned
GatewayClass seam (Task 1) reverts with Task 1 — the companion
`ingress-gateway-api-views` spec, if it lands after this revert, re-adds the
seam (the dedupe note in the method docstrings tracks the ownership).
