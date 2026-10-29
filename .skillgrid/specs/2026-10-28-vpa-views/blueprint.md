# VPAs (Vertical Pod Autoscaler) Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already
ratified for CRD kinds: the Cilium NetworkPolicies full-custom-object seam,
same `_KINDS`/`_GETTERS` wiring, same list+data view pair; the 4.1 template
pair is the source of truth for the page shape).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny + CRD-absent
empty) before any frontend exists; Task 2 is the list view; Task 3 the data
view; Task 4 the routing cleanup. Each task is independently revertable.

**Goal:** Resolve the nav leaf `/other-resource/vertical-pod-autoscaler` to a
real, SAR-gated, read-only list + data pair — the 4.1 VPA pages (a CRD) ported
with the ratified 5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`, and already threads
`namespace`. This change adds ONE kind:
`K8sClient.list_vertical_pod_autoscalers` / `get_vertical_pod_autoscaler`
(kubernetes `CustomObjectsApi`, group `autoscaling.k8s.io`, namespaced CRD,
**full custom object** — the Cilium precedent), + two dict rows (`_KINDS` /
`_GETTERS`). No new client attribute: `self._custom()` / `self._api_client`
already exist (the CRD + Cilium kinds use them). Frontend: two views (list
cloned from NetworkPolicy.tsx for the namespace handling, data cloned from
PriorityClassData.tsx for the CTable+JSON block), `VerticalPodAutoscalerItem`
type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CustomObjectsApi` (already a dependency, already
used by the CRD + Cilium kinds via `self._custom()`), Flask + Smorest
(existing route), React + CoreUI + TanStack Query + MSW (existing), no new
npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/other-resources/vpa.html.j2`
(list: Name/Namespace/Target Kind/Target Name/Update Mode/Min Memory/Max
Memory/Creation Timestamp — Target Name is a hidden-form link to
`/workload/<kind-lower>s`; Min/Max Memory are the LAST container's
`minAllowed.memory`/`maxAllowed.memory` via `{% set %}` overwrite),
`4.1:src/kubedash/templates/other-resources/vpa-data.html.j2` (data: Name/
Created/Namespace/Annotations/Labels/Target (Owner)/Update Mode/Container
Policies/Conditions — the Conditions table iterates a TOP-LEVEL
`vpa_data.conditions` key that the read function never populates: a dead
table), `4.1:src/kubedash/lib/k8s/other.py:50` (`k8sVPAListGet`: resolves the
CRD served+storage version via `get_vpa_crd_version` (line 17), then
`CustomObjectsApi().list_namespaced_custom_object`; populates only
`metadata`/`spec`/`status`), `4.1:src/kubedash/blueprint/other_resources.py:26`
(the list + data routes, the data page is list-then-filter). In-repo
precedents — `backend/app/services/k8s_client.py:667-734` (the
`list_cilium_network_policies`/`get_cilium_network_policy` full-custom-object
CRD seam to mirror, `get_crd_served` line 648, `_crd_body` line 531),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch (line
~104-114, the `namespace = namespace or "default"` fallback),
`backend/tests/api/test_resources.py:1093-1230` (the ciliumnetworkpolicies
API tests to mirror: 200 uses served version, all-namespaces, SAR deny w/
group, 502 on unreachable, absent → empty),
`frontend/src/views/Security/NetworkPolicy.tsx` (the namespaced list view:
`selectedNamespace ?? 'default'`, namespace in URL + query key),
`frontend/src/views/OtherResource/PriorityClassData.tsx` (the data view:
CTable + labels/annotations sub-tables + JSON block; the
`NOT_FOUND`-as-throw-not-found-state pattern),
`frontend/tests/views/network_policies.test.tsx` +
`priority_class_data.test.tsx` (the test patterns to clone).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0010, ADR-0020, ADR-0021,
ADR-0022. None created.

## Terms

None (the spec's vocabulary; "VerticalPodAutoscaler" is the k8s kind, not a
new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/verticalpodautoscalers?namespace=team-a` → 200,
  `kind: "verticalpodautoscalers"`, items as FULL custom objects (spec +
  status intact, camelCase), SAR-gated on `list verticalpodautoscalers`
  (group `autoscaling.k8s.io`, namespace `team-a`), 403 names the resource and
  the client call is never made on deny
  (`verticalpodautoscalers-list-200-in-namespace`,
  `verticalpodautoscalers-sar-denied`).
- Without a namespace param the client uses
  `list_cluster_custom_object` (`verticalpodautoscalers-list-all-namespaces-
  without-param`).
- CRD absent (operator not installed) → `items == []`, 200, NOT an error
  (`verticalpodautoscalers-crd-absent-is-empty`) — the Cilium
  `get_crd_served is None → []` contract.
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the full object, miss = `[]` (`verticalpodautoscalers-get-by-name`).
- The singular `verticalpodautoscaler` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`verticalpodautoscaler-kind-singular-rejected`).
- The list view fetches
  `/api/v1/clusters/<id>/resources/verticalpodautoscalers?namespace=<ns>` with
  `<ns> = selectedNamespace ?? 'default'`; card title EXACTLY `Vertical Pod
  Autoscaler List`; columns Name/Namespace/Target Kind/Target Name/Update
  Mode/Min Memory/Max Memory/Created; every name links to the data page with
  BOTH `name` and `namespace` (`vpa-list-renders-rows-with-data-links`).
- Target Kind = `spec.targetRef.kind`, Target Name = `spec.targetRef.name` as
  PLAIN TEXT (no link), Update Mode = `spec.updatePolicy.updateMode` (`N/A`
  when absent), Min/Max Memory = the LAST container's `minAllowed.memory` /
  `maxAllowed.memory` (`N/A` when none) (`vpa-list-target-and-memory-cells`,
  `vpa-list-last-container-memory-semantics`, `vpa-list-missing-update-policy`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Name/Created/Namespace/Target (Owner)/Update Mode/Labels/Annotations) +
  the Container Policies table (Container Name/Controlled Values/Mode/Min
  Allowed/Max Allowed/Controlled Resources) + the Conditions table (Type/
  Status/Last Transition Time/Reason/Message, from `status.conditions`) + a
  JSON-highlighted full-object block, and treats a miss as the pinned state
  `No VerticalPodAutoscaler '<name>' found` — never an error style
  (`vpa-data-renders-detail`, `vpa-data-conditions-from-status`,
  `vpa-data-container-policies`, `vpa-data-not-found-state`).
- `/other-resource/vertical-pod-autoscaler` is gone from
  `views/Stub/routes.ts`; both real views are routed; the nav leaf is
  byte-identical (`vpa-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — the two methods (modified; no new
  attribute, `self._custom()` + `self._api_client` already exist).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_verticalpodautoscalers.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `VerticalPodAutoscalerItem` (modified).
- `frontend/src/views/OtherResource/VerticalPodAutoscaler.tsx` (new).
- `frontend/src/views/OtherResource/VerticalPodAutoscalerData.tsx` (new).
- `frontend/tests/views/vertical_pod_autoscalers.test.tsx` (new).
- `frontend/tests/views/vertical_pod_autoscaler_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- The kind is a CRD: the service methods MUST call `get_crd_served` FIRST and
  return `[]` when it is `None` — the CRD-absent contract. Forgetting the
  `get_crd_served` guard is a 500 (the CRD read 404s as a transport
  `ClusterUnreachableError`) on any cluster without the VPA operator.
- The list view's name-link href is the SOLE producer of the data page's
  `?name=&namespace=` query strings — the data page parses the params, never
  constructs one (the priorityclass/networkpolicy contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404 OR CRD-absent) — the data view must NOT treat
  `items: []` as an API error (the `NOT_FOUND`-throw pattern from
  PriorityClassData).
- The `name` branch of the generic route falls back to `namespace = "default"`
  when no namespace param is present — the data page ALWAYS sends the
  namespace (it has it from the link), so the fallback never fires for this
  view; the test suite pins that the data URL carries the namespace.
- The custom object is camelCase (the wire form, like the Cilium CRDs) — NOT
  snake_case. The type and the cell readers use camelCase keys
  (`spec.targetRef.kind`, `status.conditions`, `minAllowed.memory`).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `CustomObjectsApi` is already vendored and
  already used by the CRD + Cilium kinds via `self._custom()` (air-gap,
  ADR-0020). No new `K8sClient` attribute.
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- CRD kind (group `autoscaling.k8s.io`, namespaced): the list URL and the
  data URL carry `namespace=`; SAR group = `"autoscaling.k8s.io"`, namespace =
  the query namespace or `None`; the client methods resolve the served version
  via `get_crd_served` and use the `list_namespaced_custom_object` /
  `list_cluster_custom_object` branch (the `list_cilium_network_policies`
  pattern).
- The custom object is camelCase (the custom-object wire form) — the type and
  cell readers use camelCase keys. NOT snake_case (it is not a generated
  core-API model).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Vertical Pod Autoscaler List` (4.1's title, verbatim —
  the e2e-smoke contract).
- Pinned copy (do not reword): `No vertical pod autoscalers found`,
  `No VerticalPodAutoscaler '<name>' found`,
  `Error: vertical pod autoscaler name not provided`, `No cluster selected.`,
  `Loading vertical pod autoscalers...`, `No labels`, `No annotations`,
  `No container policies`, `No conditions`, and the 4.1 cell literal `N/A`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_vertical_pod_autoscalers`
  + `get_vertical_pod_autoscaler` next to the Cilium methods (line ~715). No
  `__init__` change (`self._custom()` / `self._api_client` already exist).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["verticalpodautoscalers"]` + `_GETTERS["verticalpodautoscalers"]`.
- `backend/tests/services/test_k8s_client_verticalpodautoscalers.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_vertical_pod_autoscalers` / `get_vertical_pod_autoscaler`; 6 new tests.
- `frontend/src/lib/types.ts` (modify) — `VerticalPodAutoscalerItem` next to
  the Cilium CRD types.
- `frontend/src/views/OtherResource/VerticalPodAutoscaler.tsx` (new) —
  namespace handling from NetworkPolicy.tsx, layout from PriorityClass.tsx.
- `frontend/src/views/OtherResource/VerticalPodAutoscalerData.tsx` (new) —
  clone of PriorityClassData.tsx + the 4.1 Container-Policies + Conditions
  tables.
- `frontend/tests/views/vertical_pod_autoscalers.test.tsx` (new).
- `frontend/tests/views/vertical_pod_autoscaler_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (line ~381) + the two view imports (after line 48).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 24
  (`/other-resource/vertical-pod-autoscaler`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — verticalpodautoscalers kind (CRD, full object, SAR-gated)

**SATISFIES:** `verticalpodautoscalers-list-200-in-namespace`,
`verticalpodautoscalers-list-all-namespaces-without-param`,
`verticalpodautoscalers-crd-absent-is-empty`,
`verticalpodautoscalers-sar-denied`, `verticalpodautoscalers-binding-404`,
`verticalpodautoscaler-kind-singular-rejected`,
`verticalpodautoscalers-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_verticalpodautoscalers.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_vertical_pod_autoscalers(namespace: str | None) ->
  list[dict]` and `K8sClient.get_vertical_pod_autoscaler(namespace: str, name:
  str) -> list[dict]` — the exact names `_KINDS`/`_GETTERS` reference via
  `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the ciliumnetworkpolicies tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_verticalpodautoscalers.py`,
  mirroring the Cilium test pattern with `object.__new__` + `SimpleNamespace`
  (stub `get_crd_served` to return a version + scope, and `_custom()` to
  return the fake):

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient

  _VERSION = "v1"

  def _client(custom: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._custom = lambda: custom
      # The CRD is present and served (the absent case is tested separately).
      client.get_crd_served = lambda group, plural: (_VERSION, "Namespaced")
      return client


  def _vpa(name: str, ns: str) -> dict:
      return {
          "apiVersion": "autoscaling.k8s.io/v1",
          "kind": "VerticalPodAutoscaler",
          "metadata": {"name": name, "namespace": ns, "creationTimestamp": "2026-01-02T03:04:05Z"},
          "spec": {
              "targetRef": {"kind": "Deployment", "name": name, "apiVersion": "apps/v1"},
              "updatePolicy": {"updateMode": "Auto"},
              "resourcePolicy": {
                  "containerPolicies": [
                      {"containerName": "app", "minAllowed": {"memory": "128Mi"}, "maxAllowed": {"memory": "1Gi"}, "mode": "Auto"}
                  ]
              },
          },
          "status": {"conditions": [{"type": "RecommendationProvided", "status": "True", "reason": "RecommendationAvailable", "message": "ok", "lastTransitionTime": "2026-01-02T03:04:06Z"}]},
      }


  def test_list_vertical_pod_autoscalers_in_namespace() -> None:
      """[verticalpodautoscalers-list-200-in-namespace] a namespace is
      forwarded to ``list_namespaced_custom_object`` and the FULL object
      (spec + status intact, camelCase) is returned (the Cilium pattern)."""
      seen: list[object] = []
      vpa = _vpa("web-vpa", "team-a")
      custom = SimpleNamespace(
          list_namespaced_custom_object=lambda group, version, namespace, plural: (
              seen.append((group, version, namespace, plural)),
              {"items": [vpa]},
          )[1],
      )
      result = _client(custom).list_vertical_pod_autoscalers("team-a")
      assert result[0]["metadata"]["name"] == "web-vpa"
      assert result[0]["spec"]["targetRef"]["kind"] == "Deployment"  # spec intact
      assert result[0]["status"]["conditions"][0]["type"] == "RecommendationProvided"  # status intact
      assert seen == [("autoscaling.k8s.io", _VERSION, "team-a", "verticalpodautoscalers")]


  def test_list_vertical_pod_autoscalers_all_namespaces_without_namespace() -> None:
      """[verticalpodautoscalers-list-all-namespaces-without-param] ``None``
      uses the all-namespaces custom-object call (the Cilium branch)."""
      seen: list[object] = []
      custom = SimpleNamespace(
          list_cluster_custom_object=lambda group, version, plural: (
              seen.append(True),
              {"items": []},
          )[1],
      )
      assert _client(custom).list_vertical_pod_autoscalers(None) == []
      assert seen == [True]


  def test_list_vertical_pod_autoscalers_crd_absent_is_empty() -> None:
      """[verticalpodautoscalers-crd-absent-is-empty] the CRD read is
      ``None`` (operator not installed) -> ``[]`` (the Cilium absent
      contract), and the custom-object list is never called."""
      seen: list[object] = []
      custom = SimpleNamespace(
          list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
      )
      client = object.__new__(K8sClient)
      client._custom = lambda: custom
      client.get_crd_served = lambda group, plural: None
      assert client.list_vertical_pod_autoscalers("team-a") == []
      assert seen == []  # the list call was never made


  def test_get_vertical_pod_autoscaler_404_returns_empty_list() -> None:
      """[verticalpodautoscalers-get-by-name] a miss is ``[]``, mirroring
      ``get_cilium_network_policy``'s 0/1-item contract."""
      def get(group, version, namespace, plural, name):
          raise ApiException(status=404)

      custom = SimpleNamespace(get_namespaced_custom_object=get)
      assert _client(custom).get_vertical_pod_autoscaler("team-a", "ghost") == []


  def test_get_vertical_pod_autoscaler_hit_returns_one_full_item() -> None:
      vpa = _vpa("web-vpa", "team-a")
      custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: vpa)
      result = _client(custom).get_vertical_pod_autoscaler("team-a", "web-vpa")
      assert result[0]["spec"]["targetRef"]["name"] == "web-vpa"  # full object


  def test_get_vertical_pod_autoscaler_other_api_error_maps_to_unreachable() -> None:
      def get(group, version, namespace, plural, name):
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(get_namespaced_custom_object=get)).get_vertical_pod_autoscaler("team-a", "web-vpa")
  ```

  (Implementation note: `get_crd_served` is an instance method; the tests
  stub it via attribute assignment on the `object.__new__` client, the same
  way the Cilium tests stub the served-version seam. `_crd_body` is a
  `@staticmethod` and is NOT stubbed — it handles the plain-dict
  custom-object response as-is.)

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_verticalpodautoscalers.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`, next to
  `get_cilium_network_policy` (line ~715):

  ```python
  _VPA_GROUP = "autoscaling.k8s.io"
  _VPA_PLURAL = "verticalpodautoscalers"

  def list_vertical_pod_autoscalers(self, namespace: str | None) -> list[dict[str, Any]]:
      """VerticalPodAutoscaler items, FULL custom-object shape (spec + status
      intact, camelCase — the wire form, like the Cilium CRDs). The VPA CRD's
      OWN served version + scope is the authority (``get_crd_served``). CRD
      absent (operator not installed) -> ``[]`` (the expected state, the
      Cilium absence contract); any other read failure ->
      ``ClusterUnreachableError`` (502). The VPA pages need
      ``spec.resourcePolicy.containerPolicies`` and ``status.conditions``,
      so this returns the raw object — NOT the lossy ``list_crd_instances``
      projection."""
      served = self.get_crd_served(self._VPA_GROUP, self._VPA_PLURAL)
      if served is None:
          return []
      version, scope = served
      custom = self._custom()
      try:
          resp = (
              custom.list_namespaced_custom_object(
                  self._VPA_GROUP, version, namespace, self._VPA_PLURAL
              )
              if namespace and scope == "Namespaced"
              else custom.list_cluster_custom_object(
                  self._VPA_GROUP, version, self._VPA_PLURAL
              )
          )
      except ApiException as e:
          self._unreachable("list_vertical_pod_autoscalers", e)
          raise AssertionError("unreachable") from e
      body = self._crd_body(resp)
      items = body.get("items", [])
      return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

  def get_vertical_pod_autoscaler(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One VerticalPodAutoscaler as a 0/1-item FULL custom object; ``[]``
      on 404 or when the CRD is absent (operator not installed). Any other
      ApiException maps to ``ClusterUnreachableError`` (502), matching
      ``get_cilium_network_policy``."""
      served = self.get_crd_served(self._VPA_GROUP, self._VPA_PLURAL)
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          item = custom.get_namespaced_custom_object(
              self._VPA_GROUP, version, namespace, self._VPA_PLURAL, name
          )
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_vertical_pod_autoscaler", e)
          raise AssertionError("unreachable") from e
      item = self._crd_body(item)
      return [item.to_dict() if hasattr(item, "to_dict") else item]
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "verticalpodautoscalers": (
      "list_vertical_pod_autoscalers",
      "verticalpodautoscalers",
      "autoscaling.k8s.io",
  ),
  ```
  in `_KINDS` (after the cilium rows; group `autoscaling.k8s.io`), and
  ```python
  "verticalpodautoscalers": "get_vertical_pod_autoscaler",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the ciliumnetworkpolicies
  block, lines 1093–1230):
  - FakeK8s gains:
    ```python
    def list_vertical_pod_autoscalers(self, namespace: str | None) -> list[dict]:
        # Namespaced CRD (autoscaling.k8s.io): the namespace is forwarded;
        # the FULL custom object (spec + status) is returned (camelCase).
        return [
            {
                "metadata": {
                    "name": "web-vpa",
                    "namespace": namespace or "team-a",
                    "creationTimestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {"vpa.kubernetes.io/managed-by": "kubedash"},
                },
                "spec": {
                    "targetRef": {"kind": "Deployment", "name": "web", "apiVersion": "apps/v1"},
                    "updatePolicy": {"updateMode": "Auto"},
                    "resourcePolicy": {
                        "containerPolicies": [
                            {
                                "containerName": "app",
                                "controlledValues": "RequestsLimits",
                                "mode": "Auto",
                                "minAllowed": {"memory": "128Mi"},
                                "maxAllowed": {"memory": "1Gi"},
                                "controlledResources": ["cpu", "memory"],
                            }
                        ]
                    },
                },
                "status": {
                    "conditions": [
                        {
                            "type": "RecommendationProvided",
                            "status": "True",
                            "lastTransitionTime": "2026-01-02T03:04:06Z",
                            "reason": "RecommendationAvailable",
                            "message": "recommendation available",
                        }
                    ]
                },
            }
        ]

    def get_vertical_pod_autoscaler(self, namespace: str, name: str) -> list[dict]:
        if name == "web-vpa":
            return self.list_vertical_pod_autoscalers(namespace)
        return []
    ```
  - Six new tests mirroring the cilium block, same docstring-tag style:
    - `test_list_verticalpodautoscalers_200_in_namespace` — 200,
      `body["kind"] == "verticalpodautoscalers"`, one item in `team-a` with
      `spec` + `status` intact; assert the FakeK8s received
      `namespace="team-a"`.
    - `test_list_verticalpodautoscalers_all_namespaces_without_param` — no
      `namespace` param → 200; assert the FakeK8s received `None`.
    - `test_list_verticalpodautoscalers_get_by_name` —
      `?name=web-vpa&namespace=team-a` → 1 item;
      `?name=ghost&namespace=team-a` → `items == []`.
    - `test_list_verticalpodautoscalers_sar_denied` — SAR denies; 403; assert
      `("list", "verticalpodautoscalers", "team-a", None, "autoscaling.k8s.io")`
      in `asked` (namespace `team-a`, group `autoscaling.k8s.io` — the
      load-bearing assertions).
    - `test_verticalpodautoscalers_binding_404` — cluster 999, unbound user
      → 404.
    - `test_verticalpodautoscaler_kind_singular_rejected` —
      `/resources/verticalpodautoscaler` → 404
      `RESOURCE_KIND_NOT_SUPPORTED`.
    - (CRD-absent case: the service test covers it; the API route returns
      `[]` from the FakeK8s when it is programmed to — optional to add a 7th
      API test if the cilium block has an absent-case analog.)

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_verticalpodautoscalers.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_verticalpodautoscalers.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): verticalpodautoscalers kind (CRD, full object, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `vpa-list-renders-rows-with-data-links`,
`vpa-list-target-and-memory-cells`, `vpa-list-last-container-memory-semantics`,
`vpa-list-missing-update-policy`, `vpa-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/OtherResource/VerticalPodAutoscaler.tsx`
- Test: `frontend/tests/views/vertical_pod_autoscalers.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `verticalpodautoscalers` list URL, namespaced
  CRD, full object).
- Produces: the data-page link
  `/other-resource/vertical-pod-autoscaler/data?name=<name>&namespace=<ns>` —
  the SOLE producer of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedNamespace`
  (no new seam).
- Deletion test: deleting the view → the route (Task 4) 404s / the test file
  fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to the
  Cilium CRD types. **camelCase** (the custom-object wire form):

  ```ts
  /** A VerticalPodAutoscaler custom object as returned by /api/v1/clusters/<id>/resources/verticalpodautoscalers (autoscaling.k8s.io CRD, camelCase wire form; namespaced). */
  export interface VerticalPodAutoscalerItem {
    metadata?: {
      name?: string
      namespace?: string
      creationTimestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      targetRef?: { kind?: string; name?: string; apiVersion?: string }
      updatePolicy?: { updateMode?: string }
      resourcePolicy?: {
        containerPolicies?: Array<{
          containerName?: string
          controlledValues?: string
          mode?: string
          minAllowed?: Record<string, string>
          maxAllowed?: Record<string, string>
          controlledResources?: string[]
        }>
      }
    }
    status?: {
      conditions?: Array<{
        type?: string
        status?: string
        lastTransitionTime?: string
        reason?: string
        message?: string
      }>
    }
    [key: string]: unknown
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/vertical_pod_autoscalers.test.tsx`: clone
  `network_policies.test.tsx` 1:1 (KubeDataTable fake included) with the
  network_policies namespace setup (`selectProd` sets
  `selectedNamespace: 'team-a'`), and:
  - fixture `webVpa` (the full custom object, camelCase):
    ```ts
    const webVpa = {
      apiVersion: 'autoscaling.k8s.io/v1',
      kind: 'VerticalPodAutoscaler',
      metadata: {
        name: 'web-vpa',
        namespace: 'team-a',
        creationTimestamp: '2026-01-02T03:04:05Z',
        labels: { team: 'a' },
        annotations: { 'vpa.kubernetes.io/managed-by': 'kubedash' },
      },
      spec: {
        targetRef: { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' },
        updatePolicy: { updateMode: 'Auto' },
        resourcePolicy: {
          containerPolicies: [
            { containerName: 'app', controlledValues: 'RequestsLimits', mode: 'Auto', minAllowed: { memory: '128Mi' }, maxAllowed: { memory: '1Gi' }, controlledResources: ['cpu', 'memory'] },
          ],
        },
      },
      status: {
        conditions: [{ type: 'RecommendationProvided', status: 'True', lastTransitionTime: '2026-01-02T03:04:06Z', reason: 'RecommendationAvailable', message: 'ok' }],
      },
    }
    ```
  - `renderAt` default path `/other-resource/vertical-pod-autoscaler`; MSW
    handler on `*/api/v1/clusters/1/resources/verticalpodautoscalers`.
  - `list-renders-vpa-rows-with-data-links`: link `web-vpa` →
    `/other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a`;
    fetch URL EXACTLY
    `/api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a`;
    heading EXACTLY `Vertical Pod Autoscaler List`; breadcrumb `Other
    Resources`; column headers `['Name', 'Namespace', 'Target Kind', 'Target
    Name', 'Update Mode', 'Min Memory', 'Max Memory', 'Created']`; Target
    Name `web` is PLAIN TEXT (assert it is NOT a link).
  - `list-target-and-memory-cells`: Target Kind `Deployment`, Min Memory
    `128Mi`, Max Memory `1Gi`, Update Mode `Auto`.
  - `list-last-container-memory-semantics`: a second fixture with TWO
    container policies (first `minAllowed.memory 64Mi`, second
    `minAllowed.memory 256Mi`) → Min Memory cell shows `256Mi` (4.1's `{% set %}`
    overwrite: the last container with the key wins).
  - `list-missing-update-policy`: a fixture with no `updatePolicy` → Update
    Mode cell shows `N/A`.
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No vertical pod autoscalers found`
    (also the CRD-absent state).

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/vertical_pod_autoscalers.test.tsx`
  Expected: FAIL (cannot find module
  `src/views/OtherResource/VerticalPodAutoscaler`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/OtherResource/VerticalPodAutoscaler.tsx`: layout from
  `PriorityClass.tsx`, namespace handling from `NetworkPolicy.tsx`:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement,
    the CRD full-object seam (the Cilium precedent, camelCase), the
    `?name=&namespace=` delta, the dropped Target link, the last-container
    memory semantics (4.1's `{% set %}` overwrite).
  - `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`
  - `type VpaRow = { name, namespace, targetKind: string, targetName: string, updateMode: string, minMemory: string, maxMemory: string, created: string }`:
    ```ts
    // 4.1's Min/Max Memory take the LAST container in
    // spec.resourcePolicy.containerPolicies that defines the key (the Jinja
    // `{% set mem_min = ... %}` overwrite). "N/A" is 4.1's literal for the
    // absent value (certainty rule: never guess, never crash the row).
    const containerMem = (
      item: VerticalPodAutoscalerItem,
      key: 'minAllowed' | 'maxAllowed',
    ): string => {
      let value = 'N/A'
      for (const cp of item.spec?.resourcePolicy?.containerPolicies ?? []) {
        const v = cp?.[key]?.memory
        if (v != null) value = String(v)
      }
      return value
    }

    const toRow = (item: VerticalPodAutoscalerItem): VpaRow => ({
      name: item.metadata?.name ?? '',
      namespace: item.metadata?.namespace ?? namespace,
      targetKind: item.spec?.targetRef?.kind ?? 'N/A',
      // 4.1 linked Target Name to /workload/<kind-lower>s; 5.0 has no
      // workload-page destination yet, so it is plain text (the full
      // targetRef is in the data page's JSON block).
      targetName: item.spec?.targetRef?.name ?? 'N/A',
      updateMode: item.spec?.updatePolicy?.updateMode ?? 'N/A',
      minMemory: containerMem(item, 'minAllowed'),
      maxMemory: containerMem(item, 'maxAllowed'),
      created: formatTimestamp(item.metadata?.creationTimestamp),
    })
    ```
  - query key `['verticalpodautoscalers', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/verticalpodautoscalers?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/other-resource/vertical-pod-autoscaler/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(row.namespace)}`
    (the row's OWN namespace — an all-namespaces list would carry mixed
    namespaces; the link must follow the row, not the store).
  - breadcrumb: Other Resources → Vertical Pod Autoscaler List; card title
    EXACTLY `Vertical Pod Autoscaler List`.
  - columns: Name (link) / Namespace / Target Kind / Target Name (text) /
    Update Mode / Min Memory / Max Memory / Created.
  - pinned states: `No cluster selected.`, `Loading vertical pod autoscalers...`,
    `Error loading vertical pod autoscalers: {message}`,
    `No vertical pod autoscalers found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/vertical_pod_autoscalers.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/OtherResource/VerticalPodAutoscaler.tsx frontend/tests/views/vertical_pod_autoscalers.test.tsx`
  `git commit -m "feat(frontend): vertical pod autoscaler list view (4.1 CRD port, namespaced)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `vpa-data-renders-detail`, `vpa-data-conditions-from-status`,
`vpa-data-container-policies`, `vpa-data-not-found-state`,
`vpa-data-missing-name`

**Files:**
- Create: `frontend/src/views/OtherResource/VerticalPodAutoscalerData.tsx`
- Test: `frontend/tests/views/vertical_pod_autoscaler_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item full object;
  `[]` = miss OR CRD-absent) and Task 2's link (the sole producer of the
  `?name=&namespace=` strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/vertical_pod_autoscaler_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/verticalpodautoscalers?name=web-vpa&namespace=team-a`
    returning `{ kind: 'verticalpodautoscalers', items: [webVpa] }`; a miss
    handler (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a`
    — assert EXACTLY ONE fetch and that its URL has `name=web-vpa` AND
    `namespace=team-a`; CTable rows: Name `web-vpa`, Namespace `team-a`,
    Target (Owner) `web`, Update Mode `Auto`, a Created row (via
    `formatTimestamp`); the Container Policies table has header `['Container
    Name', 'Controlled Values', 'Mode', 'Min Allowed', 'Max Allowed',
    'Controlled Resources']` and a row `app / RequestsLimits / Auto /
    memory: 128Mi / memory: 1Gi / cpu, memory`; the Conditions table has a
    row `RecommendationProvided / True / 2026-01-02T03:04:06Z /
    RecommendationAvailable / ok`; the full-object block contains
    `"updateMode": "Auto"` (the JSON block).
  - `data-conditions-from-status`: the Conditions row is sourced from
    `status.conditions` (4.1's top-level `conditions` was dead) — assert the
    `RecommendationProvided` row renders.
  - `data-missing-policy`: a VPA with no `resourcePolicy` and no
    `status.conditions` → `No container policies` and `No conditions`.
  - `data-not-found-state`: `?name=ghost&namespace=team-a` →
    `No VerticalPodAutoscaler 'ghost' found`; assert NO `.text-danger` node
    for it (a state, not an error).
  - `data-missing-name`: `/other-resource/vertical-pod-autoscaler/data` (no
    param) → `Error: vertical pod autoscaler name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/vertical_pod_autoscaler_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/OtherResource/VerticalPodAutoscalerData.tsx`: clone of
  `PriorityClassData.tsx` + the 4.1 Container-Policies + Conditions tables:
  - docstring: single `?name=&namespace=` fetch (no 4.1 list-then-filter),
    the full custom object (camelCase, the Cilium seam), the
    `status.conditions` fix (4.1's top-level `conditions` was dead), the
    dropped Target link, NOT_FOUND as a pinned STATE, the `json` hljs grammar
    as the truthful classifier (ratified 2026-10-28), the 4.1 deviations (no
    trimAnnotations).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read both params: `const name = params.get('name') ?? ''`,
    `const namespace = params.get('namespace') ?? ''`.
  - query key `['vpa-data', cluster?.id, namespace, name]`; enabled when
    `cluster != null && name !== '' && namespace !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/verticalpodautoscalers?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Other Resources → Vertical Pod Autoscaler List (link) →
    `{name}`.
  - card title `Vertical Pod Autoscaler Data`.
  - CTable rows: Name / Created / Namespace / Target (Owner)
    (`spec.targetRef.name ?? '—'` — plain text, the 4.1 link is dropped) /
    Update Mode (`spec.updatePolicy.updateMode ?? 'N/A'`) / Labels /
    Annotations (sub-tables, `No labels` / `No annotations` when empty — the
    priorityclass twin's shape).
  - Container Policies table (nested CTable, header Container Name /
    Controlled Values / Mode / Min Allowed / Max Allowed / Controlled
    Resources), one row per `spec.resourcePolicy.containerPolicies[]` entry
    (`No container policies` when the resource policy or list is absent):
    ```tsx
    const policies = item?.spec?.resourcePolicy?.containerPolicies ?? []
    // Min/Max Allowed render "resource: value" lines (N/A when the bound is absent).
    const bounds = (b?: Record<string, string>) =>
      b && Object.keys(b).length ? Object.entries(b).map(([k, v]) => `${k}: ${v}`) : ['N/A']
    // row: <td>{cp.containerName}</td><td>{cp.controlledValues ?? 'N/A'}</td><td>{cp.mode ?? 'N/A'}</td><td>{bounds(cp.minAllowed).join('<br/>')}</td><td>{bounds(cp.maxAllowed).join('<br/>')}</td><td>{cp.controlledResources?.join(', ') || 'N/A'}</td>
    ```
  - Conditions table (nested CTable, header Type / Status / Last Transition
    Time / Reason / Message), one row per `status.conditions[]` entry
    (`No conditions` when absent) — read from `status.conditions` (4.1's
    top-level `conditions` was never populated).
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No VerticalPodAutoscaler '{name}' found`,
    `Error: vertical pod autoscaler name not provided`,
    `Loading vertical pod autoscaler data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/vertical_pod_autoscaler_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/OtherResource/VerticalPodAutoscalerData.tsx frontend/tests/views/vertical_pod_autoscaler_data.test.tsx`
  `git commit -m "feat(frontend): vertical pod autoscaler data view (4.1 CRD tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `vpa-stub-removed-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 2–3's view components.
- Produces: the resolved nav leaf (the goal).
- Seam: react-router `Route` + the `stubRoutes` array.
- Deletion test: delete the two `Route`s → both paths fall through to the
  stub list (or 404 once the stub entry is gone) — the nav leaf is dead
  again, the exact pre-change state.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the two view imports
  (next to the priorityclass imports, after line 48) and, after the
  priorityclass pair (line ~381), mirror the block:
  ```tsx
  <Route
    path="/other-resource/vertical-pod-autoscaler"
    element={
      <ProtectedRoute>
        <VerticalPodAutoscalerView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/other-resource/vertical-pod-autoscaler/data"
    element={
      <ProtectedRoute>
        <VerticalPodAutoscalerDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 24
  (`{ path: '/other-resource/vertical-pod-autoscaler', title: 'VPAs', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/other-resource/vertical-pod-autoscaler'` to the `viewPaths` set in
  `expectedStubs()` (the test derives expected stubs from the nav minus
  `viewPaths`; without the addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Task 3 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON
    block uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire vertical-pod-autoscaler routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_verticalpodautoscalers.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/vertical_pod_autoscalers.test.tsx tests/views/vertical_pod_autoscaler_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` absent; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend kind) ──► Task 2 (list view) ──► Task 4 (routing)
                └────────► Task 3 (data view) ──┘
```

Tasks 2 and 3 are independent of each other (both consume Task 1); either
can run first or in parallel. Task 4 last (it removes the stub, so the
views must exist first).

## Rollback

Each task is one conventional commit and independently revertable (no
schema, no dependency, no public contract change). Reverting Task 4 is
self-contained (route + stub removal + test in one commit).
