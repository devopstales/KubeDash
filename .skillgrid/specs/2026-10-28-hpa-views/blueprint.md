# HPAs (Horizontal Pod Autoscaler) Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already
ratified for namespaced kinds: secrets + networkpolicies; the 4.1 template
pair is the source of truth for the page shape).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny) before any
frontend exists; Task 2 is the list view; Task 3 the data view; Task 4 the
routing cleanup. Each task is independently revertable.

**Goal:** Resolve the nav leaf `/other-resource/horizontal-pod-autoscaler` to
a real, SAR-gated, read-only list + data pair — the 4.1 HPA pages ported with
the ratified 5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`, and already threads
`namespace` (namespaced kinds: secrets, networkpolicies). This change adds
ONE kind: `K8sClient.list_horizontal_pod_autoscalers` /
`get_horizontal_pod_autoscaler` (kubernetes `AutoscalingV1Api`, core group v1,
namespaced with the all-namespaces branch) + two dict rows (`_KINDS` /
`_GETTERS`) + one new `self._autoscaling` attribute in `__init__`. Frontend:
two views (list cloned from NetworkPolicy.tsx for the namespace handling, data
cloned from PriorityClassData.tsx for the CTable+JSON block),
`HorizontalPodAutoscalerItem` type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `AutoscalingV1Api` (already a dependency, the 4.1
code used it; one new attribute `self._autoscaling` in 5.0's
`K8sClient.__init__`), Flask + Smorest (existing route), React + CoreUI +
TanStack Query + MSW (existing), no new npm/Python dependency (air-gap,
ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/other-resources/hpa.html.j2`
(list: Name/Namespace/Owner/Targets/MinReplicas/MaxReplicas/Replicas — the
MinReplicas/MaxReplicas header-CELL swap: `{{ hpa.spec.max_replicas }}` under
`<th>MinReplicas</th>`; Owner is a hidden-form link to
`/workload/<kind-lower>s`; Targets is the legacy v1 CPU badge),
`4.1:src/kubedash/templates/other-resources/hpa-data.html.j2` (data: Name/
Created/Namespace/Annotations/Labels/Owner/Metrics/MinReplicas/MaxReplicas/
Deployment pods/Conditions — the Conditions table is dynamic-key AND reads
`hpa_data.conditions` which the read function populates ONLY from the legacy
`autoscaling.alpha.kubernetes.io/conditions` annotation, not `status`),
`4.1:src/kubedash/lib/k8s/other.py:110` (`k8sHPAListGet`:
`AutoscalingV1Api().list_namespaced_horizontal_pod_autoscaler`, generates
`name`/`namespace`/`annotations`/`labels`/`spec`/`status`/`created` + the
legacy-annotation `conditions`), `4.1:src/kubedash/blueprint/other_resources.py:79`
(the list + data routes, the data page is list-then-filter). In-repo
precedents — `backend/app/services/k8s_client.py:762-786` (the
`list_network_policies`/`get_network_policy` namespaced core-kind pair to
mirror; `self._networking` at line 224 is the attribute pattern),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch (line
~104-114, the `namespace = namespace or "default"` fallback),
`backend/tests/api/test_resources.py:1033-1090` (the networkpolicy
get-by-name + singular-rejected API tests to mirror),
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

None (the spec's vocabulary; "HorizontalPodAutoscaler" is the k8s kind, not a
new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/horizontalpodautoscalers?namespace=team-a` → 200,
  `kind: "horizontalpodautoscalers"`, items in `to_dict` form, SAR-gated on
  `list horizontalpodautoscalers` (core, namespace `team-a`), 403 names the
  resource and the client call is never made on deny
  (`horizontalpodautoscalers-list-200-in-namespace`,
  `horizontalpodautoscalers-sar-denied`).
- Without a namespace param the client uses
  `list_horizontal_pod_autoscaler_for_all_namespaces`
  (`horizontalpodautoscalers-list-all-namespaces-without-param`).
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the object, miss = `[]` (`horizontalpodautoscalers-get-by-name`).
- The singular `horizontalpodautoscaler` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`horizontalpodautoscaler-kind-singular-rejected`).
- The list view fetches
  `/api/v1/clusters/<id>/resources/horizontalpodautoscalers?namespace=<ns>`
  with `<ns> = selectedNamespace ?? 'default'`; card title EXACTLY
  `Horizontal Pod Autoscaler List`; columns Name/Namespace/Owner/Targets/Min
  Replicas/Max Replicas/Replicas; every name links to the data page with BOTH
  `name` and `namespace` (`hpa-list-renders-rows-with-data-links`).
- Targets cell = `status.current_cpu_utilization_percentage` /
  `spec.target_cpu_utilization_percentage` `%` (the `UNKNOWN` literal when the
  current is absent), Min Replicas cell = `spec.min_replicas`, Max Replicas
  cell = `spec.max_replicas` (the 4.1 header-swap corrected), Replicas cell =
  `status.current_replicas`, Owner cell = `spec.scale_target_ref.name` as
  plain text (`hpa-list-targets-and-replica-cells`,
  `hpa-list-unknown-cpu-target`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Name/Created/Namespace/Owner/Metrics/Min Replicas/Max Replicas/Replicas/
  Labels/Annotations) + the Conditions table (Type/Status/Last Transition
  Time/Reason/Message, from `status.conditions` else the legacy annotation) +
  a JSON-highlighted full-object block, and treats a miss as the pinned state
  `No HorizontalPodAutoscaler '<name>' found` — never an error style
  (`hpa-data-renders-detail`, `hpa-data-conditions-from-status`,
  `hpa-data-conditions-from-legacy-annotation`, `hpa-data-missing-conditions`,
  `hpa-data-not-found-state`).
- `/other-resource/horizontal-pod-autoscaler` is gone from
  `views/Stub/routes.ts`; both real views are routed; the nav leaf is
  byte-identical (`hpa-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `self._autoscaling` attribute + the
  two methods (modified).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_horizontalpodautoscalers.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `HorizontalPodAutoscalerItem` (modified).
- `frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx` (new).
- `frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx` (new).
- `frontend/tests/views/horizontal_pod_autoscalers.test.tsx` (new).
- `frontend/tests/views/horizontal_pod_autoscaler_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- The list view's name-link href is the SOLE producer of the data page's
  `?name=&namespace=` query strings — the data page parses the params, never
  constructs one (the priorityclass/networkpolicy contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an
  API error (the `NOT_FOUND`-throw pattern from PriorityClassData).
- The Conditions reader is the one place that touches BOTH `status.conditions`
  AND the legacy `autoscaling.alpha.kubernetes.io/conditions` annotation — the
  fallback must be guarded (a malformed/absent annotation JSON renders
  `No conditions`, never throws).
- The `name` branch of the generic route falls back to `namespace = "default"`
  when no namespace param is present — the data page ALWAYS sends the
  namespace (it has it from the link), so the fallback never fires for this
  view; the test suite pins that the data URL carries the namespace.
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `AutoscalingV1Api` is already vendored in the
  kubernetes client (the 4.1 code imported it); one new `self._autoscaling`
  attribute in `K8sClient.__init__` (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Namespaced kind (core group, v1): the list URL and the data URL carry
  `namespace=`; SAR group = `""`, namespace = the query namespace or `None`;
  the client methods use the `list_namespaced_horizontal_pod_autoscaler(namespace)`
  / `list_horizontal_pod_autoscaler_for_all_namespaces()` branch (the
  `list_network_policies` pattern).
- The `to_dict` form is snake_case (a generated core-API model) — the type and
  cell readers use snake_case keys (`spec.scale_target_ref.name`,
  `status.current_replicas`, `spec.min_replicas`).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Horizontal Pod Autoscaler List` (4.1's title, verbatim —
  the e2e-smoke contract).
- Pinned copy (do not reword): `No horizontal pod autoscalers found`,
  `No HorizontalPodAutoscaler '<name>' found`,
  `Error: horizontal pod autoscaler name not provided`, `No cluster selected.`,
  `Loading horizontal pod autoscalers...`, `No labels`, `No annotations`,
  `No conditions`, and the 4.1 `UNKNOWN` CPU-target literal.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `self._autoscaling =
  k8s_client.AutoscalingV1Api(api_client)` next to `self._networking`
  (line ~224); `list_horizontal_pod_autoscalers` next to
  `list_network_policies` (line ~762), `get_horizontal_pod_autoscaler` next to
  `get_network_policy` (line ~777).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["horizontalpodautoscalers"]` + `_GETTERS["horizontalpodautoscalers"]`.
- `backend/tests/services/test_k8s_client_horizontalpodautoscalers.py` (new)
  — `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_horizontal_pod_autoscalers` / `get_horizontal_pod_autoscaler`; 6 new
  tests.
- `frontend/src/lib/types.ts` (modify) — `HorizontalPodAutoscalerItem` next
  to `NetworkPolicyItem` / `PriorityClassItem`.
- `frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx` (new) —
  namespace handling from NetworkPolicy.tsx, layout from PriorityClass.tsx.
- `frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx` (new) —
  clone of PriorityClassData.tsx + the 4.1 Metrics/Replicas/Conditions rows.
- `frontend/tests/views/horizontal_pod_autoscalers.test.tsx` (new).
- `frontend/tests/views/horizontal_pod_autoscaler_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (line ~381) + the two view imports (after line 48).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 23
  (`/other-resource/horizontal-pod-autoscaler`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — horizontalpodautoscalers kind (service + `_KINDS` + API tests)

**SATISFIES:** `horizontalpodautoscalers-list-200-in-namespace`,
`horizontalpodautoscalers-list-all-namespaces-without-param`,
`horizontalpodautoscalers-sar-denied`, `horizontalpodautoscalers-binding-404`,
`horizontalpodautoscaler-kind-singular-rejected`,
`horizontalpodautoscalers-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_horizontalpodautoscalers.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_horizontal_pod_autoscalers(namespace: str | None)
  -> list[dict]` and `K8sClient.get_horizontal_pod_autoscaler(namespace: str,
  name: str) -> list[dict]` — the exact names `_KINDS`/`_GETTERS` reference
  via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the networkpolicies tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_horizontalpodautoscalers.py`,
  mirroring the networkpolicies test pattern with `object.__new__` +
  `SimpleNamespace`:

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient


  def _client(autoscaling: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._autoscaling = autoscaling
      return client


  def test_list_horizontal_pod_autoscalers_in_namespace() -> None:
      """[horizontalpodautoscalers-list-200-in-namespace] a namespace is
      forwarded to ``list_namespaced_horizontal_pod_autoscaler`` (the
      ``list_network_policies`` pattern)."""
      seen: list[object] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "web-hpa", "namespace": "team-a"},
              "spec": {"max_replicas": 10, "min_replicas": 2,
                       "scale_target_ref": {"kind": "Deployment", "name": "web"}},
              "status": {"current_replicas": 3, "current_cpu_utilization_percentage": 50},
          }
      )
      autoscaling = SimpleNamespace(
          list_namespaced_horizontal_pod_autoscaler=lambda namespace: (
              seen.append(namespace),
              SimpleNamespace(items=[item]),
          )[1],
      )
      result = _client(autoscaling).list_horizontal_pod_autoscalers("team-a")
      assert result[0]["metadata"]["namespace"] == "team-a"
      assert seen == ["team-a"]  # the namespace is forwarded, not dropped


  def test_list_horizontal_pod_autoscalers_all_namespaces_without_namespace() -> None:
      """[horizontalpodautoscalers-list-all-namespaces-without-param]
      ``None`` uses the all-namespaces call (the ``list_secrets`` branch)."""
      seen: list[object] = []
      autoscaling = SimpleNamespace(
          list_horizontal_pod_autoscaler_for_all_namespaces=lambda: (
              seen.append(True),
              SimpleNamespace(items=[]),
          )[1],
      )
      assert _client(autoscaling).list_horizontal_pod_autoscalers(None) == []
      assert seen == [True]


  def test_list_horizontal_pod_autoscalers_maps_500_to_unreachable() -> None:
      def list_all(namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_horizontal_pod_autoscaler=list_all)).list_horizontal_pod_autoscalers("team-a")


  def test_get_horizontal_pod_autoscaler_404_returns_empty_list() -> None:
      """[horizontalpodautoscalers-get-by-name] a miss is ``[]``, mirroring
      ``get_network_policy``'s 0/1-item contract."""
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=404)

      autoscaling = SimpleNamespace(read_namespaced_horizontal_pod_autoscaler=read)
      assert _client(autoscaling).get_horizontal_pod_autoscaler("team-a", "ghost") == []


  def test_get_horizontal_pod_autoscaler_hit_returns_one_item() -> None:
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-hpa"}})
      autoscaling = SimpleNamespace(read_namespaced_horizontal_pod_autoscaler=lambda name, namespace: item)
      assert _client(autoscaling).get_horizontal_pod_autoscaler("team-a", "web-hpa") == [
          {"metadata": {"name": "web-hpa"}}
      ]


  def test_get_horizontal_pod_autoscaler_other_api_error_maps_to_unreachable() -> None:
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_horizontal_pod_autoscaler=read)).get_horizontal_pod_autoscaler("team-a", "web-hpa")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_horizontalpodautoscalers.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`:

  `__init__`, next to `self._networking` (line ~224):
  ```python
  # HorizontalPodAutoscaler (autoscaling/v1, namespaced) — the R4
  # "horizontalpodautoscalers" kind (4.1-parity nav leaf; ADR-0022 placement).
  self._autoscaling = k8s_client.AutoscalingV1Api(api_client)
  ```

  Next to `list_network_policies` (line ~762):
  ```python
  def list_horizontal_pod_autoscalers(self, namespace: str | None) -> list[dict[str, Any]]:
      """HorizontalPodAutoscaler list in the standard kubernetes dict form
      (``to_dict``) for one namespace, or across all namespaces when the
      namespace is ``None`` (the ``list_secrets`` branch). No field stripping
      — the view renders ``spec``/``status`` and the data page the full
      object. A transport ApiException maps to ``ClusterUnreachableError``
      (502)."""
      try:
          resp = (
              self._autoscaling.list_namespaced_horizontal_pod_autoscaler(namespace)
              if namespace
              else self._autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_horizontal_pod_autoscalers", e)
          raise AssertionError("unreachable") from e
      return [h.to_dict() for h in resp.items]
  ```

  Next to `get_network_policy` (line ~777):
  ```python
  def get_horizontal_pod_autoscaler(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One HorizontalPodAutoscaler as a 0/1-item list; ``[]`` on 404. Any
      other ApiException maps to ``ClusterUnreachableError`` (502), matching
      ``get_network_policy``'s transport contract."""
      try:
          return [self._autoscaling.read_namespaced_horizontal_pod_autoscaler(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_horizontal_pod_autoscaler", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "horizontalpodautoscalers": (
      "list_horizontal_pod_autoscalers",
      "horizontalpodautoscalers",
      "",
  ),
  ```
  in `_KINDS` (after the priorityclasses row; core group = `""`), and
  ```python
  "horizontalpodautoscalers": "get_horizontal_pod_autoscaler",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the networkpolicy block,
  lines 1033–1090):
  - FakeK8s gains:
    ```python
    def list_horizontal_pod_autoscalers(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (autoscaling/v1): the namespace is forwarded (the
        # real K8sClient.list_horizontal_pod_autoscalers pattern).
        return [
            {
                "metadata": {
                    "name": "web-hpa",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {},
                },
                "spec": {
                    "scale_target_ref": {"kind": "Deployment", "name": "web", "api_version": "apps/v1"},
                    "min_replicas": 2,
                    "max_replicas": 10,
                    "target_cpu_utilization_percentage": 80,
                },
                "status": {
                    "current_replicas": 3,
                    "desired_replicas": 3,
                    "current_cpu_utilization_percentage": 50,
                    "conditions": [
                        {
                            "type": "AbleToScale",
                            "status": "True",
                            "last_transition_time": "2026-01-02T03:04:06Z",
                            "reason": "SuccessfulRescale",
                            "message": "Ready to scale",
                        }
                    ],
                },
            }
        ]

    def get_horizontal_pod_autoscaler(self, namespace: str, name: str) -> list[dict]:
        if name == "web-hpa":
            return self.list_horizontal_pod_autoscalers(namespace)
        return []
    ```
  - Six new tests mirroring the networkpolicy block, same docstring-tag style:
    - `test_list_horizontalpodautoscalers_200_in_namespace` — 200,
      `body["kind"] == "horizontalpodautoscalers"`, one item in `team-a`;
      assert the FakeK8s received `namespace="team-a"`.
    - `test_list_horizontalpodautoscalers_all_namespaces_without_param` — no
      `namespace` param → 200; assert the FakeK8s received `None` (the
      all-namespaces branch).
    - `test_list_horizontalpodautoscalers_get_by_name` —
      `?name=web-hpa&namespace=team-a` → 1 item;
      `?name=ghost&namespace=team-a` → `items == []`.
    - `test_list_horizontalpodautoscalers_sar_denied` — SAR denies; 403;
      assert `("list", "horizontalpodautoscalers", "team-a", None, "")` in
      `asked` (namespace `team-a`, core group `""` — the load-bearing
      assertions).
    - `test_horizontalpodautoscalers_binding_404` — cluster 999, unbound user
      → 404.
    - `test_horizontalpodautoscaler_kind_singular_rejected` —
      `/resources/horizontalpodautoscaler` → 404
      `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_horizontalpodautoscalers.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_horizontalpodautoscalers.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): horizontalpodautoscalers kind (autoscaling, namespaced, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `hpa-list-renders-rows-with-data-links`,
`hpa-list-targets-and-replica-cells`, `hpa-list-unknown-cpu-target`,
`hpa-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx`
- Test: `frontend/tests/views/horizontal_pod_autoscalers.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `horizontalpodautoscalers` list URL, namespaced).
- Produces: the data-page link
  `/other-resource/horizontal-pod-autoscaler/data?name=<name>&namespace=<ns>`
  — the SOLE producer of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedNamespace`
  (no new seam).
- Deletion test: deleting the view → the route (Task 4) 404s / the test file
  fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `NetworkPolicyItem`:

  ```ts
  /** A HorizontalPodAutoscaler item as returned by /api/v1/clusters/<id>/resources/horizontalpodautoscalers (kubernetes to_dict, snake_case; namespaced, autoscaling/v1). */
  export interface HorizontalPodAutoscalerItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      scale_target_ref?: { kind?: string; name?: string; api_version?: string }
      min_replicas?: number
      max_replicas?: number
      target_cpu_utilization_percentage?: number
      metrics?: unknown[]
    }
    status?: {
      current_replicas?: number
      desired_replicas?: number
      current_cpu_utilization_percentage?: number
      conditions?: Array<{
        type?: string
        status?: string
        last_transition_time?: string
        reason?: string
        message?: string
      }>
    }
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/horizontal_pod_autoscalers.test.tsx`: clone
  `network_policies.test.tsx` 1:1 (KubeDataTable fake included) with the
  network_policies namespace setup (`selectProd` sets
  `selectedNamespace: 'team-a'`), and:
  - fixture `webHpa` (the to_dict shape):
    ```ts
    const webHpa = {
      apiVersion: 'autoscaling/v1',
      kind: 'HorizontalPodAutoscaler',
      metadata: {
        name: 'web-hpa',
        namespace: 'team-a',
        creation_timestamp: '2026-01-02T03:04:05Z',
        labels: { team: 'a' },
        annotations: {},
      },
      spec: {
        scale_target_ref: { kind: 'Deployment', name: 'web', api_version: 'apps/v1' },
        min_replicas: 2,
        max_replicas: 10,
        target_cpu_utilization_percentage: 80,
      },
      status: {
        current_replicas: 3,
        desired_replicas: 3,
        current_cpu_utilization_percentage: 50,
        conditions: [{ type: 'AbleToScale', status: 'True', last_transition_time: '2026-01-02T03:04:06Z', reason: 'SuccessfulRescale', message: 'Ready to scale' }],
      },
    }
    const noCpuHpa = { ...webHpa, status: { ...webHpa.status, current_cpu_utilization_percentage: undefined } }
    ```
  - `renderAt` default path `/other-resource/horizontal-pod-autoscaler`; MSW
    handler on `*/api/v1/clusters/1/resources/horizontalpodautoscalers`.
  - `list-renders-hpa-rows-with-data-links`: link `web-hpa` →
    `/other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a`;
    fetch URL EXACTLY
    `/api/v1/clusters/1/resources/horizontalpodautoscalers?namespace=team-a`;
    heading EXACTLY `Horizontal Pod Autoscaler List`; breadcrumb `Other
    Resources`; column headers `['Name', 'Namespace', 'Owner', 'Targets',
    'Min Replicas', 'Max Replicas', 'Replicas']`; row shows `team-a`.
  - `list-targets-and-replica-cells`: Targets `50 / 80 %`; Min Replicas `2`,
    Max Replicas `10` (the 4.1 header-swap corrected — assert the Min cell is
    `2`, NOT `10`); Replicas `3`; Owner `web` as PLAIN TEXT (not a link).
  - `list-unknown-cpu-target`: `noCpuHpa` row → Targets cell shows
    `UNKNOWN / 80 %`.
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-error-state`: 403 `RBAC_DENIED` →
    `Error loading horizontal pod autoscalers: RBAC_DENIED: list on
    horizontalpodautoscalers`.
  - `list-empty-state`: `items: []` → `No horizontal pod autoscalers found`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/horizontal_pod_autoscalers.test.tsx`
  Expected: FAIL (cannot find module
  `src/views/OtherResource/HorizontalPodAutoscaler`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx`: layout from
  `PriorityClass.tsx`, namespace handling from `NetworkPolicy.tsx`:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement,
    the `?name=&namespace=` delta, the min/max header-swap correction, the
    legacy v1 CPU target (the `UNKNOWN` literal), the dropped Owner link.
  - `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`
  - `type HpaRow = { name, namespace, owner: string, targets: string, minReplicas: string, maxReplicas: string, replicas: string }`:
    ```ts
    // 4.1's Targets badge: current/target CPU percent (a legacy autoscaling/v1
    // field). The "UNKNOWN" literal is 4.1's exact fallback for an absent
    // current (certainty rule: never guess). 4.1's list template swapped the
    // Min/Max cells ({{ max_replicas }} under <th>MinReplicas</th>); 5.0
    // renders the matching value under each header.
    const toRow = (item: HorizontalPodAutoscalerItem): HpaRow => ({
      name: item.metadata?.name ?? '',
      namespace: item.metadata?.namespace ?? namespace,
      // 4.1 linked Owner to /workload/<kind-lower>s; 5.0 has no
      // workload-page destination yet, so it is plain text (the full
      // scale_target_ref is in the data page's JSON block).
      owner: item.spec?.scale_target_ref?.name ?? '—',
      targets: `${item.status?.current_cpu_utilization_percentage ?? 'UNKNOWN'} / ${item.spec?.target_cpu_utilization_percentage ?? '—'} %`,
      minReplicas: item.spec?.min_replicas != null ? String(item.spec.min_replicas) : '—',
      maxReplicas: item.spec?.max_replicas != null ? String(item.spec.max_replicas) : '—',
      replicas: item.status?.current_replicas != null ? String(item.status.current_replicas) : '—',
    })
    ```
  - query key `['horizontalpodautoscalers', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/horizontalpodautoscalers?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/other-resource/horizontal-pod-autoscaler/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(row.namespace)}`
    (the row's OWN namespace — an all-namespaces list would carry mixed
    namespaces; the link must follow the row, not the store).
  - breadcrumb: Other Resources → Horizontal Pod Autoscaler List; card title
    EXACTLY `Horizontal Pod Autoscaler List`.
  - columns: Name (link) / Namespace / Owner (text) / Targets / Min Replicas /
    Max Replicas / Replicas.
  - pinned states: `No cluster selected.`, `Loading horizontal pod
    autoscalers...`, `Error loading horizontal pod autoscalers: {message}`,
    `No horizontal pod autoscalers found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/horizontal_pod_autoscalers.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx frontend/tests/views/horizontal_pod_autoscalers.test.tsx`
  `git commit -m "feat(frontend): horizontal pod autoscaler list view (4.1 port, namespaced)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `hpa-data-renders-detail`, `hpa-data-conditions-from-status`,
`hpa-data-conditions-from-legacy-annotation`, `hpa-data-missing-conditions`,
`hpa-data-not-found-state`, `hpa-data-missing-name`

**Files:**
- Create: `frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx`
- Test: `frontend/tests/views/horizontal_pod_autoscaler_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item list; `[]` =
  miss) and Task 2's link (the sole producer of the `?name=&namespace=`
  strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/horizontal_pod_autoscaler_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/horizontalpodautoscalers?name=web-hpa&namespace=team-a`
    returning `{ kind: 'horizontalpodautoscalers', items: [webHpa] }`; a miss
    handler (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a`
    — assert EXACTLY ONE fetch and that its URL has `name=web-hpa` AND
    `namespace=team-a`; CTable rows: Name `web-hpa`, Namespace `team-a`,
    Owner `web`, Metrics `50 / 80 %`, Min Replicas `2`, Max Replicas `10`,
    Replicas `3 Current / 3 Desired`, a Created row (via `formatTimestamp`);
    the full-object block contains `"min_replicas": 2` (the JSON block).
  - `data-conditions-from-status`: a HPA with `status.conditions` → the
    Conditions table has a row `AbleToScale / True / 2026-01-02T03:04:06Z /
    SuccessfulRescale / Ready to scale`.
  - `data-conditions-from-legacy-annotation`: a HPA with NO
    `status.conditions` but the `autoscaling.alpha.kubernetes.io/conditions`
    annotation = a JSON string of `[{type:'AbleToScale',status:'True',...}]`
    → the Conditions table shows that condition as a typed row (4.1's source).
  - `data-missing-conditions`: a HPA with neither → `No conditions`.
  - `data-not-found-state`: `?name=ghost&namespace=team-a` →
    `No HorizontalPodAutoscaler 'ghost' found`; assert NO `.text-danger` node
    for it (a state, not an error).
  - `data-missing-name`: `/other-resource/horizontal-pod-autoscaler/data`
    (no param) → `Error: horizontal pod autoscaler name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/horizontal_pod_autoscaler_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx`: clone of
  `PriorityClassData.tsx` + the 4.1 Metrics/Replicas/Conditions:
  - docstring: single `?name=&namespace=` fetch (no 4.1 list-then-filter), the
    legacy v1 CPU target (`UNKNOWN` literal), the Conditions source
    (`status.conditions` else the legacy `autoscaling.alpha.kubernetes.io/
    conditions` annotation — 4.1's source), NOT_FOUND as a pinned STATE, the
    `json` hljs grammar as the truthful classifier (ratified 2026-10-28), the
    4.1 deviations (min/max swap corrected list-only, no trimAnnotations,
    typed Conditions).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read both params: `const name = params.get('name') ?? ''`,
    `const namespace = params.get('namespace') ?? ''`.
  - query key `['hpa-data', cluster?.id, namespace, name]`; enabled when
    `cluster != null && name !== '' && namespace !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/horizontalpodautoscalers?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Other Resources → Horizontal Pod Autoscaler List (link) →
    `{name}`.
  - card title `Horizontal Pod Autoscaler Data`.
  - CTable rows: Name / Created / Namespace / Owner
    (`spec.scale_target_ref.name ?? '—'` — plain text, the 4.1 link is
    dropped) / Metrics
    (`${status.current_cpu_utilization_percentage ?? 'UNKNOWN'} /
    ${spec.target_cpu_utilization_percentage ?? '—'} %`) / Min Replicas
    (`spec.min_replicas ?? '—'`) / Max Replicas (`spec.max_replicas ?? '—'`) /
    Replicas (`${status.current_replicas ?? '—'} Current /
    ${status.desired_replicas ?? '—'} Desired`) / Labels / Annotations
    (sub-tables, `No labels` / `No annotations` when empty — the
    priorityclass twin's shape).
  - Conditions reader (the one place touching `status` AND the legacy
    annotation):
    ```ts
    // 4.1 read the conditions from the legacy
    // autoscaling.alpha.kubernetes.io/conditions annotation (a json.loads of
    // the value); modern HPAs carry them on status.conditions. Read
    // status.conditions first, fall back to the annotation (4.1's source).
    // A malformed/absent annotation renders [] (No conditions), never throws.
    const LEGACY_CONDITIONS = 'autoscaling.alpha.kubernetes.io/conditions'
    const conditionsOf = (item: HorizontalPodAutoscalerItem) => {
      const statusConds = item.status?.conditions
      if (statusConds && statusConds.length) return statusConds
      const raw = item.metadata?.annotations?.[LEGACY_CONDITIONS]
      if (!raw) return []
      try {
        const parsed = JSON.parse(raw)
        return Array.isArray(parsed) ? parsed : []
      } catch {
        return []
      }
    }
    ```
  - Conditions table (nested CTable, header Type / Status / Last Transition
    Time / Reason / Message), one row per `conditionsOf(item)` entry (`No
    conditions` when empty).
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No HorizontalPodAutoscaler '{name}' found`,
    `Error: horizontal pod autoscaler name not provided`,
    `Loading horizontal pod autoscaler data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/horizontal_pod_autoscaler_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/OtherResource/HorizontalPodAutoscalerData.tsx frontend/tests/views/horizontal_pod_autoscaler_data.test.tsx`
  `git commit -m "feat(frontend): horizontal pod autoscaler data view (4.1 tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `hpa-stub-removed-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 2–3's view components.
- Produces: the resolved nav leaf (the goal).
- Seam: react-router `Route` + the `stubRoutes` array.
- Deletion test: delete the two `Route`s → both paths fall through to the
  stub list (or 404 once the stub entry is gone) — the nav leaf is dead again,
  the exact pre-change state.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the two view imports
  (next to the priorityclass imports, after line 48) and, after the
  priorityclass pair (line ~381), mirror the block:
  ```tsx
  <Route
    path="/other-resource/horizontal-pod-autoscaler"
    element={
      <ProtectedRoute>
        <HorizontalPodAutoscalerView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/other-resource/horizontal-pod-autoscaler/data"
    element={
      <ProtectedRoute>
        <HorizontalPodAutoscalerDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 23
  (`{ path: '/other-resource/horizontal-pod-autoscaler', title: 'HPAs', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/other-resource/horizontal-pod-autoscaler'` to the `viewPaths` set in
  `expectedStubs()` (the test derives expected stubs from the nav minus
  `viewPaths`; without the addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Task 3 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON block
    uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire horizontal-pod-autoscaler routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_horizontalpodautoscalers.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/horizontal_pod_autoscalers.test.tsx tests/views/horizontal_pod_autoscaler_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` absent; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend kind) ──► Task 2 (list view) ──► Task 4 (routing)
                └────────► Task 3 (data view) ──┘
```

Tasks 2 and 3 are independent of each other (both consume Task 1); either can
run first or in parallel. Task 4 last (it removes the stub, so the views must
exist first).

## Rollback

Each task is one conventional commit and independently revertable (no schema,
no dependency, no public contract change). Reverting Task 4 is
self-contained (route + stub removal + test in one commit).
