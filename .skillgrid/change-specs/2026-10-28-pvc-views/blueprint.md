# PVC Views (List + Data + Usage) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route + one additive
metrics route; no migration, no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already ratified
for namespaced core kinds: secrets/resourcequotas/networkpolicies; the Usage
route mirrors the ADR-0003 two-tier metrics pattern already in
`backend/app/api/metrics.py`; the 4.1 template pair is the source of truth
for the page shape).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny) before any
frontend exists; Task 2 is the Usage metrics route (the list page's second
fetch needs it); Task 3 is the list view; Task 4 the data view; Task 5 the
routing cleanup. Each task is independently revertable.

**Goal:** Resolve the nav leaf `/storage/pvc` to a real, SAR-gated, read-only
list + data pair — the 4.1 PVC pages ported with the ratified 5.0 deltas —
plus the PVC-usage metrics route that feeds the list's Usage column.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_persistent_volume_claims` / `get_persistent_volume_claim`
(kubernetes `CoreV1Api`, core group, **namespaced** — the
`list_secrets` / `get_resource_quota` pattern) + two dict rows
(`_KINDS` / `_GETTERS`), NO new `__init__` attribute (`self._v1` already
exists). Plus ONE metrics route: `GET /v1/clusters/<id>/metrics/pvcs` in
`backend/app/api/metrics.py` + `K8sClient.pvc_usage(namespace)` — kubelet
`/stats/summary` per node (the 4.1 `k8sPVCMetric` read, re-implemented with
`json.loads` instead of `eval`), the ADR-0003 query-only degrade (unavailable
stats → 200 empty, never 500) and the ADR-0004 two-tier gate (`get nodes`
SAR deny → 200 `metrics_denied: true`, never 403). Frontend: two views
(list cloned from the namespaced ResourceQuota view — header-selected
namespace, KubeDataTable — with a second parallel query for usage joined by
PVC name; data cloned from the ResourceQuota data view for the CTable + JSON
block), `PvcItem` / `PvcUsageOut` types, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CoreV1Api` (already a dependency — `self._v1`
exists in `K8sClient.__init__`; the 4.1 code used the same API),
Flask + Smorest (existing metrics blueprint + resources route), React +
CoreUI + TanStack Query + MSW (existing), no new npm/Python dependency
(air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R6).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/storage/pvc.html.j2`
(list: Status/Name/StorageClass/Volume/Capacity/Usage — Status is the
`status.phase` three-tier badge Bound→success / Terminating→danger / else
→warning; Usage is `percentageUsed|round(1)` % joined from `pvc_metrics`;
Name/StorageClass/Volume cells are hidden-form POST links),
`4.1:src/kubedash/templates/storage/pvc-data.html.j2` (data: Status/Name/
Namespace/Created/Annotations/Labels/StorageClass/Persistent Volume/Access
Mode/VolumeMode/Capacity — 4.1's "Lables" typo, list-then-filter),
`4.1:src/kubedash/lib/k8s/storage.py:83` (`k8sPersistentVolumeClaimListGet`:
`CoreV1Api().list_namespaced_persistent_volume_claim`, generates
`status`/`name`/`created`/`annotations`/`labels`/`access_modes`/
`storage_class_name`/`volume_name`/`volume_mode`/`capacity`),
`4.1:src/kubedash/lib/k8s/metrics.py:348` (`k8sPVCMetric`: per-node
`connect_get_node_proxy_with_path(name, path="stats/summary",
_request_timeout=1)`, `eval(data)`, aggregates `pod.volume[].pvcRef` for the
namespace: capacityBytes/usedBytes/availableBytes/percentageUsed; swallows
ApiException → partial list), `4.1:src/kubedash/blueprint/storage.py:119`
(the list + data routes; the data page re-lists then filters by name in
Python). In-repo precedents —
`backend/app/services/k8s_client.py:736-790` (the `list_resource_quotas` /
`get_resource_quota` namespaced core-kind pattern to mirror — the
`list_namespaced_*` vs `list_*_for_all_namespaces` branch, 0/1-item getter,
`_unreachable` mapping), `backend/app/api/metrics.py:97-133` (the
`node_metrics` route — the two-tier metrics.k8s.io SAR gate +
`metrics_available`/`metrics_denied` degrade shape to mirror for kubelet
stats), `backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name`
branch (line ~104-114, the `namespace = namespace or "default"` fallback —
the data page always sends its namespace so the fallback is never used in
practice), `backend/tests/api/test_resources.py` (the resourcequotas API
tests to mirror: namespaced 200, all-namespaces branch, get-by-name, SAR deny
with namespace, binding 404, singular kind rejected),
`frontend/src/views/OtherResource/ResourceQuota.tsx` + `ResourceQuotaData.tsx`
(the namespaced list/data view pair to clone — header-selected namespace,
ALWAYS sends `?namespace=`, KubeDataTable + CTable + JSON block),
`frontend/tests/views/resource_quotas.test.tsx` +
`resource_quota_data.test.tsx` (the namespaced test patterns to clone).

**In-force ADRs:** per `adr.md` — ADR-0003, ADR-0004, ADR-0009, ADR-0010,
ADR-0020, ADR-0021, ADR-0022. None created.

## Terms

None (the spec's vocabulary; "PVC" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/persistentvolumeclaims?namespace=<ns>` → 200,
  `kind: "persistentvolumeclaims"`, items in `to_dict` snake_case form,
  SAR-gated on `list persistentvolumeclaims` (core, the query namespace),
  403 names the resource and the client call is never made on deny
  (`pvcs-list-200`, `pvcs-sar-denied`).
- Without `?namespace=` the list spans all namespaces
  (`list_persistent_volume_claim_for_all_namespaces` — the `list_secrets`
  branch) (`pvcs-list-all-namespaces`).
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the object, miss = `[]` (`pvcs-get-by-name`).
- The singular `persistentvolumeclaim` kind (and `pvc`) is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`pvc-kind-singular-rejected`).
- `GET .../metrics/pvcs?namespace=<ns>` → 200 with
  `{ cluster, namespace, source: "kubelet stats/summary",
  metrics_available, metrics_denied, items }`; per-PVC
  `capacity_bytes`/`used_bytes`/`available_bytes`/`percentage_used`
  aggregated across pods by `pvcRef`; a PVC with zero capacity reports
  `percentage_used: 0.0` (never a division error)
  (`pvc-usage-happy-path`).
- A metrics SAR deny (`get` on `nodes`) → 200 `metrics_denied: true`,
  `metrics_available: false`, `items: []` — NEVER a 403
  (`pvc-usage-sar-denied`).
- Every node whose `/stats/summary` fails (404/5xx/timeout) is skipped;
  zero healthy nodes → 200 `metrics_available: false`, `items: []`; a
  partial node set → 200 with the healthy subset
  (`pvc-usage-kubelet-degrade`, `pvc-usage-partial-nodes`).
- The list view fetches `/api/v1/clusters/<id>/resources/
  persistentvolumeclaims?namespace=<ns>` (namespace ALWAYS from
  `useClusterStore.selectedNamespace ?? 'default'`) and a SECOND parallel
  fetch on `/api/v1/clusters/<id>/metrics/pvcs?namespace=<ns>`; card title
  EXACTLY `Persistent Volume Claim List`; columns Status/Name/StorageClass/
  Volume/Capacity/Usage; every name links to
  `/storage/pvc/data?name=<name>&namespace=<ns>`
  (`pvc-list-renders-rows-with-data-links`).
- Status cell = `status.phase` badge (Bound → success, Terminating → danger,
  else warning, `—` when absent); StorageClass = `spec.storage_class_name`,
  Volume = `spec.volume_name`, Capacity = `status.capacity.storage` (each
  `—` when absent); Usage cell = `percentage_used` joined by PVC name,
  rendered `<pct> %` one decimal, `—` when the PVC is not in the metrics
  items, when `metrics_available` is false, or when the usage fetch fails
  (`pvc-list-usage-join`, `pvc-list-usage-degrades-to-em-dash`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Status/Name/Namespace/Created/Access Mode/Volume Mode/Capacity/
  StorageClass/Persistent Volume/Labels/Annotations) + the JSON-highlighted
  full-object block, and treats a miss as the pinned state `No PVC
  '<name>' found` — never an error style
  (`pvc-data-renders-detail`, `pvc-data-not-found-state`).
- `/storage/pvc` is gone from `views/Stub/routes.ts`; both real views are
  routed; the nav leaf is byte-identical
  (`pvc-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `list_persistent_volume_claims`,
  `get_persistent_volume_claim`, `pvc_usage` (modified; no new `__init__`
  attribute).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/app/api/metrics.py` — the `pvcs` route (modified).
- `backend/app/schemas/metrics.py` — `PvcUsageOut` (modified).
- `backend/tests/services/test_k8s_client_pvcs.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 7 new tests
  (modified).
- `backend/tests/api/test_metrics_pvcs.py` (new).
- `frontend/src/lib/types.ts` — `PvcItem`, `PvcUsage` (modified).
- `frontend/src/views/Storage/Pvc.tsx` (new).
- `frontend/src/views/Storage/PvcData.tsx` (new).
- `frontend/tests/views/pvcs.test.tsx` (new).
- `frontend/tests/views/pvc_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- The list view's usage join is BY PVC NAME across two independent
  responses: the metrics route returns `items[].name` = the PVC name in the
  SAME namespace the view requested; the view builds a `Map<name, item>` and
  looks up each row. A PVC absent from the metrics items (no pods using it,
  or stats unavailable) renders `—` — the join NEVER errors and NEVER blocks
  the list (the usage query's `isError` is swallowed to `—`, mirroring the
  ADR-0003 two-tier rule client-side).
- The Usage cell's `—` has THREE distinct causes the view must not
  distinguish: PVC not in `items`, `metrics_available: false`, and the
  fetch itself failed — all three render `—` (certainty rule: the observed
  tier degrades to unknown, never to a row error).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an
  API error (the NOT_FOUND-as-state pattern from the resourcequota data view).
- The `to_dict` form is snake_case (a generated core-API model) — the type
  and cell readers use snake_case keys (`storage_class_name`,
  `volume_name`, `access_modes`, `volume_mode`, `status.capacity.storage`,
  `status.phase`).
- The kubelet stats body is parsed with `json.loads`, NEVER `eval` (the 4.1
  `eval(data)` is replaced; the body is a JSON document from the kubelet
  Summary API).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table and the metrics route are additive).

## Global Constraints

- No new Python dependency — `CoreV1Api` is already the client's `self._v1`
  (the PVC methods need NO new attribute; the stats read uses the same
  `self._v1.connect_get_node_proxy_with_path`); `json` is stdlib (air-gap,
  ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by the resourcequota data view; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Namespaced kind (core group, v1): the list URL carries `?namespace=` when
  given; the data URL carries `?name=&namespace=` (the page always sends
  both); SAR group = `""`, namespace = the query namespace or `None`.
- The `to_dict` form is snake_case (a generated core-API model) — the type
  and cell readers use snake_case keys.
- The metrics route is KUBELET stats, not metrics.k8s.io — the response
  `source` field is EXACTLY `"kubelet stats/summary"` so the UI can say
  which observed tier is missing (the `source: "metrics.k8s.io"` distinction
  from the existing node_metrics route).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Persistent Volume Claim List` (4.1's title, verbatim —
  the e2e-smoke contract).
- Pinned copy (do not reword): `No persistent volume claims found`,
  `No PVC '<name>' found`, `Error: pvc name not provided`,
  `No cluster selected.`, `Loading persistent volume claims...`,
  `No labels`, `No annotations`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_persistent_volume_
  claims` next to `list_resource_quotas` (line ~736),
  `get_persistent_volume_claim` next to `get_resource_quota` (line ~780),
  `pvc_usage` next to the `node_metrics` family (line ~369).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["persistentvolumeclaims"]` + `_GETTERS["persistentvolumeclaims"]`.
- `backend/app/api/metrics.py` (modify) — the `pvcs` route after
  `node_metrics`.
- `backend/app/schemas/metrics.py` (modify) — `PvcUsageOut` (and the
  per-item schema).
- `backend/tests/services/test_k8s_client_pvcs.py` (new) —
  `object.__new__` + `SimpleNamespace` fake for the list/get methods; a
  faked `self._v1.connect_get_node_proxy_with_path` for `pvc_usage`.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_persistent_volume_claims` / `get_persistent_volume_claim`; 7 new
  tests.
- `backend/tests/api/test_metrics_pvcs.py` (new) — the metrics route
  against the FakeK8s pool seam.
- `frontend/src/lib/types.ts` (modify) — `PvcItem`, `PvcUsage` next to
  `ResourceQuotaItem`.
- `frontend/src/views/Storage/Pvc.tsx` (new) — namespaced layout from
  ResourceQuota.tsx + the second usage query.
- `frontend/src/views/Storage/PvcData.tsx` (new) — clone of
  ResourceQuotaData.tsx with the 4.1 PVC row set.
- `frontend/tests/views/pvcs.test.tsx` (new).
- `frontend/tests/views/pvc_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes + the two view imports.
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 19
  (`/storage/pvc`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set.
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — persistentvolumeclaims kind (service + `_KINDS` + API tests)

**SATISFIES:** `pvcs-list-200`, `pvcs-list-all-namespaces`,
`pvcs-sar-denied`, `pvcs-binding-404`, `pvc-kind-singular-rejected`,
`pvcs-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_pvcs.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_persistent_volume_claims(namespace: str | None)
  -> list[dict]` and `K8sClient.get_persistent_volume_claim(namespace: str,
  name: str) -> list[dict]` — the exact names `_KINDS`/`_GETTERS` reference
  via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the resourcequotas tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_pvcs.py`, mirroring the
  resourcequotas test pattern with `object.__new__` + `SimpleNamespace`:

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient


  def _client(v1: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._v1 = v1
      return client


  def test_list_pvc_namespaced() -> None:
      """[pvcs-list-200] the namespaced branch uses
      ``list_namespaced_persistent_volume_claim`` (the ``list_secrets``
      pattern)."""
      seen: list[str] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "data-pvc", "namespace": "team-a",
                           "creation_timestamp": "2026-01-02T03:04:05Z"},
              "spec": {"storage_class_name": "csi-fast", "volume_name": "pv-1",
                       "access_modes": ["ReadWriteOnce"], "volume_mode": "Filesystem"},
              "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}},
          }
      )
      v1 = SimpleNamespace(
          list_namespaced_persistent_volume_claim=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_persistent_volume_claims("team-a")
      assert result[0]["metadata"]["name"] == "data-pvc"
      assert result[0]["status"]["phase"] == "Bound"
      assert seen == ["team-a"]


  def test_list_pvc_all_namespaces_when_namespace_none() -> None:
      """[pvcs-list-all-namespaces] ``None`` uses the all-namespaces call
      (the ``list_secrets`` branch)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "data-pvc"}})
      v1 = SimpleNamespace(
          list_persistent_volume_claim_for_all_namespaces=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_persistent_volume_claims(None)
      assert result[0]["metadata"]["name"] == "data-pvc"
      assert seen == [True]


  def test_list_pvc_maps_500_to_unreachable() -> None:
      def list_all() -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_persistent_volume_claim=list_all))
          .list_persistent_volume_claims("team-a")


  def test_get_pvc_404_returns_empty_list() -> None:
      """[pvcs-get-by-name] a miss is ``[]`` (the ``get_resource_quota``
      contract)."""
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=404)

      assert _client(SimpleNamespace(read_namespaced_persistent_volume_claim=read))
          .get_persistent_volume_claim("team-a", "ghost") == []


  def test_get_pvc_hit_returns_one_item() -> None:
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "data-pvc"}})
      v1 = SimpleNamespace(read_namespaced_persistent_volume_claim=lambda name, ns: item)
      assert _client(v1).get_persistent_volume_claim("team-a", "data-pvc") == [
          {"metadata": {"name": "data-pvc"}}
      ]


  def test_get_pvc_other_api_error_maps_to_unreachable() -> None:
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_persistent_volume_claim=read))
          .get_persistent_volume_claim("team-a", "data-pvc")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_pvcs.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`:

  Next to `list_resource_quotas` (line ~736):
  ```python
  def list_persistent_volume_claims(self, namespace: str | None) -> list[dict[str, Any]]:
      """PersistentVolumeClaim list in the standard kubernetes dict form
      (``to_dict``) for one namespace, or across all namespaces when the
      namespace is ``None`` (the ``list_secrets`` branch). No field
      stripping — the view renders ``spec``/``status`` and the data page the
      full object. A transport ApiException maps to ``ClusterUnreachableError``
      (502)."""
      try:
          resp = (
              self._v1.list_namespaced_persistent_volume_claim(namespace)
              if namespace
              else self._v1.list_persistent_volume_claim_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_persistent_volume_claims", e)
          raise AssertionError("unreachable") from e
      return [pvc.to_dict() for pvc in resp.items]
  ```

  Next to `get_resource_quota` (line ~780):
  ```python
  def get_persistent_volume_claim(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One PVC as a 0/1-item list; ``[]`` on 404. Any other ApiException
      maps to ``ClusterUnreachableError`` (502), matching
      ``get_resource_quota``'s transport contract."""
      try:
          return [self._v1.read_namespaced_persistent_volume_claim(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_persistent_volume_claim", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # PVC (core, namespaced) — the 4.1-parity nav leaf resolved by the
  # pvc-views change (list + data views; ADR-0022 placement). The 4.1 route
  # name was "pvc"; the API kind is the plural.
  "persistentvolumeclaims": ("list_persistent_volume_claims", "persistentvolumeclaims", ""),
  ```
  in `_KINDS` (after the resourcequotas row; core group = `""`), and
  ```python
  "persistentvolumeclaims": "get_persistent_volume_claim",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the resourcequotas
  block):
  - FakeK8s gains:
    ```python
    def list_persistent_volume_claims(self, namespace: str | None) -> list[dict]:
        # Namespaced (core v1): None -> all-namespaces branch (mirrors the
        # real K8sClient.list_persistent_volume_claims).
        self.last_pvc_namespace = namespace
        return [
            {
                "metadata": {"name": "data-pvc", "namespace": "team-a",
                             "creation_timestamp": "2026-01-02T03:04:05Z",
                             "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"},
                             "labels": {"team": "a"}},
                "spec": {"storage_class_name": "csi-fast", "volume_name": "pv-1",
                         "access_modes": ["ReadWriteOnce"], "volume_mode": "Filesystem"},
                "status": {"phase": "Bound", "capacity": {"storage": "10Gi"}},
            }
        ]

    def get_persistent_volume_claim(self, namespace: str, name: str) -> list[dict]:
        if name == "data-pvc":
            return self.list_persistent_volume_claims(namespace)
        return []
    ```
  - Seven new tests mirroring the resourcequotas block, same docstring-tag
    style:
    - `test_list_pvcs_200` — `?namespace=team-a` → 200, `body["kind"] ==
      "persistentvolumeclaims"`, one item in `to_dict` form.
    - `test_list_pvcs_all_namespaces` — no `?namespace=` → 200; assert the
      FakeK8s received `None` (the all-namespaces branch).
    - `test_list_pvcs_get_by_name` — `?name=data-pvc&namespace=team-a` →
      1 item; `?name=ghost&namespace=team-a` → `items == []`.
    - `test_list_pvcs_sar_denied` — SAR denies; 403; assert
      `("list", "persistentvolumeclaims", "team-a", None, "")` in `asked`
      (the namespace forwarded, core group `""` — the load-bearing
      assertions).
    - `test_pvcs_binding_404` — cluster 999, unbound user → 404.
    - `test_pvc_kind_singular_rejected` — `/resources/persistentvolumeclaim`
      → 404 `RESOURCE_KIND_NOT_SUPPORTED`.
    - `test_pvc_kind_41_name_rejected` — 4.1's route name `/resources/pvc`
      → 404 `RESOURCE_KIND_NOT_SUPPORTED` (documents that the 4.1 name is
      NOT a valid kind identifier).

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_pvcs.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_pvcs.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): persistentvolumeclaims kind (core, namespaced, SAR-gated)"`

### Task 2: Backend — PVC-usage metrics route (kubelet stats, query-only)

**SATISFIES:** `pvc-usage-happy-path`, `pvc-usage-sar-denied`,
`pvc-usage-kubelet-degrade`, `pvc-usage-partial-nodes`, `pvc-usage-binding-404`

**Files:**
- Modify: `backend/app/services/k8s_client.py` (`pvc_usage`)
- Modify: `backend/app/api/metrics.py` (the `pvcs` route)
- Modify: `backend/app/schemas/metrics.py` (`PvcUsageOut`)
- Test: `backend/tests/services/test_k8s_client_pvcs.py` (extend — the
  `pvc_usage` cases)
- Test: `backend/tests/api/test_metrics_pvcs.py` (new)

**Interfaces:**
- Consumes: nothing from Task 1 (independent seam — the metrics route has its
  own SAR + its own client method).
- Produces: `K8sClient.pvc_usage(namespace: str) -> tuple[bool, list[dict]]`
  (available, items) and the route response
  `{ cluster, namespace, source, metrics_available, metrics_denied, items }`
  — the exact shape Task 3's list view joins by `items[].name`.
- Seam: the existing `pool` factory + the existing `rbac.can` gate (the
  `node_metrics` route is the precedent for both).
- Deletion test: delete `pvc_usage` → the route 500s at
  `getattr`/attribute access; delete the route → the Task 3 fetch 404s and
  the Usage column never resolves.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** — extend
  `backend/tests/services/test_k8s_client_pvcs.py`:

  ```python
  import json

  _STATS_A = json.dumps({
      "pods": [
          {"volume": [
              {"pvcRef": {"name": "data-pvc", "namespace": "team-a"},
               "capacityBytes": "1000", "usedBytes": "400", "availableBytes": "600"},
              {"pvcRef": {"name": "data-pvc", "namespace": "team-a"},
               "capacityBytes": "1000", "usedBytes": "100", "availableBytes": "900"},
          ]},
          {"volume": [
              {"pvcRef": {"name": "other-ns-pvc", "namespace": "kube-system"},
               "capacityBytes": "500", "usedBytes": "1", "availableBytes": "499"},
          ]},
      ]
  })


  def _stats_client(stats_by_node: dict[str, object]) -> K8sClient:
      def proxy(name, path=None, **kwargs):
          return stats_by_node[name]

      client = object.__new__(K8sClient)
      client._v1 = SimpleNamespace(
          list_node=lambda: SimpleNamespace(items=[
              SimpleNamespace(to_dict=lambda: {"metadata": {"name": n}})
              for n in stats_by_node
          ]),
          connect_get_node_proxy_with_path=proxy,
      )
      return client


  def test_pvc_usage_aggregates_per_pvc_in_namespace() -> None:
      """[pvc-usage-happy-path] entries are summed PER PVC per namespace;
      other namespaces are excluded; percentage = used/capacity*100."""
      available, items = _stats_client({"n1": _STATS_A}).pvc_usage("team-a")
      assert available is True
      assert items == [{
          "name": "data-pvc",
          "capacity_bytes": 2000,
          "used_bytes": 500,
          "available_bytes": 1500,
          "percentage_used": 25.0,
      }]


  def test_pvc_usage_zero_capacity_is_zero_percent() -> None:
      """4.1's ``usedBytes / capacityBytes`` would divide by zero; 5.0
      reports 0.0 (guard)."""
      stats = json.dumps({"pods": [{"volume": [
          {"pvcRef": {"name": "empty-pvc", "namespace": "team-a"},
           "capacityBytes": "0", "usedBytes": "0", "availableBytes": "0"}]}]})
      available, items = _stats_client({"n1": stats}).pvc_usage("team-a")
      assert available is True
      assert items[0]["percentage_used"] == 0.0


  def test_pvc_usage_skips_unhealthy_nodes() -> None:
      """[pvc-usage-partial-nodes] a node whose stats call raises is
      skipped; the healthy subset is returned, ``available`` stays True."""
      def raise_500(name, path=None, **kwargs):
          raise ApiException(status=500)

      client = object.__new__(K8sClient)
      client._v1 = SimpleNamespace(
          list_node=lambda: SimpleNamespace(items=[
              SimpleNamespace(to_dict=lambda: {"metadata": {"name": "n1"}}),
              SimpleNamespace(to_dict=lambda: {"metadata": {"name": "bad"}}),
          ]),
          connect_get_node_proxy_with_path=lambda name, path=None, **kw: (
              _STATS_A if name == "n1" else raise_500(name, path)
          ),
      )
      available, items = client.pvc_usage("team-a")
      assert available is True
      assert items[0]["name"] == "data-pvc"


  def test_pvc_usage_all_nodes_unhealthy_is_empty() -> None:
      """[pvc-usage-kubelet-degrade] zero healthy nodes → ``(False, [])`` —
      the ADR-0003 query-only degrade, never an exception."""
      def raise_404(name, path=None, **kwargs):
          raise ApiException(status=404)

      client = object.__new__(K8sClient)
      client._v1 = SimpleNamespace(
          list_node=lambda: SimpleNamespace(items=[
              SimpleNamespace(to_dict=lambda: {"metadata": {"name": "bad"}})]),
          connect_get_node_proxy_with_path=raise_404,
      )
      available, items = client.pvc_usage("team-a")
      assert available is False
      assert items == []
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_pvcs.py -q`.
  Expected: FAIL (no `pvc_usage`).

- [ ] **Step 3: Implement the service method** — `k8s_client.py`, next to
  the `node_metrics` family (line ~369):
  ```python
  def pvc_usage(self, namespace: str) -> tuple[bool, list[dict[str, Any]]]:
      """PVC storage usage per namespace from the KUBELET /stats/summary
      endpoint (4.1's ``k8sPVCMetric`` read, re-implemented): for every node,
      ``connect_get_node_proxy_with_path(name, path="stats/summary")``, then
      aggregate each pod's ``volume[].pvcRef`` entries for ``namespace``.

      Returns ``(available, items)`` — ``items`` is one entry per PVC:
      ``{name, capacity_bytes, used_bytes, available_bytes,
      percentage_used}`` (bytes summed across all pods using the PVC;
      ``percentage_used`` = used / capacity * 100, ``0.0`` when capacity is
      zero — the 4.1 division-by-zero guard). The ADR-0003 query-only
      degrade: a node whose stats call fails (404/5xx/timeout — no kubelet,
      stats unavailable) is SKIPPED, never raised; zero healthy nodes →
      ``(False, [])``. The body is parsed with ``json.loads`` (4.1's
      ``eval`` is not replicated).
      """
      nodes = [n.to_dict() for n in self._v1.list_node().items]
      aggregated: dict[str, dict[str, int]] = {}
      healthy = 0
      for node in nodes:
          name = node["metadata"]["name"]
          try:
              raw = self._v1.connect_get_node_proxy_with_path(
                  name, path="stats/summary", _request_timeout=2
              )
              body = json.loads(raw)
          except (ApiException, ValueError):
              # A per-node stats failure is the EXPECTED state (kubelet
              # absent/down/stats API off) — skip, never raise (ADR-0003).
              continue
          healthy += 1
          for pod in body.get("pods") or []:
              for vol in pod.get("volume") or []:
                  ref = vol.get("pvcRef")
                  if not ref or ref.get("namespace") != namespace:
                      continue
                  entry = aggregated.setdefault(ref["name"], {
                      "capacity_bytes": 0, "used_bytes": 0, "available_bytes": 0,
                  })
                  entry["capacity_bytes"] += int(vol.get("capacityBytes") or 0)
                  entry["used_bytes"] += int(vol.get("usedBytes") or 0)
                  entry["available_bytes"] += int(vol.get("availableBytes") or 0)
      items = [
          {
              **entry,
              "percentage_used": (
                  round(entry["used_bytes"] / entry["capacity_bytes"] * 100, 1)
                  if entry["capacity_bytes"] else 0.0
              ),
              "name": name,
          }
          for name, entry in aggregated.items()
      ]
      return healthy > 0, items
  ```
  (``import json`` at the top of the module if not already present —
  verify; ``list_node`` is already a method, its result here is the raw
  kubernetes model, hence the explicit ``to_dict``.)

- [ ] **Step 4: Add the schema** — `backend/app/schemas/metrics.py`:
  ```python
  class PvcUsageItem(Schema):
      name: str
      capacity_bytes: int
      used_bytes: int
      available_bytes: int
      percentage_used: float

  class PvcUsageOut(Schema):
      cluster: str
      namespace: str
      source: str  # EXACTLY "kubelet stats/summary"
      metrics_available: bool
      metrics_denied: bool
      items: list[PvcUsageItem]
  ```

- [ ] **Step 5: Add the route** — `backend/app/api/metrics.py`, after
  `node_metrics`:
  ```python
  @blp.route("/clusters/<int:cluster_id>/metrics/pvcs", methods=["GET"])
  @blp.response(200, PvcUsageOut)
  @blp.doc(
      responses={
          404: "CLUSTER_NOT_FOUND (binding gate)",
          502: "CLUSTER_UNREACHABLE",
      }
  )
  def pvc_usage(self, cluster_id: int) -> dict[str, object]:
      """PVC storage usage (the /storage/pvc list's Usage column).

      KUBELET stats/summary, NOT metrics.k8s.io (4.1's ``k8sPVCMetric``
      read the kubelet per node). The ADR-0004 gate is ``get`` on ``nodes``
      (the stats proxy goes through the node API): denied -> 200 with
      ``metrics_denied: true`` and empty ``items`` (the two-tier pattern —
      the observed tier degrades to unknown, never 403, so the declared PVC
      list still renders). The ADR-0003 degrade lives in
      ``K8sClient.pvc_usage``: unavailable kubelet stats are 200
      ``metrics_available: false`` + empty items, never 500. ``namespace``
      is required (4.1 had no all-namespace branch for this read): absent
      -> 200 with ``metrics_available: false`` + empty items.
      """
      cluster = _cluster_for(g.current_user, cluster_id)
      namespace = request.args.get("namespace")
      if not namespace:
          return {
              "cluster": cluster.name, "namespace": "",
              "source": "kubelet stats/summary",
              "metrics_available": False, "metrics_denied": False,
              "items": [],
          }
      metrics_allowed = rbac.can(
          g.current_user, cluster, "get", "nodes", None, None, ""
      )
      if not metrics_allowed:
          return {
              "cluster": cluster.name, "namespace": namespace,
              "source": "kubelet stats/summary",
              "metrics_available": False, "metrics_denied": True,
              "items": [],
          }
      available, items = pool.get(cluster).pvc_usage(namespace)
      return {
          "cluster": cluster.name, "namespace": namespace,
          "source": "kubelet stats/summary",
          "metrics_available": available, "metrics_denied": False,
          "items": items,
      }
  ```
  (``from flask import request`` — verify the import; the module already
  imports ``g``.)

- [ ] **Step 6: Write the route tests** —
  `backend/tests/api/test_metrics_pvcs.py` (mirror the `test_metrics_
  summary.py` fixture pattern — the app + FakeK8s pool seam):
  - `test_pvc_usage_happy_path` — bound user, SAR allows `get nodes`,
    FakeK8s `pvc_usage` returns `True` + one item → 200,
    `source == "kubelet stats/summary"`, `metrics_available: true`,
    `metrics_denied: false`, one item with the exact fields.
  - `test_pvc_usage_sar_denied` — SAR denies `get nodes` → 200
    `metrics_denied: true`, `metrics_available: false`, `items == []`;
    assert `("get", "nodes", None, None, "")` in `asked` and
    `pvc_usage` was NEVER called.
  - `test_pvc_usage_kubelet_degrade` — FakeK8s returns `(False, [])` → 200
    `metrics_available: false`, `items == []` (NOT 500).
  - `test_pvc_usage_binding_404` — cluster 999, unbound user → 404.
  - `test_pvc_usage_missing_namespace_param` — no `?namespace=` → 200
    `metrics_available: false`, `items == []`; `pvc_usage` never called.

- [ ] **Step 7: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_pvcs.py tests/api/test_metrics_pvcs.py -q`

- [ ] **Step 8: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/metrics.py backend/app/schemas/metrics.py backend/tests/services/test_k8s_client_pvcs.py backend/tests/api/test_metrics_pvcs.py`
  `git commit -m "feat(metrics): pvc usage route (kubelet stats, query-only degrade)"`

### Task 3: Frontend — list view + usage join + test

**SATISFIES:** `pvc-list-renders-rows-with-data-links`,
`pvc-list-usage-join`, `pvc-list-usage-degrades-to-em-dash`,
`pvc-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Storage/Pvc.tsx`
- Test: `frontend/tests/views/pvcs.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's list API (the `persistentvolumeclaims` URL) and Task
  2's metrics API (the `metrics/pvcs` URL) — joined by PVC name.
- Produces: the data-page link `/storage/pvc/data?name=<name>&namespace=<ns>`
  — the SOLE producer of those query strings.
- Seam: `apiFetch` + TanStack Query (two queries) +
  `useClusterStore.selectedCluster` + `useClusterStore.selectedNamespace`.
- Deletion test: deleting the view → the route (Task 5) 404s / the test
  file fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the types** — `frontend/src/lib/types.ts`, next to
  `ResourceQuotaItem`:

  ```ts
  /** A PVC item as returned by /api/v1/clusters/<id>/resources/persistentvolumeclaims (kubernetes to_dict, snake_case; namespaced, core v1). */
  export interface PvcItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      storage_class_name?: string
      volume_name?: string
      access_modes?: string[]
      volume_mode?: string
    }
    status?: {
      phase?: string
      capacity?: { storage?: string }
    }
    [key: string]: unknown
  }

  /** One PVC-usage entry from /api/v1/clusters/<id>/metrics/pvcs (kubelet stats/summary). */
  export interface PvcUsage {
    name: string
    capacity_bytes: number
    used_bytes: number
    available_bytes: number
    percentage_used: number
  }

  export interface PvcUsageResponse {
    cluster: string
    namespace: string
    source: string
    metrics_available: boolean
    metrics_denied: boolean
    items: PvcUsage[]
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/pvcs.test.tsx`: clone
  `resource_quotas.test.tsx` (the namespaced pattern) and:
  - fixture `boundPvc` (the to_dict shape from Task 1's FakeK8s) +
    `unboundPvc` (`status: { phase: 'Pending' }`, no `spec.volume_name`,
    no `status.capacity`).
  - MSW handlers: `*/api/v1/clusters/1/resources/persistentvolumeclaims?namespace=team-a`
    → `{ kind: 'persistentvolumeclaims', items: [boundPvc, unboundPvc] }`;
    `*/api/v1/clusters/1/metrics/pvcs?namespace=team-a` →
    `{ cluster: 'c1', namespace: 'team-a', source: 'kubelet stats/summary',
    metrics_available: true, metrics_denied: false, items: [{ name:
    'data-pvc', capacity_bytes: 10737418240, used_bytes: 4529848320,
    available_bytes: 6207569920, percentage_used: 42.3 }] }`.
  - `list-renders-pvc-rows-with-data-links`: links `data-pvc` →
    `/storage/pvc/data?name=data-pvc&namespace=team-a`; the list fetch URL
    has `namespace=team-a`; heading EXACTLY `Persistent Volume Claim List`;
    breadcrumb `Storage`; column headers
    `['Status', 'Name', 'StorageClass', 'Volume', 'Capacity', 'Usage']`.
  - `list-status-phase-badges`: `Bound` → success badge, `Pending` →
    warning badge.
  - `list-usage-join`: `data-pvc` Usage cell = `42.3 %`; `other-pvc` (absent
    from the metrics items) Usage cell = `—`.
  - `list-usage-degrades-to-em-dash` (3 cases in one test via
    `describe.each` or 3 asserts): (a) usage response `metrics_available:
    false` → all Usage `—`; (b) usage fetch rejects (500) → all Usage `—`
    AND the list still renders its rows; (c) `metrics_denied: true` → all
    Usage `—`.
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No persistent volume claims found`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/pvcs.test.tsx`
  Expected: FAIL (cannot find module `src/views/Storage/Pvc`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/Storage/Pvc.tsx`: namespaced layout from
  `ResourceQuota.tsx` + the second usage query:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement
    (Storage), the `?name=&namespace=` delta, the Usage column as a second
    fetch (the ADR-0003 two-tier rule client-side: the usage query's error
    degrades the column to `—`, never the list), the Status badge tiers.
  - `const cluster = useClusterStore((s) => s.selectedCluster)`;
    `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`.
  - `type PvcRow = { name, phase, storageClass, volume, capacity, usage }`:
    ```ts
    // 4.1's three-tier Status badge: Bound -> success, Terminating ->
    // danger, everything else -> warning; "—" when absent (certainty rule).
    const phaseBadge = (phase?: string): { cls: string; text: string } => {
      if (phase === 'Bound') return { cls: 'badge-success', text: phase }
      if (phase === 'Terminating') return { cls: 'badge-danger', text: phase }
      return phase ? { cls: 'badge-warning', text: phase } : { cls: '', text: '—' }
    }
    const toRow = (item: PvcItem, usage: PvcUsage | undefined): PvcRow => ({
      name: item.metadata?.name ?? '',
      phase: item.status?.phase ?? '',
      storageClass: item.spec?.storage_class_name ?? '—',
      volume: item.spec?.volume_name ?? '—',
      capacity: item.status?.capacity?.storage ?? '—',
      usage: usage ? `${usage.percentage_used} %` : '—',
    })
    ```
  - list query: key `['pvcs', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/persistentvolumeclaims?namespace=${encodeURIComponent(namespace)}`.
  - usage query: key `['pvc-usage', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/metrics/pvcs?namespace=${encodeURIComponent(namespace)}`;
    **its `isError`/`isLoading` NEVER surface as a list error** — build the
    join map from `usageData?.items` only when
    `usageData?.metrics_available && !usageData.metrics_denied`:
    ```ts
    // The observed tier degrades to unknown, never to a row error
    // (ADR-0003 two-tier, client-side): a failed/absent usage response
    // means every Usage cell renders "—".
    const usageByPvc = useMemo(() => {
      const map = new Map<string, PvcUsage>()
      if (usageData?.metrics_available && !usageData.metrics_denied) {
        for (const u of usageData.items) map.set(u.name, u)
      }
      return map
    }, [usageData])
    ```
  - name link →
    `/storage/pvc/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Storage → Persistent Volume Claim List; card title EXACTLY
    `Persistent Volume Claim List`.
  - columns: Status (badge) / Name (link) / StorageClass / Volume /
    Capacity / Usage.
  - pinned states: `No cluster selected.`, `Loading persistent volume
    claims...`, `Error loading persistent volume claims: {message}`,
    `No persistent volume claims found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/pvcs.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Storage/Pvc.tsx frontend/tests/views/pvcs.test.tsx`
  `git commit -m "feat(frontend): pvc list view (4.1 port + usage column)"`

### Task 4: Frontend — data view + test

**SATISFIES:** `pvc-data-renders-detail`, `pvc-data-not-found-state`,
`pvc-data-missing-name`

**Files:**
- Create: `frontend/src/views/Storage/PvcData.tsx`
- Test: `frontend/tests/views/pvc_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item list; `[]` =
  miss) and Task 3's link (the sole producer of the query strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 5) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/pvc_data.test.tsx`: clone
  `resource_quota_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/persistentvolumeclaims?name=data-pvc&namespace=team-a`
    returning `{ kind: 'persistentvolumeclaims', items: [boundPvc] }`; a
    miss handler (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/storage/pvc/data?name=data-pvc&namespace=team-a` — assert EXACTLY ONE
    fetch and that its URL has BOTH `name=data-pvc` and
    `namespace=team-a`; CTable rows: Name `data-pvc`, Namespace `team-a`,
    Status `Bound` (badge), Access Mode `ReadWriteOnce`, Volume Mode
    `Filesystem`, Capacity `10Gi`, StorageClass `csi-fast`, Persistent
    Volume `pv-1`, a Created row (via `formatTimestamp`), a Labels
    sub-table `team: a`, an Annotations sub-table with the
    last-applied-configuration key (rendered verbatim — no trimAnnotations);
    the full-object block contains `"storage_class_name": "csi-fast"` (the
    JSON block).
  - `data-missing-optional-fields`: a PVC with no `spec.volume_name`, no
    `status.capacity`, no `status.phase` → those rows `—`.
  - `data-not-found-state`: `?name=ghost&namespace=team-a` → `No PVC
    'ghost' found`; assert NO `.text-danger` node for it (a state, not an
    error).
  - `data-missing-name`: `/storage/pvc/data?namespace=team-a` (no name) →
    `Error: pvc name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]`.

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/pvc_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/Storage/PvcData.tsx`: clone of
  `ResourceQuotaData.tsx` with the 4.1 PVC row set:
  - docstring: single `?name=&namespace=` fetch (no 4.1 list-then-filter),
    NOT_FOUND as a pinned STATE, the `json` hljs grammar as the truthful
    classifier (ratified 2026-10-28), the 4.1 deviations (the "Lables" typo
    NOT replicated, no trimAnnotations).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read the params: `const name = params.get('name') ?? ''`;
    `const namespace = params.get('namespace') ??
    useClusterStore.getState().selectedNamespace ?? 'default'` (the page
    only renders with a cluster selected, so the store fallback is always
    available — the brief's R5 missing-namespace rule).
  - query key `['pvc-data', cluster?.id, name, namespace]`; enabled when
    `cluster != null && name !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/persistentvolumeclaims?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Storage → Persistent Volume Claim List (link) → `{name}`.
  - card title `Persistent Volume Claim Data`.
  - CTable rows (the 4.1 data page's row set, 4.1's "Lables" typo fixed):
    Status (`item.status?.phase` badge, same tiers as the list; `—` when
    absent) / Name / Namespace (`namespace`) / Created
    (`formatTimestamp(item.metadata?.creation_timestamp)`) / Access Mode
    (`(item.spec?.access_modes ?? []).join(', ') || '—'`) / Volume Mode
    (`item.spec?.volume_mode ?? '—'`) / Capacity
    (`item.status?.capacity?.storage ?? '—'`) / StorageClass
    (`item.spec?.storage_class_name ?? '—'`) / Persistent Volume
    (`item.spec?.volume_name ?? '—'`) / Labels / Annotations (sub-tables,
    `No labels` / `No annotations` when empty — the resourcequota twin's
    shape).
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No PVC '{name}' found`, `Error: pvc name not provided`,
    `Loading pvc data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/pvc_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/Storage/PvcData.tsx frontend/tests/views/pvc_data.test.tsx`
  `git commit -m "feat(frontend): pvc data view (4.1 tables + JSON block)"`

### Task 5: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `pvc-stub-removed-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 3–4's view components.
- Produces: the resolved nav leaf (the goal).
- Seam: react-router `Route` + the `stubRoutes` array.
- Deletion test: delete the two `Route`s → both paths fall through to the
  stub list (or 404 once the stub entry is gone) — the nav leaf is dead
  again, the exact pre-change state.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the two view imports
  (next to the resourcequota imports) and, after the resourcequota pair,
  mirror the block:
  ```tsx
  <Route
    path="/storage/pvc"
    element={
      <ProtectedRoute>
        <PvcView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/storage/pvc/data"
    element={
      <ProtectedRoute>
        <PvcDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 19
  (`{ path: '/storage/pvc', title: 'VolumeClaims', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/storage/pvc'` to the `viewPaths` set in `expectedStubs()` (the test
  derives expected stubs from the nav minus `viewPaths`; without the
  addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Tasks 3–4 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON
    block uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire pvc routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_pvcs.py tests/api/test_resources.py tests/api/test_metrics_pvcs.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/pvcs.test.tsx tests/views/pvc_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` absent; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend kind) ─────────────► Task 3 (list view) ──► Task 5 (routing)
Task 2 (usage route) ───────────────► Task 3 (list view)     ▲
Task 1 (backend kind) ──► Task 4 (data view) ────────────────┘
```

Tasks 2 and 4 are independent of Task 3 (Task 4 only needs Task 1's
`?name=&namespace=` contract; Task 2 only needs the pool seam). Task 3
needs BOTH Task 1 and Task 2 (the list view's two queries). Task 5 last (it
removes the stub, so the views must exist first).

## Rollback

Each task is one conventional commit and independently revertable (no
schema, no dependency, no public contract change). Reverting Task 5 is
self-contained (route + stub removal + test in one commit). Reverting Task
2 alone leaves the list view's Usage column permanently `—` (its query
404s and the client-side degrade swallows it) — a valid degraded state,
not a broken one.
