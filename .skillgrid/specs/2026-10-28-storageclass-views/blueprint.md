# StorageClass Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already ratified
for cluster-scoped core kinds: nodes/priorityclasses/runtimeclasses; the 4.1
template pair is the source of truth for the page shape).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny) before any
frontend exists; Task 2 is the list view; Task 3 the data view; Task 4 the
routing cleanup. Each task is independently revertable.

**Goal:** Resolve the nav leaf `/storage/storage-class` to a real, SAR-gated,
read-only list + data pair — the 4.1 StorageClass pages ported with the
ratified 5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_storage_classes` / `get_storage_class` (kubernetes
`StorageV1Api`, storage.k8s.io group, **cluster-scoped**) + two dict rows (`_KINDS` /
`_GETTERS`) + one new `self._storage` attribute in `__init__`. Frontend: two
views (list cloned from PriorityClass.tsx for the cluster-scoped layout, data
cloned from PriorityClassData.tsx for the CTable+JSON block),
`StorageClassItem` type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `StorageV1Api` (already a dependency, the 4.1 code
used it; one new attribute `self._storage` in 5.0's `K8sClient.__init__`),
Flask + Smorest (existing route), React + CoreUI + TanStack Query + MSW
(existing), no new npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/storage/storage-class.html.j2`
(list: Name/Default/Reclaim Policy/Volume Binding Mode — Default is the
`storageclass.kubernetes.io/is-default-class` annotation value),
`4.1:src/kubedash/templates/storage/storage-class-data.html.j2` (data: Name/
Created/Annotations/Labels/Reclaim Policy/Binding Mode/Provisioner/Parameters
— the data page's "Binding Mode" label is the shorter form of the list's
"Volume Binding Mode" header; the Parameters card is dynamic-key, one row per
`parameters` entry), `4.1:src/kubedash/lib/k8s/storage.py:15`
(`k8sStorageClassListGet`: `StorageV1Api().list_storage_class`, generates
`name`/`created`/`annotations`/`labels`/`provisioner`/`reclaim_policy`/
`volume_binding_mode` + conditional `parameters`),
`4.1:src/kubedash/blueprint/storage.py:28` (the list + data routes, the data
page is list-then-filter by name). In-repo precedents —
`backend/app/services/k8s_client.py:261-276` (the `list_nodes` /
`list_priority_classes` cluster-scoped core-kind pattern to mirror;
`self._scheduling` at line ~226 is the attribute pattern),
`backend/app/services/k8s_client.py:819-830` (the `get_priority_class`
cluster-scoped getter to mirror),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch (line
~104-114, the `namespace = namespace or "default"` fallback — irrelevant for
a cluster-scoped read),
`backend/tests/api/test_resources.py:1272-1334` (the priorityclasses API tests
to mirror: 200, ignores namespace, get-by-name, SAR deny, binding 404,
singular kind rejected),
`frontend/src/views/OtherResource/PriorityClass.tsx` (the cluster-scoped list
view: no namespace selector, breadcrumb + KubeDataTable),
`frontend/src/views/OtherResource/PriorityClassData.tsx` (the data view:
CTable + labels/annotations sub-tables + JSON block; the
`NOT_FOUND`-as-throw-not-found-state pattern),
`frontend/tests/views/priority_classes.test.tsx` +
`priority_class_data.test.tsx` (the cluster-scoped test patterns to clone).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0010, ADR-0020, ADR-0021,
ADR-0022. None created.

## Terms

None (the spec's vocabulary; "StorageClass" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/storageclasses` → 200, `kind: "storageclasses"`, items in
  `to_dict` snake_case form, SAR-gated on `list storageclasses` (core,
  namespace `None`), 403 names the resource and the client call is never made
  on deny (`storageclasses-list-200`, `storageclasses-sar-denied`).
- A `namespace` param is accepted and ignored (cluster-scoped) — the client
  uses `list_storage_class` (`storageclasses-list-ignores-namespace`).
- `?name=` returns a 0/1-item list through the SAME route — hit = the object,
  miss = `[]` (`storageclasses-get-by-name`).
- The singular `storageclass` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`storageclass-kind-singular-rejected`).
- The list view fetches `/api/v1/clusters/<id>/resources/storageclasses` (NO
  namespace param — cluster-scoped); card title EXACTLY `Storage Classes
  List`; columns Name/Default/Reclaim Policy/Volume Binding Mode; every name
  links to `/storage/storage-class/data?name=<name>` (NO namespace)
  (`storage-class-list-renders-rows-with-data-links`).
- Default cell = the `storageclass.kubernetes.io/is-default-class` annotation
  value (`—` when absent), Reclaim Policy cell = `reclaim_policy` (`—` when
  absent), Volume Binding Mode cell = `volume_binding_mode` (`—` when absent)
  (`storage-class-list-default-policy-binding-cells`,
  `storage-class-list-missing-fields`).
- The data view fetches ONCE with `?name=`, renders the CTable
  (Name/Created/Reclaim Policy/Volume Binding Mode/Provisioner/Labels/
  Annotations) + the Parameters table (key/value, `No parameters` when absent)
  + a JSON-highlighted full-object block, and treats a miss as the pinned
  state `No StorageClass '<name>' found` — never an error style
  (`storage-class-data-renders-detail`,
  `storage-class-data-missing-parameters`,
  `storage-class-data-not-found-state`).
- `/storage/storage-class` is gone from `views/Stub/routes.ts`; both real
  views are routed; the nav leaf is byte-identical
  (`storage-class-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `self._storage` attribute + the two
  methods (modified).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_storageclasses.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `StorageClassItem` (modified).
- `frontend/src/views/Storage/StorageClass.tsx` (new).
- `frontend/src/views/Storage/StorageClassData.tsx` (new).
- `frontend/tests/views/storage_classes.test.tsx` (new).
- `frontend/tests/views/storage_class_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- The kind is **cluster-scoped**: `list_storage_classes` uses
  `list_storage_class` (no namespace), and `get_storage_class` uses
  `read_storage_class` (the `_GETTERS` convention passes `(namespace, name)`;
  the namespace is accepted and ignored — the `list_nodes` /
  `get_priority_class` cluster-scoped pattern). The `?name=` branch's
  `namespace = "default"` fallback never affects the read.
- The list view's name-link href is the SOLE producer of the data page's
  `?name=` query strings (cluster-scoped: NO `namespace`) — the data page
  parses the param, never constructs one (the priorityclass contract; keep
  it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an API
  error (the `NOT_FOUND`-throw pattern from PriorityClassData).
- The `to_dict` form is snake_case (a generated core-API model) — the type and
  cell readers use snake_case keys (`reclaim_policy`, `volume_binding_mode`,
  `provisioner`, `storageclass.kubernetes.io/is-default-class`).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `StorageV1Api` is already vendored in the
  kubernetes client (the 4.1 code imported it); one new `self._storage`
  attribute in `K8sClient.__init__` (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Cluster-scoped kind (storage.k8s.io group, v1): the list URL and the data
  URL carry NO `namespace=` param; SAR group = `"storage.k8s.io"`,
  namespace = `None` (2026-11-05 review fix: the original `""` core group
  never matches a storage.k8s.io grant); the client
  methods use `list_storage_class` / `read_storage_class` (the
  `list_nodes` / `get_priority_class` cluster-scoped pattern).
- The `to_dict` form is snake_case (a generated core-API model) — the type and
  cell readers use snake_case keys.
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Storage Classes List` (4.1's title, verbatim — the
  e2e-smoke contract).
- Pinned copy (do not reword): `No storage classes found`,
  `No StorageClass '<name>' found`, `Error: storage class name not provided`,
  `No cluster selected.`, `Loading storage classes...`, `No labels`,
  `No annotations`, `No parameters`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `self._storage =
  k8s_client.StorageV1Api(api_client)` next to `self._scheduling`
  (line ~226); `list_storage_classes` next to `list_priority_classes`
  (line ~267), `get_storage_class` next to `get_priority_class` (line ~819).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["storageclasses"]` + `_GETTERS["storageclasses"]`.
- `backend/tests/services/test_k8s_client_storageclasses.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_storage_classes` / `get_storage_class`; 6 new tests.
- `frontend/src/lib/types.ts` (modify) — `StorageClassItem` next to
  `PriorityClassItem`.
- `frontend/src/views/Storage/StorageClass.tsx` (new) — cluster-scoped layout
  from PriorityClass.tsx (no namespace selector).
- `frontend/src/views/Storage/StorageClassData.tsx` (new) — clone of
  PriorityClassData.tsx + the 4.1 Provisioner + Parameters table.
- `frontend/tests/views/storage_classes.test.tsx` (new).
- `frontend/tests/views/storage_class_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (line ~381) + the two view imports (after line 48).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 21
  (`/storage/storage-class`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — storageclasses kind (service + `_KINDS` + API tests)

**SATISFIES:** `storageclasses-list-200`,
`storageclasses-list-ignores-namespace`, `storageclasses-sar-denied`,
`storageclasses-binding-404`, `storageclass-kind-singular-rejected`,
`storageclasses-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_storageclasses.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_storage_classes(_namespace: str | None) ->
  list[dict]` and `K8sClient.get_storage_class(_namespace: str, name: str) ->
  list[dict]` — the exact names `_KINDS`/`_GETTERS` reference via `getattr`
  (the `_GETTERS` call convention passes `(namespace, name)`; the namespace is
  accepted and ignored for this cluster-scoped kind).
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the priorityclasses tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_storageclasses.py`, mirroring the
  priorityclasses test pattern with `object.__new__` + `SimpleNamespace`:

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient


  def _client(storage: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._storage = storage
      return client


  def test_list_storage_classes_ignores_namespace() -> None:
      """[storageclasses-list-ignores-namespace] cluster-scoped: the
      namespace is accepted-and-ignored, the cluster-scoped call is used (the
      ``list_nodes`` pattern)."""
      seen: list[object] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "csi-fast", "creation_timestamp": "2026-01-02T03:04:05Z"},
              "provisioner": "csi.example.com",
              "reclaim_policy": "Delete",
              "volume_binding_mode": "WaitForFirstConsumer",
          }
      )
      storage = SimpleNamespace(
          list_storage_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1]
      )
      result = _client(storage).list_storage_classes("team-a")  # ns ignored
      assert result[0]["metadata"]["name"] == "csi-fast"
      assert result[0]["reclaim_policy"] == "Delete"
      assert seen == [True]  # the cluster-scoped call, no namespace forwarded


  def test_list_storage_classes_maps_500_to_unreachable() -> None:
      def list_all() -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_storage_class=list_all)).list_storage_classes(None)


  def test_get_storage_class_404_returns_empty_list() -> None:
      """[storageclasses-get-by-name] a miss is ``[]``, mirroring
      ``get_priority_class``'s 0/1-item contract."""
      def read(name: str) -> None:
          raise ApiException(status=404)

      storage = SimpleNamespace(read_storage_class=read)
      assert _client(storage).get_storage_class(None, "ghost") == []


  def test_get_storage_class_hit_returns_one_item() -> None:
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "csi-fast"}})
      storage = SimpleNamespace(read_storage_class=lambda name: item)
      assert _client(storage).get_storage_class(None, "csi-fast") == [
          {"metadata": {"name": "csi-fast"}}
      ]


  def test_get_storage_class_ignores_namespace() -> None:
      """cluster-scoped: the namespace is accepted and ignored (the
      ``get_priority_class`` pattern)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "csi-fast"}})
      storage = SimpleNamespace(read_storage_class=lambda name: (seen.append(name), item)[1])
      _client(storage).get_storage_class("team-a", "csi-fast")  # ns ignored
      assert seen == ["csi-fast"]


  def test_get_storage_class_other_api_error_maps_to_unreachable() -> None:
      def read(name: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_storage_class=read)).get_storage_class(None, "csi-fast")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_storageclasses.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`:

  `__init__`, next to `self._scheduling` (line ~226):
  ```python
  # StorageClass (storage/v1, cluster-scoped) — the R4 "storageclasses" kind
  # (4.1-parity nav leaf; ADR-0022 placement).
  self._storage = k8s_client.StorageV1Api(api_client)
  ```

  Next to `list_priority_classes` (line ~267):
  ```python
  def list_storage_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
      """StorageClass list in the standard kubernetes dict form (``to_dict``).
      Cluster-scoped: the namespace argument is accepted and ignored (the
      ``list_nodes`` pattern). No field stripping — the view renders
      ``reclaim_policy``/``volume_binding_mode``/``provisioner`` and the data
      page the full object. A transport ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          resp = self._storage.list_storage_class()
      except ApiException as e:
          self._unreachable("list_storage_classes", e)
          raise AssertionError("unreachable") from e
      return [sc.to_dict() for sc in resp.items]
  ```

  Next to `get_priority_class` (line ~819):
  ```python
  def get_storage_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
      """One StorageClass as a 0/1-item list; ``[]`` on 404. Cluster-scoped:
      the namespace argument is accepted and ignored. Any other ApiException
      maps to ``ClusterUnreachableError`` (502), matching
      ``get_priority_class``'s transport contract."""
      try:
          return [self._storage.read_storage_class(name).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_storage_class", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "storageclasses": ("list_storage_classes", "storageclasses", "storage.k8s.io"),
  ```
  in `_KINDS` (after the priorityclasses row; group = `"storage.k8s.io"` —
  the 2026-11-05 review fix; the original `""` core group was wrong), and
  ```python
  "storageclasses": "get_storage_class",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the priorityclasses block,
  lines 1272–1334):
  - FakeK8s gains:
    ```python
    def list_storage_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped (storage/v1): the namespace is accepted-and-ignored
        # (mirrors the real K8sClient.list_storage_classes).
        return [
            {
                "metadata": {
                    "name": "csi-fast",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "annotations": {"storageclass.kubernetes.io/is-default-class": "true"},
                    "labels": {"team": "a"},
                },
                "provisioner": "csi.example.com",
                "reclaim_policy": "Delete",
                "volume_binding_mode": "WaitForFirstConsumer",
                "parameters": {"type": "standard"},
            }
        ]

    def get_storage_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "csi-fast":
            return self.list_storage_classes(None)
        return []
    ```
  - Six new tests mirroring the priorityclasses block, same docstring-tag
    style:
    - `test_list_storageclasses_200` — 200, `body["kind"] ==
      "storageclasses"`, one item in `to_dict` form.
    - `test_list_storageclasses_ignores_namespace` — `?namespace=team-a` →
      200; assert the FakeK8s received `None` (the cluster-scoped branch).
    - `test_list_storageclasses_get_by_name` — `?name=csi-fast` → 1 item;
      `?name=ghost` → `items == []`.
    - `test_list_storageclasses_sar_denied` — SAR denies; 403; assert
      `("list", "storageclasses", None, None, "storage.k8s.io")` in `asked`
      (namespace `None`, group `storage.k8s.io` — the load-bearing
      assertions; 2026-11-05 review fix).
    - `test_storageclasses_binding_404` — cluster 999, unbound user → 404.
    - `test_storageclass_kind_singular_rejected` —
      `/resources/storageclass` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_storageclasses.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_storageclasses.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): storageclasses kind (storage, cluster-scoped, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `storage-class-list-renders-rows-with-data-links`,
`storage-class-list-default-policy-binding-cells`,
`storage-class-list-missing-fields`, `storage-class-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Storage/StorageClass.tsx`
- Test: `frontend/tests/views/storage_classes.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `storageclasses` list URL, cluster-scoped).
- Produces: the data-page link `/storage/storage-class/data?name=<name>` — the
  SOLE producer of those query strings (cluster-scoped: NO `namespace`).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` (no
  namespace seam — cluster-scoped).
- Deletion test: deleting the view → the route (Task 4) 404s / the test file
  fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `PriorityClassItem`:

  ```ts
  /** A StorageClass item as returned by /api/v1/clusters/<id>/resources/storageclasses (kubernetes to_dict, snake_case; cluster-scoped, storage/v1). */
  export interface StorageClassItem {
    metadata?: {
      name?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    provisioner?: string
    reclaim_policy?: string
    volume_binding_mode?: string
    allow_volume_expansion?: boolean
    parameters?: Record<string, string>
    [key: string]: unknown
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/storage_classes.test.tsx`: clone
  `priority_classes.test.tsx` 1:1 (the cluster-scoped pattern — no namespace
  setup; KubeDataTable fake included), and:
  - fixture `csiFast` (the to_dict shape):
    ```ts
    const csiFast = {
      apiVersion: 'storage.k8s.io/v1',
      kind: 'StorageClass',
      metadata: {
        name: 'csi-fast',
        creation_timestamp: '2026-01-02T03:04:05Z',
        annotations: { 'storageclass.kubernetes.io/is-default-class': 'true' },
        labels: { team: 'a' },
      },
      provisioner: 'csi.example.com',
      reclaim_policy: 'Delete',
      volume_binding_mode: 'WaitForFirstConsumer',
      parameters: { type: 'standard' },
    }
    const bareSc = { ...csiFast, metadata: { ...csiFast.metadata, annotations: {} }, reclaim_policy: undefined, volume_binding_mode: undefined }
    ```
  - `renderAt` default path `/storage/storage-class`; MSW handler on
    `*/api/v1/clusters/1/resources/storageclasses`.
  - `list-renders-storage-class-rows-with-data-links`: link `csi-fast` →
    `/storage/storage-class/data?name=csi-fast` (NO namespace); fetch URL
    EXACTLY `/api/v1/clusters/1/resources/storageclasses` (NO namespace
    param); heading EXACTLY `Storage Classes List`; breadcrumb `Storage`;
    column headers `['Name', 'Default', 'Reclaim Policy', 'Volume Binding
    Mode']`.
  - `list-default-policy-binding-cells`: Default `true`, Reclaim Policy
    `Delete`, Volume Binding Mode `WaitForFirstConsumer`.
  - `list-missing-fields`: `bareSc` row → Default/Reclaim Policy/Volume
    Binding Mode all `—`.
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No storage classes found`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/storage_classes.test.tsx`
  Expected: FAIL (cannot find module `src/views/Storage/StorageClass`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/Storage/StorageClass.tsx`: cluster-scoped layout from
  `PriorityClass.tsx` (no namespace selector):
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement
    (Storage), the `?name=` delta, the cluster-scoped (no namespace) contract,
    the is-default-class annotation for the Default column.
  - `const cluster = useClusterStore((s) => s.selectedCluster)` (NO namespace
    read — cluster-scoped).
  - `type ScRow = { name, isDefault: string, reclaimPolicy: string, volumeBindingMode: string }`:
    ```ts
    // The Default column is the storageclass.kubernetes.io/is-default-class
    // annotation value (4.1's template iterated the annotations looking for
    // this exact key). "—" when absent (certainty rule: never guess).
    const IS_DEFAULT = 'storageclass.kubernetes.io/is-default-class'
    const toRow = (item: StorageClassItem): ScRow => ({
      name: item.metadata?.name ?? '',
      isDefault: item.metadata?.annotations?.[IS_DEFAULT] ?? '—',
      reclaimPolicy: item.reclaim_policy ?? '—',
      volumeBindingMode: item.volume_binding_mode ?? '—',
    })
    ```
  - query key `['storageclasses', cluster?.id]` (NO namespace); URL
    `/api/v1/clusters/${cluster!.id}/resources/storageclasses` (NO namespace
    param).
  - name link → `/storage/storage-class/data?name=${encodeURIComponent(name)}`
    (cluster-scoped: NO `namespace`).
  - breadcrumb: Storage → Storage Classes List; card title EXACTLY
    `Storage Classes List`.
  - columns: Name (link) / Default / Reclaim Policy / Volume Binding Mode.
  - pinned states: `No cluster selected.`, `Loading storage classes...`,
    `Error loading storage classes: {message}`, `No storage classes found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/storage_classes.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Storage/StorageClass.tsx frontend/tests/views/storage_classes.test.tsx`
  `git commit -m "feat(frontend): storage class list view (4.1 port, cluster-scoped)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `storage-class-data-renders-detail`,
`storage-class-data-missing-parameters`, `storage-class-data-not-found-state`,
`storage-class-data-missing-name`

**Files:**
- Create: `frontend/src/views/Storage/StorageClassData.tsx`
- Test: `frontend/tests/views/storage_class_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=` contract (0/1-item list; `[]` = miss) and Task
  2's link (the sole producer of the `?name=` strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/storage_class_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/storageclasses?name=csi-fast` returning
    `{ kind: 'storageclasses', items: [csiFast] }`; a miss handler
    (`?name=ghost`) returning `{ items: [] }`.
  - `data-renders-detail`: at `/storage/storage-class/data?name=csi-fast` —
    assert EXACTLY ONE fetch and that its URL has `name=csi-fast` (NO
    namespace); CTable rows: Name `csi-fast`, Reclaim Policy `Delete`, Volume
    Binding Mode `WaitForFirstConsumer`, Provisioner `csi.example.com`, a
    Created row (via `formatTimestamp`), a Labels sub-table `team: a`, an
    Annotations sub-table
    `storageclass.kubernetes.io/is-default-class: true`; the Parameters table
    has a row `type: standard`; the full-object block contains
    `"reclaim_policy": "Delete"` (the JSON block).
  - `data-missing-parameters`: a class with no `parameters` → `No parameters`.
  - `data-not-found-state`: `?name=ghost` → `No StorageClass 'ghost' found`;
    assert NO `.text-danger` node for it (a state, not an error).
  - `data-missing-name`: `/storage/storage-class/data` (no param) →
    `Error: storage class name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/storage_class_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/Storage/StorageClassData.tsx`: clone of
  `PriorityClassData.tsx` + the 4.1 Provisioner + Parameters table:
  - docstring: single `?name=` fetch (no 4.1 list-then-filter), the
    cluster-scoped contract (no namespace), NOT_FOUND as a pinned STATE, the
    `json` hljs grammar as the truthful classifier (ratified 2026-10-28), the
    4.1 deviations (Volume Binding Mode label, no trimAnnotations).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read the param: `const name = params.get('name') ?? ''` (NO namespace).
  - query key `['storage-class-data', cluster?.id, name]`; enabled when
    `cluster != null && name !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/storageclasses?name=${encodeURIComponent(name)}`
    (NO namespace).
  - breadcrumb: Storage → Storage Classes List (link) → `{name}`.
  - card title `Storage Class Data`.
  - CTable rows: Name / Created / Reclaim Policy (`item.reclaim_policy ??
    '—'`) / Volume Binding Mode (`item.volume_binding_mode ?? '—'` — 4.1's data
    label was "Binding Mode"; 5.0 keeps the list header verbatim) /
    Provisioner (`item.provisioner ?? '—'`) / Labels / Annotations (sub-tables,
    `No labels` / `No annotations` when empty — the priorityclass twin's
    shape).
  - Parameters table (nested CTable, header `Key / Value`), one row per
    `item.parameters` entry (`No parameters` when the field is absent):
    ```tsx
    const parameters = Object.entries(item?.parameters ?? {})
    // 4.1's dynamic-key Parameters card, one row per entry.
    // row: <td>{key}</td><td className="text-break">{value}</td>
    ```
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No StorageClass '{name}' found`,
    `Error: storage class name not provided`, `Loading storage class data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/storage_class_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/Storage/StorageClassData.tsx frontend/tests/views/storage_class_data.test.tsx`
  `git commit -m "feat(frontend): storage class data view (4.1 tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `storage-class-stub-removed-and-routes-wired`

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
    path="/storage/storage-class"
    element={
      <ProtectedRoute>
        <StorageClassView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/storage/storage-class/data"
    element={
      <ProtectedRoute>
        <StorageClassDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 21
  (`{ path: '/storage/storage-class', title: 'StorageClass', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/storage/storage-class'` to the `viewPaths` set in `expectedStubs()`
  (the test derives expected stubs from the nav minus `viewPaths`; without
  the addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Task 3 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON block
    uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire storage-class routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_storageclasses.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/storage_classes.test.tsx tests/views/storage_class_data.test.tsx tests/views/Stub.test.tsx` — green.
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
