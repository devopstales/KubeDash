# SnapshotClass Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already
ratified for CRD kinds: the Cilium full-custom-object seam, same
`_KINDS`/`_GETTERS` wiring, same list+data view pair; the 4.1 template pair is
the source of truth for the page shape).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny + CRD-absent
empty) before any frontend exists; Task 2 is the list view; Task 3 the data
view; Task 4 the routing cleanup. Each task is independently revertable.

**Goal:** Resolve the nav leaf `/storage/snapshot-class` to a real, SAR-gated,
read-only list + data pair — the 4.1 SnapshotClass pages (a cluster-scoped
CRD) ported with the ratified 5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_volume_snapshot_classes` / `get_volume_snapshot_class`
(kubernetes `CustomObjectsApi`, group `snapshot.storage.k8s.io`, **cluster-
scoped CRD, full custom object** — the Cilium precedent + the RuntimeClass
cluster-scoped pattern), + two dict rows (`_KINDS` / `_GETTERS`). No new
client attribute: `self._custom()` / `self._api_client` already exist (the
CRD + Cilium kinds use them). Frontend: two views (list cloned from
PriorityClass.tsx for the cluster-scoped layout, data cloned from
PriorityClassData.tsx for the CTable+JSON block), `VolumeSnapshotClassItem`
type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CustomObjectsApi` (already a dependency, already
used by the CRD + Cilium kinds via `self._custom()`), Flask + Smorest
(existing route), React + CoreUI + TanStack Query + MSW (existing), no new
npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/storage/snapshot-class.html.j2`
(list: Name/Default/Deletion Policy/Driver — Default is the
`snapshot.storage.kubernetes.io/is-default-class` annotation value),
`4.1:src/kubedash/templates/storage/snapshot-class-data.html.j2` (data: Name/
Created/Annotations/Labels/Deletion Policy/Driver/Parameters — the Parameters
card is dynamic-key, one row per `parameters` entry),
`4.1:src/kubedash/lib/k8s/storage.py:46` (`k8sSnapshotClassListGet`:
`CustomObjectsApi().list_cluster_custom_object("snapshot.storage.k8s.io", "v1",
"volumesnapshotclasses")` — a **hardcoded `v1`**; generates
`name`/`created`/`annotations`/`driver`/`deletionPolicy` + conditional
`labels`/`parameters`; swallows ALL `ApiException` → `[]`),
`4.1:src/kubedash/blueprint/storage.py:73` (the list + data routes, the data
page is list-then-filter by name). In-repo precedents —
`backend/app/services/k8s_client.py:648-734` (the `get_crd_served` /
`list_cilium_clusterwide_network_policies` / `get_cilium_network_policy`
full-custom-object CRD seam to mirror; the cluster-scoped `list_crds` /
`get_crd` use `list_cluster_custom_object` / `get_cluster_custom_object`),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch (line
~104-114, the `namespace = namespace or "default"` fallback — irrelevant for
a cluster-scoped read),
`backend/tests/api/test_resources.py:1093-1230` (the ciliumnetworkpolicies API
tests to mirror: 200, all-namespaces, SAR deny w/ group, 502 on unreachable,
absent → empty),
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

None (the spec's vocabulary; "VolumeSnapshotClass" is the k8s kind, not a new
term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/volumesnapshotclasses` → 200,
  `kind: "volumesnapshotclasses"`, items as FULL custom objects (driver +
  deletionPolicy + parameters intact, camelCase), SAR-gated on
  `list volumesnapshotclasses` (group `snapshot.storage.k8s.io`, namespace
  `None`), 403 names the resource and the client call is never made on deny
  (`volumesnapshotclasses-list-200`, `volumesnapshotclasses-sar-denied`).
- A `namespace` param is accepted and ignored (cluster-scoped) — the client
  uses `list_cluster_custom_object` (`volumesnapshotclasses-list-ignores-
  namespace`).
- CRD absent (snapshot operator not installed) → `items == []`, 200, NOT an
  error (`volumesnapshotclasses-crd-absent-is-empty`) — the Cilium
  `get_crd_served is None → []` contract.
- `?name=` returns a 0/1-item list through the SAME route — hit = the full
  object, miss = `[]` (`volumesnapshotclasses-get-by-name`).
- The singular `volumesnapshotclass` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`volumesnapshotclass-kind-singular-rejected`).
- The list view fetches `/api/v1/clusters/<id>/resources/volumesnapshotclasses`
  (NO namespace param — cluster-scoped); card title EXACTLY `Snapshot Classes
  List`; columns Name/Default/Deletion Policy/Driver; every name links to
  `/storage/snapshot-class/data?name=<name>` (NO namespace)
  (`snapshot-class-list-renders-rows-with-data-links`).
- Default cell = the `snapshot.storage.kubernetes.io/is-default-class`
  annotation value (`—` when absent), Deletion Policy cell = `deletionPolicy`
  (`—` when absent), Driver cell = `driver` (`—` when absent)
  (`snapshot-class-list-default-policy-driver-cells`,
  `snapshot-class-list-missing-fields`).
- The data view fetches ONCE with `?name=`, renders the CTable
  (Name/Created/Deletion Policy/Driver/Labels/Annotations) + the Parameters
  table (key/value, `No parameters` when absent) + a JSON-highlighted
  full-object block, and treats a miss as the pinned state
  `No VolumeSnapshotClass '<name>' found` — never an error style
  (`snapshot-class-data-renders-detail`, `snapshot-class-data-missing-
  parameters`, `snapshot-class-data-not-found-state`).
- `/storage/snapshot-class` is gone from `views/Stub/routes.ts`; both real
  views are routed; the nav leaf is byte-identical
  (`snapshot-class-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — the two methods (modified; no new
  attribute, `self._custom()` + `self._api_client` already exist).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_volume_snapshot_classes.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `VolumeSnapshotClassItem` (modified).
- `frontend/src/views/Storage/SnapshotClass.tsx` (new).
- `frontend/src/views/Storage/SnapshotClassData.tsx` (new).
- `frontend/tests/views/snapshot_classes.test.tsx` (new).
- `frontend/tests/views/snapshot_class_data.test.tsx` (new).
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
  `ClusterUnreachableError`) on any cluster without the snapshot operator.
- The kind is **cluster-scoped**: `list_volume_snapshot_classes` uses
  `list_cluster_custom_object` (no namespace), and `get_volume_snapshot_class`
  uses `get_cluster_custom_object` (the `_GETTERS` convention passes
  `(namespace, name)`; the namespace is accepted and ignored — the
  `list_crds` / `get_crd` cluster-scoped pattern). The `?name=` branch's
  `namespace = "default"` fallback never affects the read.
- The list view's name-link href is the SOLE producer of the data page's
  `?name=` query strings (cluster-scoped: NO `namespace`) — the data page
  parses the param, never constructs one (the priorityclass contract; keep
  it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404 OR CRD-absent) — the data view must NOT treat
  `items: []` as an API error (the `NOT_FOUND`-throw pattern from
  PriorityClassData).
- The custom object is camelCase (the custom-object wire form, like the
  Cilium CRDs) — NOT snake_case. The type and the cell readers use camelCase
  keys (`deletionPolicy`, `driver`, `parameters`,
  `snapshot.storage.kubernetes.io/is-default-class`).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `CustomObjectsApi` is already vendored and
  already used by the CRD + Cilium + VPA kinds via `self._custom()` (air-gap,
  ADR-0020). No new `K8sClient` attribute.
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- CRD kind (group `snapshot.storage.k8s.io`, **cluster-scoped**): the list URL
  and the data URL carry NO `namespace=` param; SAR group =
  `"snapshot.storage.k8s.io"`, namespace = `None`; the client methods resolve
  the served version via `get_crd_served` and use the cluster-scoped
  `list_cluster_custom_object` / `get_cluster_custom_object` calls (the
  `list_crds` / `get_crd` cluster-scoped pattern).
- The custom object is camelCase (the custom-object wire form) — the type and
  cell readers use camelCase keys. NOT snake_case (it is not a generated
  core-API model).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Snapshot Classes List` (4.1's title, verbatim — the
  e2e-smoke contract).
- Pinned copy (do not reword): `No snapshot classes found`,
  `No VolumeSnapshotClass '<name>' found`,
  `Error: snapshot class name not provided`, `No cluster selected.`,
  `Loading snapshot classes...`, `No labels`, `No annotations`,
  `No parameters`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_volume_snapshot_classes`
  + `get_volume_snapshot_class` next to the Cilium methods (line ~715). No
  `__init__` change (`self._custom()` / `self._api_client` already exist).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["volumesnapshotclasses"]` + `_GETTERS["volumesnapshotclasses"]`.
- `backend/tests/services/test_k8s_client_volume_snapshot_classes.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_volume_snapshot_classes` / `get_volume_snapshot_class`; 6 new tests.
- `frontend/src/lib/types.ts` (modify) — `VolumeSnapshotClassItem` next to
  the Cilium CRD types.
- `frontend/src/views/Storage/SnapshotClass.tsx` (new) — cluster-scoped layout
  from PriorityClass.tsx (no namespace selector).
- `frontend/src/views/Storage/SnapshotClassData.tsx` (new) — clone of
  PriorityClassData.tsx + the 4.1 Parameters table.
- `frontend/tests/views/snapshot_classes.test.tsx` (new).
- `frontend/tests/views/snapshot_class_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (line ~381) + the two view imports (after line 48).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 22
  (`/storage/snapshot-class`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — volumesnapshotclasses kind (CRD, full object, cluster-scoped, SAR-gated)

**SATISFIES:** `volumesnapshotclasses-list-200`,
`volumesnapshotclasses-list-ignores-namespace`,
`volumesnapshotclasses-crd-absent-is-empty`,
`volumesnapshotclasses-sar-denied`, `volumesnapshotclasses-binding-404`,
`volumesnapshotclass-kind-singular-rejected`,
`volumesnapshotclasses-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_volume_snapshot_classes.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_volume_snapshot_classes(_namespace: str | None)
  -> list[dict]` and `K8sClient.get_volume_snapshot_class(_namespace: str,
  name: str) -> list[dict]` — the exact names `_KINDS`/`_GETTERS` reference
  via `getattr` (the `_GETTERS` call convention passes `(namespace, name)`;
  the namespace is accepted and ignored for this cluster-scoped kind).
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the ciliumnetworkpolicies tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_volume_snapshot_classes.py`,
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
      # The CRD is present and served, cluster-scoped (the absent case is
      # tested separately).
      client.get_crd_served = lambda group, plural: (_VERSION, "Cluster")
      return client


  def _sc(name: str) -> dict:
      return {
          "apiVersion": "snapshot.storage.k8s.io/v1",
          "kind": "VolumeSnapshotClass",
          "metadata": {
              "name": name,
              "creationTimestamp": "2026-01-02T03:04:05Z",
              "annotations": {"snapshot.storage.kubernetes.io/is-default-class": "true"},
          },
          "driver": "csi.example.com",
          "deletionPolicy": "Delete",
          "parameters": {"snapshotVolumeType": "standard"},
      }


  def test_list_volume_snapshot_classes_ignores_namespace() -> None:
      """[volumesnapshotclasses-list-ignores-namespace] cluster-scoped: the
      namespace is accepted-and-ignored, the cluster-scoped custom-object call
      is used, and the FULL object (driver + deletionPolicy + parameters
      intact, camelCase) is returned (the Cilium pattern)."""
      seen: list[object] = []
      sc = _sc("csi-snap")
      custom = SimpleNamespace(
          list_cluster_custom_object=lambda group, version, plural: (
              seen.append((group, version, plural)),
              {"items": [sc]},
          )[1],
      )
      result = _client(custom).list_volume_snapshot_classes("team-a")  # ns ignored
      assert result[0]["metadata"]["name"] == "csi-snap"
      assert result[0]["driver"] == "csi.example.com"  # full object intact
      assert result[0]["deletionPolicy"] == "Delete"
      assert result[0]["parameters"] == {"snapshotVolumeType": "standard"}
      assert seen == [("snapshot.storage.k8s.io", _VERSION, "volumesnapshotclasses")]


  def test_list_volume_snapshot_classes_crd_absent_is_empty() -> None:
      """[volumesnapshotclasses-crd-absent-is-empty] the CRD read is ``None``
      (snapshot operator not installed) -> ``[]`` (the Cilium absent
      contract), and the custom-object list is never called."""
      seen: list[object] = []
      custom = SimpleNamespace(
          list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []}
      )
      client = object.__new__(K8sClient)
      client._custom = lambda: custom
      client.get_crd_served = lambda group, plural: None
      assert client.list_volume_snapshot_classes(None) == []
      assert seen == []  # the list call was never made


  def test_get_volume_snapshot_class_404_returns_empty_list() -> None:
      """[volumesnapshotclasses-get-by-name] a miss is ``[]``, mirroring the
      CRD getter's 0/1-item contract."""
      def get(group, version, plural, name):
          raise ApiException(status=404)

      custom = SimpleNamespace(get_cluster_custom_object=get)
      assert _client(custom).get_volume_snapshot_class(None, "ghost") == []


  def test_get_volume_snapshot_class_hit_returns_one_full_item() -> None:
      sc = _sc("csi-snap")
      custom = SimpleNamespace(get_cluster_custom_object=lambda *a, **k: sc)
      result = _client(custom).get_volume_snapshot_class(None, "csi-snap")
      assert result[0]["driver"] == "csi.example.com"  # full object


  def test_get_volume_snapshot_class_ignores_namespace() -> None:
      """cluster-scoped: the namespace is accepted and ignored (the
      ``get_crd`` pattern)."""
      seen: list[object] = []
      sc = _sc("csi-snap")
      custom = SimpleNamespace(
          get_cluster_custom_object=lambda group, version, plural, name: (
              seen.append(name), sc
          )
      )
      _client(custom).get_volume_snapshot_class("team-a", "csi-snap")  # ns ignored
      assert seen == ["csi-snap"]


  def test_get_volume_snapshot_class_other_api_error_maps_to_unreachable() -> None:
      def get(group, version, plural, name):
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(get_cluster_custom_object=get)).get_volume_snapshot_class(None, "csi-snap")
  ```

  (Implementation note: `get_crd_served` is an instance method; the tests
  stub it via attribute assignment on the `object.__new__` client, the same
  way the Cilium tests stub the served-version seam. `_crd_body` is a
  `@staticmethod` and is NOT stubbed — it handles the plain-dict
  custom-object response as-is.)

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_volume_snapshot_classes.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`, next to
  `get_cilium_network_policy` (line ~715):

  ```python
  _SNAPSHOT_CLASS_GROUP = "snapshot.storage.k8s.io"
  _SNAPSHOT_CLASS_PLURAL = "volumesnapshotclasses"

  def list_volume_snapshot_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
      """VolumeSnapshotClass items, FULL custom-object shape (driver +
      deletionPolicy + parameters intact, camelCase — the wire form, like the
      Cilium CRDs). Cluster-scoped: the namespace argument is accepted and
      ignored (the ``list_crds`` pattern). The CRD's OWN served version is the
      authority (``get_crd_served``). CRD absent (snapshot operator not
      installed) -> ``[]`` (the expected state, the Cilium absence contract);
      any other read failure -> ``ClusterUnreachableError`` (502). The pages
      need ``driver``/``deletionPolicy``/``parameters``, so this returns the
      raw object — NOT the lossy ``list_crd_instances`` projection."""
      served = self.get_crd_served(self._SNAPSHOT_CLASS_GROUP, self._SNAPSHOT_CLASS_PLURAL)
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          resp = custom.list_cluster_custom_object(
              self._SNAPSHOT_CLASS_GROUP, version, self._SNAPSHOT_CLASS_PLURAL
          )
      except ApiException as e:
          self._unreachable("list_volume_snapshot_classes", e)
          raise AssertionError("unreachable") from e
      body = self._crd_body(resp)
      items = body.get("items", [])
      return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

  def get_volume_snapshot_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
      """One VolumeSnapshotClass as a 0/1-item FULL custom object; ``[]`` on
      404 or when the CRD is absent (snapshot operator not installed).
      Cluster-scoped: the namespace argument is accepted and ignored (the
      ``get_crd`` pattern). Any other ApiException maps to
      ``ClusterUnreachableError`` (502), matching the CRD getter."""
      served = self.get_crd_served(self._SNAPSHOT_CLASS_GROUP, self._SNAPSHOT_CLASS_PLURAL)
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          item = custom.get_cluster_custom_object(
              self._SNAPSHOT_CLASS_GROUP, version, self._SNAPSHOT_CLASS_PLURAL, name
          )
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_volume_snapshot_class", e)
          raise AssertionError("unreachable") from e
      item = self._crd_body(item)
      return [item.to_dict() if hasattr(item, "to_dict") else item]
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "volumesnapshotclasses": (
      "list_volume_snapshot_classes",
      "volumesnapshotclasses",
      "snapshot.storage.k8s.io",
  ),
  ```
  in `_KINDS` (after the cilium rows; group `snapshot.storage.k8s.io`), and
  ```python
  "volumesnapshotclasses": "get_volume_snapshot_class",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the ciliumnetworkpolicies
  block, lines 1093–1230):
  - FakeK8s gains:
    ```python
    def list_volume_snapshot_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped CRD (snapshot.storage.k8s.io): the namespace is
        # accepted-and-ignored; the FULL custom object (driver +
        # deletionPolicy + parameters) is returned (camelCase).
        return [
            {
                "metadata": {
                    "name": "csi-snap",
                    "creationTimestamp": "2026-01-02T03:04:05Z",
                    "annotations": {"snapshot.storage.kubernetes.io/is-default-class": "true"},
                    "labels": {"team": "a"},
                },
                "driver": "csi.example.com",
                "deletionPolicy": "Delete",
                "parameters": {"snapshotVolumeType": "standard"},
            }
        ]

    def get_volume_snapshot_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "csi-snap":
            return self.list_volume_snapshot_classes(None)
        return []
    ```
  - Six new tests mirroring the cilium block, same docstring-tag style:
    - `test_list_volumesnapshotclasses_200` — 200,
      `body["kind"] == "volumesnapshotclasses"`, one item with `driver` +
      `deletionPolicy` + `parameters` intact (the full object).
    - `test_list_volumesnapshotclasses_ignores_namespace` —
      `?namespace=team-a` → 200; assert the FakeK8s received `None` (the
      cluster-scoped branch — the namespace is ignored).
    - `test_list_volumesnapshotclasses_get_by_name` — `?name=csi-snap` → 1
      item; `?name=ghost` → `items == []`.
    - `test_list_volumesnapshotclasses_sar_denied` — SAR denies; 403; assert
      `("list", "volumesnapshotclasses", None, None, "snapshot.storage.k8s.io")`
      in `asked` (namespace `None`, group `snapshot.storage.k8s.io` — the
      load-bearing assertions).
    - `test_volumesnapshotclasses_binding_404` — cluster 999, unbound user
      → 404.
    - `test_volumesnapshotclass_kind_singular_rejected` —
      `/resources/volumesnapshotclass` → 404
      `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_volume_snapshot_classes.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_volume_snapshot_classes.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): volumesnapshotclasses kind (CRD, cluster-scoped, full object, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `snapshot-class-list-renders-rows-with-data-links`,
`snapshot-class-list-default-policy-driver-cells`,
`snapshot-class-list-missing-fields`, `snapshot-class-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Storage/SnapshotClass.tsx`
- Test: `frontend/tests/views/snapshot_classes.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `volumesnapshotclasses` list URL, cluster-
  scoped, full object).
- Produces: the data-page link `/storage/snapshot-class/data?name=<name>` —
  the SOLE producer of those query strings (cluster-scoped: NO `namespace`).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` (no
  namespace seam — cluster-scoped).
- Deletion test: deleting the view → the route (Task 4) 404s / the test file
  fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to the
  Cilium CRD types. **camelCase** (the custom-object wire form):

  ```ts
  /** A VolumeSnapshotClass custom object as returned by /api/v1/clusters/<id>/resources/volumesnapshotclasses (snapshot.storage.k8s.io CRD, camelCase wire form; cluster-scoped). */
  export interface VolumeSnapshotClassItem {
    metadata?: {
      name?: string
      creationTimestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    driver?: string
    deletionPolicy?: string
    parameters?: Record<string, string>
    [key: string]: unknown
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/snapshot_classes.test.tsx`: clone
  `priority_classes.test.tsx` 1:1 (the cluster-scoped pattern — no namespace
  setup; KubeDataTable fake included), and:
  - fixture `csiSnap` (the full custom object, camelCase):
    ```ts
    const csiSnap = {
      apiVersion: 'snapshot.storage.k8s.io/v1',
      kind: 'VolumeSnapshotClass',
      metadata: {
        name: 'csi-snap',
        creationTimestamp: '2026-01-02T03:04:05Z',
        annotations: { 'snapshot.storage.kubernetes.io/is-default-class': 'true' },
        labels: { team: 'a' },
      },
      driver: 'csi.example.com',
      deletionPolicy: 'Delete',
      parameters: { snapshotVolumeType: 'standard' },
    }
    const bareSnap = { ...csiSnap, metadata: { ...csiSnap.metadata, annotations: {} }, driver: undefined, deletionPolicy: undefined }
    ```
  - `renderAt` default path `/storage/snapshot-class`; MSW handler on
    `*/api/v1/clusters/1/resources/volumesnapshotclasses`.
  - `list-renders-snapshot-class-rows-with-data-links`: link `csi-snap` →
    `/storage/snapshot-class/data?name=csi-snap` (NO namespace); fetch URL
    EXACTLY `/api/v1/clusters/1/resources/volumesnapshotclasses` (NO
    namespace param); heading EXACTLY `Snapshot Classes List`; breadcrumb
    `Storage`; column headers `['Name', 'Default', 'Deletion Policy',
    'Driver']`.
  - `list-default-policy-driver-cells`: Default `true`, Deletion Policy
    `Delete`, Driver `csi.example.com`.
  - `list-missing-fields`: `bareSnap` row → Default/Deletion Policy/Driver
    all `—`.
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No snapshot classes found` (also the
    CRD-absent state).

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/snapshot_classes.test.tsx`
  Expected: FAIL (cannot find module `src/views/Storage/SnapshotClass`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/Storage/SnapshotClass.tsx`: cluster-scoped layout from
  `PriorityClass.tsx` (no namespace selector):
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement
    (Storage), the CRD full-object seam (the Cilium precedent, camelCase),
    the `?name=` delta, the cluster-scoped (no namespace) contract, the
    is-default-class annotation for the Default column.
  - `const cluster = useClusterStore((s) => s.selectedCluster)` (NO namespace
    read — cluster-scoped).
  - `type ScRow = { name, isDefault: string, deletionPolicy: string, driver: string }`:
    ```ts
    // The Default column is the snapshot.storage.kubernetes.io/is-default-class
    // annotation value (4.1's template iterated the annotations looking for
    // this exact key). "—" when absent (certainty rule: never guess).
    const IS_DEFAULT = 'snapshot.storage.kubernetes.io/is-default-class'
    const toRow = (item: VolumeSnapshotClassItem): ScRow => ({
      name: item.metadata?.name ?? '',
      isDefault: item.metadata?.annotations?.[IS_DEFAULT] ?? '—',
      deletionPolicy: item.deletionPolicy ?? '—',
      driver: item.driver ?? '—',
    })
    ```
  - query key `['volumesnapshotclasses', cluster?.id]` (NO namespace); URL
    `/api/v1/clusters/${cluster!.id}/resources/volumesnapshotclasses` (NO
    namespace param).
  - name link → `/storage/snapshot-class/data?name=${encodeURIComponent(name)}`
    (cluster-scoped: NO `namespace`).
  - breadcrumb: Storage → Snapshot Classes List; card title EXACTLY
    `Snapshot Classes List`.
  - columns: Name (link) / Default / Deletion Policy / Driver.
  - pinned states: `No cluster selected.`, `Loading snapshot classes...`,
    `Error loading snapshot classes: {message}`, `No snapshot classes found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/snapshot_classes.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Storage/SnapshotClass.tsx frontend/tests/views/snapshot_classes.test.tsx`
  `git commit -m "feat(frontend): snapshot class list view (4.1 CRD port, cluster-scoped)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `snapshot-class-data-renders-detail`,
`snapshot-class-data-missing-parameters`, `snapshot-class-data-not-found-state`,
`snapshot-class-data-missing-name`

**Files:**
- Create: `frontend/src/views/Storage/SnapshotClassData.tsx`
- Test: `frontend/tests/views/snapshot_class_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=` contract (0/1-item full object; `[]` = miss OR
  CRD-absent) and Task 2's link (the sole producer of the `?name=` strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/snapshot_class_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/volumesnapshotclasses?name=csi-snap`
    returning `{ kind: 'volumesnapshotclasses', items: [csiSnap] }`; a miss
    handler (`?name=ghost`) returning `{ items: [] }`.
  - `data-renders-detail`: at `/storage/snapshot-class/data?name=csi-snap` —
    assert EXACTLY ONE fetch and that its URL has `name=csi-snap` (NO
    namespace); CTable rows: Name `csi-snap`, Deletion Policy `Delete`,
    Driver `csi.example.com`, a Created row (via `formatTimestamp`), a Labels
    sub-table `team: a`, an Annotations sub-table
    `snapshot.storage.kubernetes.io/is-default-class: true`; the Parameters
    table has a row `snapshotVolumeType: standard`; the full-object block
    contains `"deletionPolicy": "Delete"` (the JSON block).
  - `data-missing-parameters`: a class with no `parameters` → `No parameters`.
  - `data-not-found-state`: `?name=ghost` → `No VolumeSnapshotClass 'ghost'
    found`; assert NO `.text-danger` node for it (a state, not an error).
  - `data-missing-name`: `/storage/snapshot-class/data` (no param) →
    `Error: snapshot class name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/snapshot_class_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/Storage/SnapshotClassData.tsx`: clone of
  `PriorityClassData.tsx` + the 4.1 Parameters table:
  - docstring: single `?name=` fetch (no 4.1 list-then-filter), the full
    custom object (camelCase, the Cilium seam), the cluster-scoped contract
    (no namespace), NOT_FOUND as a pinned STATE, the `json` hljs grammar as
    the truthful classifier (ratified 2026-10-28), the 4.1 deviations (no
    trimAnnotations).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read the param: `const name = params.get('name') ?? ''` (NO namespace).
  - query key `['snapshot-class-data', cluster?.id, name]`; enabled when
    `cluster != null && name !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/volumesnapshotclasses?name=${encodeURIComponent(name)}`
    (NO namespace).
  - breadcrumb: Storage → Snapshot Classes List (link) → `{name}`.
  - card title `Snapshot Class Data`.
  - CTable rows: Name / Created / Deletion Policy (`item.deletionPolicy ??
    '—'`) / Driver (`item.driver ?? '—'`) / Labels / Annotations (sub-tables,
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
  - pinned copy: `No VolumeSnapshotClass '{name}' found`,
    `Error: snapshot class name not provided`,
    `Loading snapshot class data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/snapshot_class_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/Storage/SnapshotClassData.tsx frontend/tests/views/snapshot_class_data.test.tsx`
  `git commit -m "feat(frontend): snapshot class data view (4.1 CRD tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `snapshot-class-stub-removed-and-routes-wired`

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
    path="/storage/snapshot-class"
    element={
      <ProtectedRoute>
        <SnapshotClassView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/storage/snapshot-class/data"
    element={
      <ProtectedRoute>
        <SnapshotClassDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 22
  (`{ path: '/storage/snapshot-class', title: 'SnapshotClass', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/storage/snapshot-class'` to the `viewPaths` set in `expectedStubs()`
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
  `git commit -m "feat(frontend): wire snapshot-class routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_volume_snapshot_classes.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/snapshot_classes.test.tsx tests/views/snapshot_class_data.test.tsx tests/views/Stub.test.tsx` — green.
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
