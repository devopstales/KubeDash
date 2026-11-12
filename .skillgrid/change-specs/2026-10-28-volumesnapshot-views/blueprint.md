# VolumeSnapshot Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already
ratified for CRD kinds: the Cilium full-custom-object seam + the VPA
namespaced-CRD pattern — same `_KINDS`/`_GETTERS` wiring, same list+data view
pair; the 4.1 list template is the source of truth for the list page shape,
the data page is new in 5.0).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny + CRD-absent
empty + all-namespaces branch) before any frontend exists; Task 2 is the list
view; Task 3 the data view; Task 4 the routing cleanup. Each task is
independently revertable.

**Goal:** Resolve the nav leaf `/storage/volumesnapshot` to a real, SAR-gated,
read-only list + data pair — the 4.1 VolumeSnapshot list (a namespaced CRD)
ported with the ratified 5.0 deltas, and a data page that resolves 4.1's
commented-out dead link.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`, and already threads
`namespace` (namespaced kinds: secrets, networkpolicies). This change adds
ONE kind: `K8sClient.list_volume_snapshots` / `get_volume_snapshot`
(kubernetes `CustomObjectsApi`, group `snapshot.storage.k8s.io`, **namespaced
CRD, full custom object** — the Cilium full-custom-object seam + the VPA
namespaced-CRD pattern), + two dict rows (`_KINDS` / `_GETTERS`). No new
client attribute: `self._custom()` / `self._api_client` already exist (the
CRD + Cilium + VPA kinds use them). Frontend: two views (list cloned from
ResourceQuota.tsx for the namespace handling, data cloned from
ResourceQuotaData.tsx / PriorityClassData.tsx for the CTable+JSON block),
`VolumeSnapshotItem` type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CustomObjectsApi` (already a dependency, already
used by the CRD + Cilium + VPA kinds via `self._custom()`), Flask + Smorest
(existing route), React + CoreUI + TanStack Query + MSW (existing), no new
npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/storage/volumesnapshot.html.j2`
(list: Usable / Name / SnapshotClass / VolumeClaim / Restore Size — the name
link to a data page is **commented out**: a dead link, 4.1 has no
`/volumesnapshot/data` route),
`4.1:src/kubedash/templates/storage/volumesnapshot-data.html.j2` (a data
template EXISTS in the 4.1 tree — Status/Name/Namespace/Created/
Annotations/Labels/SnapshotClass/Persistent Volume Claim/Volume Snapshot
Content/Snapshot Creation Time/Restore Size — but it is dead code: no route
renders it and the list never links it; 5.0's data page is NEW and renders
the 4.1 list columns + labels/annotations + the JSON block),
`4.1:src/kubedash/lib/k8s/storage.py:175` (`k8sPersistentVolumeSnapshotListGet`:
`CustomObjectsApi().list_cluster_custom_object("snapshot.storage.k8s.io", "v1",
"volumesnapshots")` — a **hardcoded `v1`** AND a **hardcoded all-namespaces
read** (the `namespace` param was post-filtered in Python, ignored when
`'all'`; the header-selected namespace never narrowed the read); deep-indexes
`spec.source.persistentVolumeClaimName` + `spec.volumeSnapshotClassName` —
both `KeyError` (500) on a SourceMode-less snapshot; swallows ALL
`ApiException` → `[]`). In-repo precedents —
`backend/app/services/k8s_client.py:667-734` (the `get_crd_served` +
`list_cilium_network_policies` / `get_cilium_network_policy` full-custom-object
CRD seam to mirror — the **namespaced** member of the family; the VPA pair
uses the identical `namespace and scope == "Namespaced"` branch),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch (line
~109-118, the `namespace = namespace or "default"` fallback — the data page
ALWAYS sends the namespace it was linked with),
`backend/tests/api/test_resources.py` (the ciliumnetworkpolicies API tests to
mirror: 200, namespace honored, SAR deny w/ group + namespace, 502 on
unreachable, absent → empty),
`frontend/src/views/OtherResource/ResourceQuota.tsx` (the namespaced list
view: `selectedNamespace ?? 'default'`, namespace in URL + query key, name
link carries BOTH `name` and `namespace`),
`frontend/src/views/OtherResource/ResourceQuotaData.tsx` +
`PriorityClassData.tsx` (the data view: single `?name=&namespace=` fetch,
CTable + labels/annotations sub-tables + JSON block; the NOT_FOUND-as-
throw-not-found-state pattern),
`frontend/tests/views/resource_quotas.test.tsx` +
`resource_quota_data.test.tsx` (the namespaced test patterns to clone).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0010, ADR-0020, ADR-0021,
ADR-0022. None created.

## Terms

None (the spec's vocabulary; "VolumeSnapshot" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/volumesnapshots?namespace=team-a` → 200,
  `kind: "volumesnapshots"`, items as FULL custom objects (spec + status
  intact, camelCase), SAR-gated on `list volumesnapshots` (group
  `snapshot.storage.k8s.io`, namespace `team-a`), 403 names the resource and
  the client call is never made on deny
  (`volumesnapshots-list-200-in-namespace`, `volumesnapshots-sar-denied`).
- The namespace is honored: the client uses
  `list_namespaced_custom_object` when the CRD is namespaced-scoped
  (`volumesnapshots-list-honors-namespace`).
- Without a `namespace` param the client uses `list_cluster_custom_object`
  (all namespaces) (`volumesnapshots-list-all-namespaces-without-param`) —
  the branch exists for the API; the page always sends a namespace.
- CRD absent (snapshot operator not installed) → `items == []`, 200, NOT an
  error (`volumesnapshots-crd-absent-is-empty`) — the Cilium
  `get_crd_served is None → []` contract.
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the full object, miss = `[]` (`volumesnapshots-get-by-name`).
- The singular `volumesnapshot` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`volumesnapshot-kind-singular-rejected`).
- The list view fetches
  `/api/v1/clusters/<id>/resources/volumesnapshots?namespace=<ns>` with
  `<ns> = selectedNamespace ?? 'default'` (the header-selected namespace — a
  fix for 4.1's all-namespaces list); card title EXACTLY `Volume Snapshot
  List` (4.1's title, kept verbatim — the e2e-smoke contract); columns
  Name / Usable / SnapshotClass / VolumeClaim / Restore Size; every name
  links to `/storage/volumesnapshot/data?name=<name>&namespace=<ns>` — the
  list view is the sole producer of those query strings (a fix for 4.1's
  commented-out dead link)
  (`volumesnapshot-list-renders-rows-with-data-links`).
- Usable cell = `status.readyToUse` badge (`True` → success, otherwise →
  danger, `—` when absent); SnapshotClass cell =
  `spec.volumeSnapshotClassName` (`—` when absent — the 4.1 deep-index 500 is
  fixed); VolumeClaim cell = `spec.source.persistentVolumeClaimName` (`—` when
  absent — same fix); Restore Size cell = `status.restoreSize` (`—` when
  absent) (`volumesnapshot-list-ready-class-pvc-cells`,
  `volumesnapshot-list-missing-fields`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Name / Created / Source / SnapshotClass / Ready To Use / Restore Size /
  Bound Content / Labels / Annotations) + a JSON-highlighted full-object
  block, and treats a miss as the pinned state `No VolumeSnapshot '<name>'
  found` — never an error style (`volumesnapshot-data-renders-detail`,
  `volumesnapshot-data-missing-fields`,
  `volumesnapshot-data-not-found-state`).
- Missing `name` param → `Error: volume snapshot name not provided`
  (`volumesnapshot-data-missing-name`).
- `/storage/volumesnapshot` is gone from `views/Stub/routes.ts`; both real
  views are routed; the nav leaf is byte-identical
  (`volumesnapshot-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — the two methods (modified; no new
  attribute, `self._custom()` + `self._api_client` already exist).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_volume_snapshots.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 7 new tests
  (modified).
- `frontend/src/lib/types.ts` — `VolumeSnapshotItem` (modified).
- `frontend/src/views/Storage/VolumeSnapshot.tsx` (new).
- `frontend/src/views/Storage/VolumeSnapshotData.tsx` (new).
- `frontend/tests/views/volume_snapshots.test.tsx` (new).
- `frontend/tests/views/volume_snapshot_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching client
  method is a 500 at `getattr(pool.get(cluster), ...)` — both rows land in
  the same commit as the service methods.
- The kind is a CRD: the service methods MUST call `get_crd_served` FIRST and
  return `[]` when it is `None` — the CRD-absent contract. Forgetting the
  `get_crd_served` guard is a 500 (the CRD read 404s as a transport
  `ClusterUnreachableError`) on any cluster without the snapshot operator.
- The kind is **namespaced**: `list_volume_snapshots` uses
  `list_namespaced_custom_object` when the CRD's scope is `Namespaced` AND a
  namespace is given, else `list_cluster_custom_object` (the all-namespaces
  branch — the VPA pattern); `get_volume_snapshot` uses
  `get_namespaced_custom_object` (the `_GETTERS` convention passes
  `(namespace, name)`; the `?name=` branch's `namespace = "default"` fallback
  is the documented behavior when no namespace is sent — the data page always
  sends the one it was linked with).
- The list view's name-link href is the SOLE producer of the data page's
  `?name=&namespace=` query strings — the data page parses the params, never
  constructs one (the ResourceQuota/NetworkPolicy contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404 OR CRD-absent) — the data view must NOT treat
  `items: []` as an API error (the NOT_FOUND-throw pattern from
  PriorityClassData/ResourceQuotaData).
- The custom object is camelCase (the custom-object wire form, like the Cilium
  CRDs and VPAs) — NOT snake_case (it is not a generated core-API model). The
  type and the cell readers use camelCase keys (`readyToUse`, `restoreSize`,
  `boundVolumeSnapshotContentName`, `volumeSnapshotClassName`,
  `persistentVolumeClaimName`, `creationTimestamp`).
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
- CRD kind (group `snapshot.storage.k8s.io`, **namespaced**): the list URL
  and the data URL carry a `namespace=` param; SAR group =
  `"snapshot.storage.k8s.io"`, namespace = the query namespace (or `None` for
  the all-namespaces list branch); the client methods resolve the served
  version via `get_crd_served` and branch on the CRD's scope (the VPA
  pattern).
- The custom object is camelCase (the custom-object wire form) — the type and
  cell readers use camelCase keys. NOT snake_case (it is not a generated
  core-API model).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Volume Snapshot List` (4.1's title, verbatim — the
  e2e-smoke contract; `ui-smoke.spec.ts:42` already asserts the
  `/storage/volumesnapshot` path).
- Pinned copy (do not reword): `No volume snapshots found`,
  `No VolumeSnapshot '<name>' found`,
  `Error: volume snapshot name not provided`, `No cluster selected.`,
  `Loading volume snapshots...`, `No labels`, `No annotations`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_volume_snapshots` +
  `get_volume_snapshot` next to the Cilium methods (line ~715). No `__init__`
  change (`self._custom()` / `self._api_client` already exist).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["volumesnapshots"]` + `_GETTERS["volumesnapshots"]`.
- `backend/tests/services/test_k8s_client_volume_snapshots.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_volume_snapshots` / `get_volume_snapshot`; 7 new tests.
- `frontend/src/lib/types.ts` (modify) — `VolumeSnapshotItem` next to the
  VPA CRD type.
- `frontend/src/views/Storage/VolumeSnapshot.tsx` (new) — namespaced layout
  from ResourceQuota.tsx (namespace read, namespace in URL + query key, name
  link carries both params).
- `frontend/src/views/Storage/VolumeSnapshotData.tsx` (new) — clone of
  ResourceQuotaData.tsx / PriorityClassData.tsx (single `?name=&namespace=`
  fetch, CTable + labels/annotations sub-tables + JSON block).
- `frontend/tests/views/volume_snapshots.test.tsx` (new).
- `frontend/tests/views/volume_snapshot_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes (mirror the resourcequota pair
  block) + the two view imports.
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 20
  (`/storage/volumesnapshot`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — volumesnapshots kind (CRD, namespaced, full object, SAR-gated)

**SATISFIES:** `volumesnapshots-list-200-in-namespace`,
`volumesnapshots-list-honors-namespace`,
`volumesnapshots-list-all-namespaces-without-param`,
`volumesnapshots-crd-absent-is-empty`, `volumesnapshots-sar-denied`,
`volumesnapshots-binding-404`, `volumesnapshot-kind-singular-rejected`,
`volumesnapshots-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_volume_snapshots.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_volume_snapshots(namespace: str | None) ->
  list[dict]` and `K8sClient.get_volume_snapshot(namespace: str, name: str) ->
  list[dict]` — the exact names `_KINDS`/`_GETTERS` reference via `getattr`
  (the `_GETTERS` call convention passes `(namespace, name)`).
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the ciliumnetworkpolicies / verticalpodautoscalers tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s with
  `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_volume_snapshots.py`, mirroring the
  VPA test pattern with `object.__new__` + `SimpleNamespace` (stub
  `get_crd_served` to return a version + scope, and `_custom()` to return the
  fake):

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
      # The CRD is present and served, namespaced (the absent case is
      # tested separately).
      client.get_crd_served = lambda group, plural: (_VERSION, "Namespaced")
      return client


  def _vs(name: str, namespace: str = "team-a") -> dict:
      return {
          "apiVersion": "snapshot.storage.k8s.io/v1",
          "kind": "VolumeSnapshot",
          "metadata": {
              "name": name,
              "namespace": namespace,
              "creationTimestamp": "2026-01-02T03:04:05Z",
              "labels": {"team": "a"},
          },
          "spec": {
              "source": {"persistentVolumeClaimName": f"pvc-{name}"},
              "volumeSnapshotClassName": "csi-snap",
          },
          "status": {
              "readyToUse": True,
              "restoreSize": "1Gi",
              "boundVolumeSnapshotContentName": f"content-{name}",
              "creationTime": "2026-01-02T03:05:00Z",
          },
      }


  def test_list_volume_snapshots_honors_namespace() -> None:
      """[volumesnapshots-list-honors-namespace] the namespace is forwarded
      to ``list_namespaced_custom_object`` (the VPA namespaced-CRD pattern)
      and the FULL object (spec + status intact, camelCase) is returned (the
      Cilium pattern)."""
      seen: list[object] = []
      vs = _vs("snap-a")
      custom = SimpleNamespace(
          list_namespaced_custom_object=lambda group, version, namespace, plural: (
              seen.append((group, version, namespace, plural)),
              {"items": [vs]},
          )[1],
      )
      result = _client(custom).list_volume_snapshots("team-a")
      assert result[0]["metadata"]["name"] == "snap-a"
      assert result[0]["spec"]["source"]["persistentVolumeClaimName"] == "pvc-snap-a"  # full object intact
      assert result[0]["status"]["readyToUse"] is True
      assert seen == [("snapshot.storage.k8s.io", _VERSION, "team-a", "volumesnapshots")]


  def test_list_volume_snapshots_all_namespaces_without_namespace() -> None:
      """[volumesnapshots-list-all-namespaces-without-param] no namespace ->
      ``list_cluster_custom_object`` (the all-namespaces branch; the page
      always sends a namespace, the API branch exists for other consumers)."""
      seen: list[object] = []
      vs = _vs("snap-a")
      custom = SimpleNamespace(
          list_cluster_custom_object=lambda group, version, plural: (
              seen.append((group, version, plural)),
              {"items": [vs]},
          )[1],
      )
      result = _client(custom).list_volume_snapshots(None)
      assert result[0]["metadata"]["name"] == "snap-a"
      assert seen == [("snapshot.storage.k8s.io", _VERSION, "volumesnapshots")]


  def test_list_volume_snapshots_crd_absent_is_empty() -> None:
      """[volumesnapshots-crd-absent-is-empty] the CRD read is ``None``
      (snapshot operator not installed) -> ``[]`` (the Cilium absent
      contract), and the custom-object list is never called."""
      seen: list[object] = []
      custom = SimpleNamespace(
          list_namespaced_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
          list_cluster_custom_object=lambda *a, **k: seen.append(True) or {"items": []},
      )
      client = object.__new__(K8sClient)
      client._custom = lambda: custom
      client.get_crd_served = lambda group, plural: None
      assert client.list_volume_snapshots("team-a") == []
      assert seen == []  # the list call was never made


  def test_get_volume_snapshot_404_returns_empty_list() -> None:
      """[volumesnapshots-get-by-name] a miss is ``[]``, mirroring the
      namespaced getter's 0/1-item contract."""
      def get(group, version, namespace, plural, name):
          raise ApiException(status=404)

      custom = SimpleNamespace(get_namespaced_custom_object=get)
      assert _client(custom).get_volume_snapshot("team-a", "ghost") == []


  def test_get_volume_snapshot_hit_returns_one_full_item() -> None:
      vs = _vs("snap-a")
      custom = SimpleNamespace(get_namespaced_custom_object=lambda *a, **k: vs)
      result = _client(custom).get_volume_snapshot("team-a", "snap-a")
      assert result[0]["status"]["boundVolumeSnapshotContentName"] == "content-snap-a"  # full object


  def test_get_volume_snapshot_other_api_error_maps_to_unreachable() -> None:
      def get(group, version, namespace, plural, name):
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(get_namespaced_custom_object=get)).get_volume_snapshot("team-a", "snap-a")
  ```

  (Implementation note: `get_crd_served` is an instance method; the tests
  stub it via attribute assignment on the `object.__new__` client, the same
  way the VPA/Cilium tests stub the served-version seam. `_crd_body` is a
  `@staticmethod` and is NOT stubbed — it handles the plain-dict
  custom-object response as-is.)

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_volume_snapshots.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`, next to
  the VPA methods:

  ```python
  _SNAPSHOT_GROUP = "snapshot.storage.k8s.io"
  _SNAPSHOT_PLURAL = "volumesnapshots"

  def list_volume_snapshots(self, namespace: str | None) -> list[dict[str, Any]]:
      """VolumeSnapshot items, FULL custom-object shape (spec + status
      intact, camelCase — the wire form, like the Cilium CRDs). The CRD's OWN
      served version + scope is the authority (``get_crd_served``); the
      namespaced read honors the namespace (a fix for 4.1's hardcoded
      all-namespaces ``list_cluster_custom_object`` read), and
      ``namespace=None`` spans all namespaces (the all-namespaces branch,
      kept for the API). CRD absent (snapshot operator not installed) ->
      ``[]`` (the expected state, the Cilium absence contract); any other
      read failure -> ``ClusterUnreachableError`` (502). The pages need
      ``spec.source``/``spec.volumeSnapshotClassName``/``status`` intact, so
      this returns the raw object — NOT the lossy ``list_crd_instances``
      projection (and no deep-indexing: 4.1's KeyError-500 on a
      SourceMode-less snapshot is fixed in the view via ``—``)."""
      served = self.get_crd_served(self._SNAPSHOT_GROUP, self._SNAPSHOT_PLURAL)
      if served is None:
          return []
      version, scope = served
      custom = self._custom()
      try:
          resp = (
              custom.list_namespaced_custom_object(
                  self._SNAPSHOT_GROUP, version, namespace, self._SNAPSHOT_PLURAL
              )
              if namespace and scope == "Namespaced"
              else custom.list_cluster_custom_object(
                  self._SNAPSHOT_GROUP, version, self._SNAPSHOT_PLURAL
              )
          )
      except ApiException as e:
          self._unreachable("list_volume_snapshots", e)
          raise AssertionError("unreachable") from e
      body = self._crd_body(resp)
      items = body.get("items", [])
      return [item.to_dict() if hasattr(item, "to_dict") else item for item in items]

  def get_volume_snapshot(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One VolumeSnapshot as a 0/1-item FULL custom object; ``[]`` on 404
      or when the CRD is absent (snapshot operator not installed). Any other
      ApiException maps to ``ClusterUnreachableError`` (502), matching
      ``get_cilium_network_policy``. The namespace is the one the data page
      was linked with (the ``?name=`` branch of the generic route falls back
      to ``"default"`` when absent — the data page always sends it)."""
      served = self.get_crd_served(self._SNAPSHOT_GROUP, self._SNAPSHOT_PLURAL)
      if served is None:
          return []
      version, _scope = served
      custom = self._custom()
      try:
          item = custom.get_namespaced_custom_object(
              self._SNAPSHOT_GROUP, version, namespace, self._SNAPSHOT_PLURAL, name
          )
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_volume_snapshot", e)
          raise AssertionError("unreachable") from e
      item = self._crd_body(item)
      return [item.to_dict() if hasattr(item, "to_dict") else item]
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # VolumeSnapshot (snapshot.storage.k8s.io, namespaced CRD) — the 4.1-parity
  # nav leaf resolved by this change (list + data views; ADR-0022 placement).
  "volumesnapshots": (
      "list_volume_snapshots",
      "volumesnapshots",
      "snapshot.storage.k8s.io",
  ),
  ```
  in `_KINDS` (after the snapshotclass/resourcequotas rows; group
  `snapshot.storage.k8s.io`), and
  ```python
  "volumesnapshots": "get_volume_snapshot",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the
  ciliumnetworkpolicies / verticalpodautoscalers block):
  - FakeK8s gains:
    ```python
    def list_volume_snapshots(self, namespace: str | None) -> list[dict]:
        # Namespaced CRD (snapshot.storage.k8s.io): the namespace is honored;
        # the FULL custom object (spec + status) is returned (camelCase).
        return [
            {
                "metadata": {
                    "name": "snap-a",
                    "namespace": namespace or "default",
                    "creationTimestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                },
                "spec": {
                    "source": {"persistentVolumeClaimName": "pvc-snap-a"},
                    "volumeSnapshotClassName": "csi-snap",
                },
                "status": {
                    "readyToUse": True,
                    "restoreSize": "1Gi",
                    "boundVolumeSnapshotContentName": "content-snap-a",
                },
            }
        ]

    def get_volume_snapshot(self, namespace: str, name: str) -> list[dict]:
        if name == "snap-a":
            return self.list_volume_snapshots(namespace)
        return []
    ```
  - Seven new tests mirroring the cilium/vpa block, same docstring-tag style:
    - `test_list_volumesnapshots_200_in_namespace` —
      `?namespace=team-a` → 200, `body["kind"] == "volumesnapshots"`, one
      item with `spec.source.persistentVolumeClaimName` +
      `status.boundVolumeSnapshotContentName` intact (the full object);
      assert the FakeK8s received `team-a`.
    - `test_list_volumesnapshots_honors_namespace` — the client received
      `namespace=team-a` (the namespaced branch was taken).
    - `test_list_volumesnapshots_all_namespaces_without_param` — no
      `?namespace=` → 200; assert the FakeK8s received `None` (the
      all-namespaces branch).
    - `test_list_volumesnapshots_crd_absent_is_empty` — FakeK8s returns
      `[]` → 200, `items == []` (not an error).
    - `test_list_volumesnapshots_sar_denied` — SAR denies; 403; assert
      `("list", "volumesnapshots", "team-a", None, "snapshot.storage.k8s.io")`
      in `asked` (namespace `team-a`, group `snapshot.storage.k8s.io` — the
      load-bearing assertions) and the client call was never made.
    - `test_volumesnapshots_binding_404` — cluster 999, unbound user → 404.
    - `test_volumesnapshot_kind_singular_rejected` —
      `/resources/volumesnapshot` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.
    - `test_list_volumesnapshots_get_by_name` — `?name=snap-a&namespace=team-a`
      → 1 item; `?name=ghost&namespace=team-a` → `items == []`; assert the
      SAR asked `("get", "volumesnapshots", "team-a", "snap-a",
      "snapshot.storage.k8s.io")`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_volume_snapshots.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_volume_snapshots.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): volumesnapshots kind (CRD, namespaced, full object, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `volumesnapshot-list-renders-rows-with-data-links`,
`volumesnapshot-list-ready-class-pvc-cells`,
`volumesnapshot-list-missing-fields`, `volumesnapshot-list-empty-state`,
`volumesnapshot-list-no-cluster-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Storage/VolumeSnapshot.tsx`
- Test: `frontend/tests/views/volume_snapshots.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `volumesnapshots` list URL with `?namespace=`,
  full object).
- Produces: the data-page link
  `/storage/volumesnapshot/data?name=<name>&namespace=<ns>` — the SOLE
  producer of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` +
  `useClusterStore.selectedNamespace ?? 'default'` (the ResourceQuota
  namespaced pattern).
- Deletion test: deleting the view → the route (Task 4) 404s / the test file
  fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to the VPA
  CRD type. **camelCase** (the custom-object wire form):

  ```ts
  /** A VolumeSnapshot custom object as returned by /api/v1/clusters/<id>/resources/volumesnapshots (snapshot.storage.k8s.io CRD, namespaced, camelCase wire form). */
  export interface VolumeSnapshotItem {
    metadata?: {
      name?: string
      namespace?: string
      creationTimestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      source?: {
        persistentVolumeClaimName?: string
        volume?: string
      }
      volumeSnapshotClassName?: string
    }
    status?: {
      readyToUse?: boolean
      restoreSize?: string
      boundVolumeSnapshotContentName?: string
      creationTime?: string
    }
    [key: string]: unknown
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/volume_snapshots.test.tsx`: clone
  `resource_quotas.test.tsx` 1:1 (the namespaced pattern — namespace in store
  + URL; KubeDataTable fake included), and:
  - fixture `snapA` (the full custom object, camelCase):
    ```ts
    const snapA = {
      apiVersion: 'snapshot.storage.k8s.io/v1',
      kind: 'VolumeSnapshot',
      metadata: {
        name: 'snap-a',
        namespace: 'team-a',
        creationTimestamp: '2026-01-02T03:04:05Z',
        labels: { team: 'a' },
      },
      spec: {
        source: { persistentVolumeClaimName: 'pvc-snap-a' },
        volumeSnapshotClassName: 'csi-snap',
      },
      status: {
        readyToUse: true,
        restoreSize: '1Gi',
        boundVolumeSnapshotContentName: 'content-snap-a',
      },
    }
    // A SourceMode-less snapshot (4.1's deep-index 500 case): no
    // persistentVolumeClaimName, no volumeSnapshotClassName, no status.
    const bareSnap = {
      ...snapA,
      metadata: { ...snapA.metadata, name: 'bare-snap', annotations: {} },
      spec: { source: {} },
      status: {},
    }
    ```
  - `renderAt` default path `/storage/volumesnapshot`; the cluster store
    fixture sets `selectedNamespace` to `team-a` (the resource_quotas test
    fixture); MSW handler on
    `*/api/v1/clusters/1/resources/volumesnapshots?namespace=team-a`.
  - `list-renders-snapshot-rows-with-data-links`: link `snap-a` →
    `/storage/volumesnapshot/data?name=snap-a&namespace=team-a` (BOTH params);
    fetch URL EXACTLY
    `/api/v1/clusters/1/resources/volumesnapshots?namespace=team-a`;
    heading EXACTLY `Volume Snapshot List`; breadcrumb `Storage`; column
    headers `['Name', 'Usable', 'SnapshotClass', 'VolumeClaim', 'Restore
    Size']`.
  - `list-ready-class-pvc-cells`: Usable success badge `Ready`,
    SnapshotClass `csi-snap`, VolumeClaim `pvc-snap-a`, Restore Size `1Gi`.
  - `list-missing-fields`: `bareSnap` row → Usable `—`, SnapshotClass `—`,
    VolumeClaim `—`, Restore Size `—` (the 4.1 deep-index 500 is fixed —
    the row renders, no crash).
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No volume snapshots found` (also the
    CRD-absent state).
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/volume_snapshots.test.tsx`
  Expected: FAIL (cannot find module `src/views/Storage/VolumeSnapshot`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/Storage/VolumeSnapshot.tsx`: namespaced layout from
  `ResourceQuota.tsx`:
  - docstring: cite the 4.1 template (the real port — the dead data link is
    resolved), ADR-0022 placement (Storage), the CRD full-object seam (the
    Cilium precedent, camelCase), the `?name=&namespace=` delta, the
    header-namespace contract (a fix for 4.1's all-namespaces list), the
    `—` certainty rule for the deep-index fields.
  - `const cluster = useClusterStore((s) => s.selectedCluster)` +
    `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`.
  - `type VsRow = { name, namespace, usable: string, snapshotClass: string,
    pvc: string, restoreSize: string }`:
    ```ts
    // 4.1 deep-indexed spec.source.persistentVolumeClaimName and
    // spec.volumeSnapshotClassName — both KeyError'd (500) on a
    // SourceMode-less snapshot. 5.0 renders "—" for absent keys
    // (certainty rule: never guess, never crash a row).
    const toRow = (item: VolumeSnapshotItem): VsRow => ({
      name: item.metadata?.name ?? '',
      namespace: item.metadata?.namespace ?? '',
      usable: item.status?.readyToUse === undefined ? '—' : item.status.readyToUse ? 'Ready' : 'Not Ready',
      snapshotClass: item.spec?.volumeSnapshotClassName ?? '—',
      pvc: item.spec?.source?.persistentVolumeClaimName ?? '—',
      restoreSize: item.status?.restoreSize ?? '—',
    })
    ```
  - query key `['volumesnapshots', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/volumesnapshots?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/storage/volumesnapshot/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`
    (BOTH params — the row's own namespace, falling back to the header
    namespace: `row.namespace || namespace`).
  - breadcrumb: Storage → Volume Snapshot List; card title EXACTLY
    `Volume Snapshot List`.
  - columns: Name (link) / Usable (badge: `Ready` → success, `Not Ready` →
    danger, `—` → muted) / SnapshotClass / VolumeClaim / Restore Size.
  - pinned states: `No cluster selected.`, `Loading volume snapshots...`,
    `Error loading volume snapshots: {message}`, `No volume snapshots found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/volume_snapshots.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Storage/VolumeSnapshot.tsx frontend/tests/views/volume_snapshots.test.tsx`
  `git commit -m "feat(frontend): volume snapshot list view (4.1 CRD port, namespaced)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `volumesnapshot-data-renders-detail`,
`volumesnapshot-data-missing-fields`,
`volumesnapshot-data-not-found-state`, `volumesnapshot-data-missing-name`

**Files:**
- Create: `frontend/src/views/Storage/VolumeSnapshotData.tsx`
- Test: `frontend/tests/views/volume_snapshot_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item full object;
  `[]` = miss OR CRD-absent) and Task 2's link (the sole producer of the
  `?name=&namespace=` strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/volume_snapshot_data.test.tsx`: clone
  `resource_quota_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/volumesnapshots?name=snap-a&namespace=team-a`
    returning `{ kind: 'volumesnapshots', items: [snapA] }`; a miss handler
    (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/storage/volumesnapshot/data?name=snap-a&namespace=team-a` — assert
    EXACTLY ONE fetch and that its URL has BOTH `name=snap-a` and
    `namespace=team-a`; CTable rows: Name `snap-a`, Source `pvc-snap-a`,
    SnapshotClass `csi-snap`, Ready To Use `Ready` (success badge), Restore
    Size `1Gi`, Bound Content `content-snap-a`, a Created row (via
    `formatTimestamp`), a Labels sub-table `team: a`; the full-object block
    contains `"readyToUse": true` (the JSON block).
  - `data-missing-fields`: a `bareSnap`-shaped item (no
    `persistentVolumeClaimName`/`volumeSnapshotClassName`/status fields) →
    Source/SnapshotClass/Ready To Use/Restore Size/Bound Content all `—`.
  - `data-not-found-state`: `?name=ghost&namespace=team-a` →
    `No VolumeSnapshot 'ghost' found`; assert NO `.text-danger` node for it
    (a state, not an error).
  - `data-missing-name`: `/storage/volumesnapshot/data` (no param) →
    `Error: volume snapshot name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]`.

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/volume_snapshot_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/Storage/VolumeSnapshotData.tsx`: clone of
  `ResourceQuotaData.tsx` / `PriorityClassData.tsx`:
  - docstring: single `?name=&namespace=` fetch (4.1 had NO data page — the
    dead link is resolved), the full custom object (camelCase, the Cilium
    seam), the `—` certainty rule for absent keys (the 4.1 deep-index 500
    fix), NOT_FOUND as a pinned STATE, the `json` hljs grammar as the
    truthful classifier (ratified 2026-10-28), the 4.1 deviations (no
    trimAnnotations).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read the params: `const name = params.get('name') ?? ''` +
    `const namespace = params.get('namespace') ?? ''`.
  - query key `['volume-snapshot-data', cluster?.id, name, namespace]`;
    enabled when `cluster != null && name !== '' && namespace !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/volumesnapshots?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Storage → Volume Snapshot List (link) → `{name}`.
  - card title `Volume Snapshot Data`.
  - CTable rows: Name / Created (`formatTimestamp(item.metadata?.
    creationTimestamp)`) / Source
    (`item.spec?.source?.persistentVolumeClaimName ?? '—'`) / SnapshotClass
    (`item.spec?.volumeSnapshotClassName ?? '—'`) / Ready To Use
    (`item.status?.readyToUse === undefined ? '—' : item.status.readyToUse
    ? success badge 'Ready' : danger badge 'Not Ready'`) / Restore Size
    (`item.status?.restoreSize ?? '—'`) / Bound Content
    (`item.status?.boundVolumeSnapshotContentName ?? '—'`) / Labels /
    Annotations (sub-tables, `No labels` / `No annotations` when empty — the
    ResourceQuotaData/PriorityClassData twin's shape).
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No VolumeSnapshot '{name}' found`,
    `Error: volume snapshot name not provided`,
    `Loading volume snapshot data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/volume_snapshot_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/Storage/VolumeSnapshotData.tsx frontend/tests/views/volume_snapshot_data.test.tsx`
  `git commit -m "feat(frontend): volume snapshot data view (new in 5.0; 4.1 tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `volumesnapshot-stub-removed-and-routes-wired`

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
  (next to the storage/resourcequota imports) and, after the resourcequota
  pair block, mirror the block:
  ```tsx
  <Route
    path="/storage/volumesnapshot"
    element={
      <ProtectedRoute>
        <VolumeSnapshotView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/storage/volumesnapshot/data"
    element={
      <ProtectedRoute>
        <VolumeSnapshotDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 20
  (`{ path: '/storage/volumesnapshot', title: 'VolumeSnapshot', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/storage/volumesnapshot'` to the `viewPaths` set in `expectedStubs()`
  (the test derives expected stubs from the nav minus `viewPaths`; without
  the addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Tasks 2–3 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON block
    uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire volumesnapshot routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_volume_snapshots.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/volume_snapshots.test.tsx tests/views/volume_snapshot_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` absent; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend kind) ──► Task 2 (list view) ──► Task 4 (routing)
                └────────► Task 3 (data view) ──┘
```

Tasks 2 and 3 are independent of each other (both consume Task 1); either
can run first or in parallel. Task 4 last (it removes the stub, so the views
must exist first).

## Rollback

Each task is one conventional commit and independently revertable (no schema,
no dependency, no public contract change). Reverting Task 4 is
self-contained (route + stub removal + test in one commit).
