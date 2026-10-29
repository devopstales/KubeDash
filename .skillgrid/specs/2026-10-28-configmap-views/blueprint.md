# ConfigMap Views (List + Data) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already ratified
for namespaced core kinds: secrets/resourcequotas/networkpolicies; the 4.1
template pair is the source of truth for the page shape; the data page's
metadata table + per-key table is a near-clone of the already-shipped
`Security/SecretData.tsx`).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny) before any
frontend exists; Task 2 is the list view; Task 3 the data view; Task 4 the
routing cleanup. Each task is independently revertable.

**Goal:** Resolve the nav leaf `/storage/configmap` to a real, SAR-gated,
read-only list + data pair — the 4.1 ConfigMap pages ported with the ratified
5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_configmaps` / `get_configmap` (kubernetes `CoreV1Api`, core
group, **namespaced** — the `list_secrets` / `get_resource_quota` pattern,
but WITHOUT the `data`-stripping that `list_secrets` applies, because a
ConfigMap's `data` is public and the list view renders a key count from it)
+ two dict rows (`_KINDS` / `_GETTERS`), NO new `__init__` attribute
(`self._v1` already exists). Frontend: two views (list cloned from
`Security/Secret.tsx` — namespaced, KubeDataTable — with a `Data Keys` count
column replacing the `Type` column; data cloned from `Security/SecretData.tsx`
for the CTable + KeyValueTable sub-tables + the full-object JSON block, with
the per-key `data` table replacing the base64-decoding `SecretValue` rows),
`ConfigMapItem` type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CoreV1Api` (already the client's `self._v1` — no
new attribute; the 4.1 code used the same API), Flask + Smorest (existing
route), React + CoreUI + TanStack Query + MSW (existing), no new npm/Python
dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/storage/configmap.html.j2`
(list: Name/Created — the name cell is a hidden-form POST link carrying
`configmap_name` + `ns_select`; card title EXACTLY `Configmaps List`),
`4.1:src/kubedash/templates/storage/configmap-data.html.j2` (data: Name/
Namespace/Kind/Created/Annotations/Labels/Version — 4.1's "Lables" typo on
line 70 — plus a per-key `data` table, each value in a `<pre><code>` block
with `<`/`>` escaped; NO full-object block; the data page is list-then-
filter by `configmap_name`), `4.1:src/kubedash/lib/k8s/storage.py:200`
(`k8sConfigmapListGet`: `CoreV1Api().list_namespaced_config_map(namespace,
_request_timeout=1)`, generates `name`/`created`/`annotations`(trimmed)/
`labels`/`data`/`version` — NOTE: no `binaryData`, no `status`),
`4.1:src/kubedash/blueprint/storage.py:277` (the list + data routes). In-
repo precedents —
`backend/app/services/k8s_client.py:757-793` (the `list_secrets` /
`get_secret` / `get_resource_quota` namespaced core-kind pattern to mirror —
the `list_namespaced_*` vs `list_*_for_all_namespaces` branch, 0/1-item
getter; `list_configmaps` differs from `list_secrets` ONLY in NOT popping
`data`/`binaryData`), `backend/app/api/resources.py` `_KINDS`/`_GETTERS` +
the `name` branch (line ~104-114, the `namespace = namespace or "default"`
fallback — the data page always sends its namespace so the fallback is never
used in practice), `backend/tests/api/test_resources.py` (the secrets
resourcequotas API tests to mirror: namespaced 200, all-namespaces branch,
get-by-name, SAR deny with namespace, binding 404, singular kind rejected),
`frontend/src/views/Security/Secret.tsx` (the namespaced list view to clone
— header-selected namespace, ALWAYS sends `?namespace=`, KubeDataTable,
`?selected=` bolding), `frontend/src/views/Security/SecretData.tsx` (the data
view to clone — CTable + `KeyValueTable` sub-tables + the `LAST_APPLIED`
filter + the per-key value rows; the `ConfigMapData` twin replaces
`SecretValue`'s base64-decode-with-eye with a plain `<pre><code>` value row,
and DROPS the `secretLanguage` heuristic — ConfigMap values are plain
strings), `frontend/tests/views/secrets.test.tsx` (the test pattern to clone,
including the KubeDataTable fake + the MSW `server.use` setup).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0009, ADR-0010, ADR-0020,
ADR-0021, ADR-0022. None created.

## Terms

None (the spec's vocabulary; "ConfigMap" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/configmaps?namespace=<ns>` → 200,
  `kind: "configmaps"`, items in `to_dict` snake_case form WITH `data`
  present (NOT stripped — unlike secrets), SAR-gated on `list configmaps`
  (core, the query namespace), 403 names the resource and the client call is
  never made on deny (`configmaps-list-200`, `configmaps-sar-denied`).
- Without `?namespace=` the list spans all namespaces
  (`list_config_map_for_all_namespaces` — the `list_secrets` branch)
  (`configmaps-list-all-namespaces`).
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the object, miss = `[]` (`configmaps-get-by-name`).
- The singular `configmap` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`configmap-kind-singular-rejected`).
- The list view fetches `/api/v1/clusters/<id>/resources/configmaps?namespace=<ns>`
  (namespace ALWAYS from `useClusterStore.selectedNamespace ?? 'default'`);
  card title EXACTLY `Configmaps List`; columns Name/Data Keys/Created; every
  name links to `/storage/configmap/data?name=<name>&namespace=<ns>`
  (`configmap-list-renders-rows-with-data-links`).
- Data Keys cell = the `data` key count as a plain integer (`0` when
  `data` is `{}`, `—` only when `data` is absent from the object); the cell
  is NOT computed from `binaryData`
  (`configmap-list-data-keys-column`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Name/Namespace/Kind/Created/Version/Labels/Annotations) + the Data table
  (one row per `data` entry, value in a `<pre><code>` block, `No data` when
  absent) + the JSON-highlighted full-object block, and treats a miss as the
  pinned state `No ConfigMap '<name>' found` — never an error style
  (`configmap-data-renders-detail`, `configmap-data-missing-data`,
  `configmap-data-not-found-state`).
- The data page's per-key value is rendered as plain `<pre><code>` text —
  NO base64 decode, NO language detection (the `secretLanguage` heuristic is
  Secret-only) (`configmap-data-value-is-plain-pre`).
- `/storage/configmap` is gone from `views/Stub/routes.ts`; both real views
  are routed; the nav leaf is byte-identical
  (`configmap-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `list_configmaps`,
  `get_configmap` (modified; no new `__init__` attribute).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_configmaps.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `ConfigMapItem` (modified).
- `frontend/src/views/Storage/ConfigMap.tsx` (new).
- `frontend/src/views/Storage/ConfigMapData.tsx` (new).
- `frontend/tests/views/configmaps.test.tsx` (new).
- `frontend/tests/views/configmap_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- `list_configmaps` MUST NOT pop `data` — the list view's `Data Keys` column
  is computed from `item.data` on the list response. A future refactor that
  "optimizes" the list by stripping `data` (copying `list_secrets`) silently
  breaks the Data Keys column to all `—`. The service method's docstring
  must say WHY it keeps `data` (the certainty rule: the field is load-bearing
  for the list view, not just the data page).
- The list view's name-link href is the SOLE producer of the data page's
  `?name=&namespace=` query strings — the data page parses the params, never
  constructs one (the secret contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an
  API error (the NOT_FOUND-as-throw-not-found-state pattern from
  `SecretData.tsx`, where the `queryFn` throws on a miss and the view
  renders the throw as the pinned state).
- The `to_dict` form is snake_case (a generated core-API model) — the type
  and cell readers use snake_case keys (`creation_timestamp`,
  `resource_version`, `data`, `binaryData` is camelCase in `to_dict` —
  verify: the kubernetes Python client's `to_dict` uses the API's camelCase
  for field names like `binaryData`, NOT snake_case; the `data` field is
  `data`, `metadata.creationTimestamp` is `creation_timestamp` (snake),
  `metadata.resourceVersion` is `resource_version` (snake) — the ConfigMap
  type must use `creation_timestamp`/`resource_version` (snake, the
  `metadata` fields) and `data` (the field name, unchanged)).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `CoreV1Api` is already the client's `self._v1`
  (NO new `__init__` attribute needed); the ConfigMap methods use the same
  `self._v1` attribute (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by `SecretData.tsx`; the `json` grammar is already registered
  there (registering again is harmless — the module is a singleton).
- Namespaced kind (core group, v1): the list URL carries `?namespace=` when
  given; the data URL carries `?name=&namespace=` (the page always sends
  both); SAR group = `""`, namespace = the query namespace or `None`.
- The `to_dict` form: `metadata` fields are snake_case
  (`creation_timestamp`, `resource_version`), the `data` field is `data`
  (the field name, unchanged), `binaryData` is `binaryData` (camelCase — the
  kubernetes client preserves the API's casing for non-metadata fields).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Configmaps List` (4.1's title, verbatim — the
  e2e-smoke contract; 4.1's casing is `Configmaps`, the nav label is
  `ConfigMaps` — keep both as-is).
- Pinned copy (do not reword): `No configmaps found`,
  `No ConfigMap '<name>' found`, `Error: configmap name not provided`,
  `No cluster selected.`, `Loading configmaps...`, `No labels`,
  `No annotations`, `No data`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_configmaps` next to
  `list_secrets` (line ~757), `get_configmap` next to `get_secret`
  (line ~774).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["configmaps"]` + `_GETTERS["configmaps"]`.
- `backend/tests/services/test_k8s_client_configmaps.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_configmaps` / `get_configmap`; 6 new tests.
- `frontend/src/lib/types.ts` (modify) — `ConfigMapItem` next to
  `K8sSecret`.
- `frontend/src/views/Storage/ConfigMap.tsx` (new) — namespaced layout from
  `Security/Secret.tsx` with the `Data Keys` column.
- `frontend/src/views/Storage/ConfigMapData.tsx` (new) — clone of
  `Security/SecretData.tsx` with the plain `<pre><code>` per-key value rows
  (no base64 decode, no `secretLanguage`).
- `frontend/tests/views/configmaps.test.tsx` (new).
- `frontend/tests/views/configmap_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the secret pair
  (line ~339-347) + the two view imports (after line 44).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 17
  (`/storage/configmap`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — configmaps kind (service + `_KINDS` + API tests)

**SATISFIES:** `configmaps-list-200`, `configmaps-list-all-namespaces`,
`configmaps-sar-denied`, `configmaps-binding-404`,
`configmap-kind-singular-rejected`, `configmaps-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_configmaps.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_configmaps(namespace: str | None) -> list[dict]`
  and `K8sClient.get_configmap(namespace: str, name: str) -> list[dict]` —
  the exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the secrets/resourcequotas tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_configmaps.py`, mirroring the
  secrets test pattern with `object.__new__` + `SimpleNamespace`:

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


  def test_list_configmaps_namespaced_keeps_data() -> None:
      """[configmaps-list-200] the namespaced branch uses
      ``list_namespaced_config_map`` and, UNLIKE ``list_secrets``, does NOT
      pop ``data`` — the list view's Data Keys column is computed from it."""
      seen: list[str] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "app-config", "namespace": "team-a",
                           "creation_timestamp": "2026-01-02T03:04:05Z",
                           "resource_version": "4242",
                           "labels": {"app": "web"},
                           "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}},
              "data": {"LOG_LEVEL": "info", "URL": "https://internal"},
          }
      )
      v1 = SimpleNamespace(
          list_namespaced_config_map=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_configmaps("team-a")
      assert result[0]["metadata"]["name"] == "app-config"
      assert result[0]["data"] == {"LOG_LEVEL": "info", "URL": "https://internal"}  # NOT stripped
      assert seen == ["team-a"]


  def test_list_configmaps_all_namespaces_when_namespace_none() -> None:
      """[configmaps-list-all-namespaces] ``None`` uses the all-namespaces
      call (the ``list_secrets`` branch)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "app-config"}})
      v1 = SimpleNamespace(
          list_config_map_for_all_namespaces=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_configmaps(None)
      assert result[0]["metadata"]["name"] == "app-config"
      assert seen == [True]


  def test_list_configmaps_maps_500_to_unreachable() -> None:
      def list_all() -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_config_map=list_all)).list_configmaps("team-a")


  def test_get_configmap_404_returns_empty_list() -> None:
      """[configmaps-get-by-name] a miss is ``[]`` (the ``get_secret``
      contract)."""
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=404)

      assert _client(SimpleNamespace(read_namespaced_config_map=read))
          .get_configmap("team-a", "ghost") == []


  def test_get_configmap_hit_returns_one_item_with_data() -> None:
      item = SimpleNamespace(to_dict=lambda: {
          "metadata": {"name": "app-config"},
          "data": {"LOG_LEVEL": "info"},
      })
      v1 = SimpleNamespace(read_namespaced_config_map=lambda name, ns: item)
      assert _client(v1).get_configmap("team-a", "app-config") == [
          {"metadata": {"name": "app-config"}, "data": {"LOG_LEVEL": "info"}}
      ]


  def test_get_configmap_other_api_error_maps_to_unreachable() -> None:
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_config_map=read))
          .get_configmap("team-a", "app-config")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_configmaps.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`:

  Next to `list_secrets` (line ~757):
  ```python
  def list_configmaps(self, namespace: str | None) -> list[dict[str, Any]]:
      """ConfigMap list in the standard kubernetes dict form (``to_dict``)
      for one namespace, or across all namespaces when the namespace is
      ``None`` (the ``list_secrets`` branch). UNLIKE ``list_secrets`` this
      does NOT pop ``data``/``binaryData``: a ConfigMap's ``data`` is public
      config (not a credential), and the list view's Data Keys column is
      computed from it — stripping it here would silently break that column.
      A transport ApiException maps to ``ClusterUnreachableError`` (502)."""
      try:
          resp = (
              self._v1.list_namespaced_config_map(namespace)
              if namespace
              else self._v1.list_config_map_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_configmaps", e)
          raise AssertionError("unreachable") from e
      return [cm.to_dict() for cm in resp.items]
  ```

  Next to `get_secret` (line ~774):
  ```python
  def get_configmap(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One ConfigMap (``data`` as plain strings, ``binaryData`` base64) as
      a 0/1-item list; ``[]`` on 404. Any other ApiException maps to
      ``ClusterUnreachableError`` (502), matching ``get_secret``'s transport
      contract."""
      try:
          return [self._v1.read_namespaced_config_map(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_configmap", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # ConfigMap (core, namespaced) — the 4.1-parity nav leaf resolved by the
  # configmap-views change (list + data views; ADR-0022 placement). The 4.1
  # route name was "configmap"; the API kind is the plural.
  "configmaps": ("list_configmaps", "configmaps", ""),
  ```
  in `_KINDS` (after the resourcequotas row; core group = `""`), and
  ```python
  "configmaps": "get_configmap",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the secrets/resourcequotas
  block):
  - FakeK8s gains:
    ```python
    def list_configmaps(self, namespace: str | None) -> list[dict]:
        # Namespaced (core v1): None -> all-namespaces branch (mirrors the
        # real K8sClient.list_configmaps). ``data`` is present (NOT stripped,
        # unlike secrets) — the list view's Data Keys column reads it.
        self.last_configmap_namespace = namespace
        return [
            {
                "metadata": {
                    "name": "app-config", "namespace": "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "resource_version": "4242",
                    "labels": {"app": "web"},
                    "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}", "owner": "platform"},
                },
                "data": {"LOG_LEVEL": "info", "URL": "https://internal"},
            },
            {"metadata": {"name": "empty-cm", "namespace": "team-a",
                          "creation_timestamp": "2026-01-03T00:00:00Z"},
             "data": {}},
            {"metadata": {"name": "no-data-cm", "namespace": "team-a",
                          "creation_timestamp": "2026-01-04T00:00:00Z"}},
        ]

    def get_configmap(self, namespace: str, name: str) -> list[dict]:
        return [cm for cm in self.list_configmaps(namespace)
                if cm["metadata"]["name"] == name]
    ```
  - Six new tests mirroring the secrets block, same docstring-tag style:
    - `test_list_configmaps_200` — `?namespace=team-a` → 200,
      `body["kind"] == "configmaps"`, items in `to_dict` form; assert the
      first item's `data` is present (NOT stripped).
    - `test_list_configmaps_all_namespaces` — no `?namespace=` → 200; assert
      the FakeK8s received `None` (the all-namespaces branch).
    - `test_list_configmaps_get_by_name` —
      `?name=app-config&namespace=team-a` → 1 item;
      `?name=ghost&namespace=team-a` → `items == []`.
    - `test_list_configmaps_sar_denied` — SAR denies; 403; assert
      `("list", "configmaps", "team-a", None, "")` in `asked` (the namespace
      forwarded, core group `""` — the load-bearing assertions).
    - `test_configmaps_binding_404` — cluster 999, unbound user → 404.
    - `test_configmap_kind_singular_rejected` —
      `/resources/configmap` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_configmaps.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_configmaps.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): configmaps kind (core, namespaced, SAR-gated, data kept)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `configmap-list-renders-rows-with-data-links`,
`configmap-list-data-keys-column`, `configmap-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Storage/ConfigMap.tsx`
- Test: `frontend/tests/views/configmaps.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `configmaps` list URL, namespaced).
- Produces: the data-page link
  `/storage/configmap/data?name=<name>&namespace=<ns>` — the SOLE producer
  of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` +
  `useClusterStore.selectedNamespace` (the secret view's seams).
- Deletion test: deleting the view → the route (Task 4) 404s / the test
  file fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `K8sSecret`:

  ```ts
  /** A ConfigMap item as returned by /api/v1/clusters/<id>/resources/configmaps (kubernetes to_dict; namespaced, core v1). ``data`` is present (NOT stripped, unlike secrets). */
  export interface ConfigMapItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      resource_version?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    /** Plain-string config values (public, not base64). */
    data?: Record<string, string>
    /** Base64-encoded binary values (camelCase — the kubernetes client preserves the API casing for non-metadata fields). */
    binaryData?: Record<string, string>
    [key: string]: unknown
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/configmaps.test.tsx`: clone
  `secrets.test.tsx` (the namespaced pattern + the KubeDataTable fake + the
  MSW `server.use` setup) and:
  - fixtures (the to_dict shape from Task 1's FakeK8s):
    ```ts
    const appConfig = {
      metadata: {
        name: 'app-config', namespace: 'team-a',
        creation_timestamp: '2026-01-02T03:04:05Z', resource_version: '4242',
        labels: { app: 'web' },
        annotations: { 'kubectl.kubernetes.io/last-applied-configuration': '{}', owner: 'platform' },
      },
      data: { LOG_LEVEL: 'info', URL: 'https://internal' },
    }
    const emptyCm = { metadata: { name: 'empty-cm', namespace: 'team-a',
      creation_timestamp: '2026-01-03T00:00:00Z' }, data: {} }
    const noDataCm = { metadata: { name: 'no-data-cm', namespace: 'team-a',
      creation_timestamp: '2026-01-04T00:00:00Z' } }
    ```
  - `renderAt` default path `/storage/configmap`; MSW handler on
    `*/api/v1/clusters/1/resources/configmaps`.
  - `list-renders-configmap-rows-with-data-links`: links `app-config` →
    `/storage/configmap/data?name=app-config&namespace=team-a`; fetch URL has
    `namespace=team-a`; heading EXACTLY `Configmaps List`; breadcrumb
    `Storage`; column headers `['Name', 'Data Keys', 'Created']`.
  - `list-data-keys-column`: `app-config` row Data Keys = `2`; `empty-cm` row
    Data Keys = `0` (NOT `—`); `no-data-cm` row Data Keys = `—` (`data`
    absent).
  - `list-never-counts-binarydata`: a ConfigMap with only `binaryData`
    (no `data`) → Data Keys = `—` (the count is `data`-only, per the brief).
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No configmaps found`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/configmaps.test.tsx`
  Expected: FAIL (cannot find module `src/views/Storage/ConfigMap`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/Storage/ConfigMap.tsx`: namespaced layout from
  `Security/Secret.tsx` with the `Data Keys` column:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement
    (Storage), the `?name=&namespace=` delta, the `Data Keys` column as the
    one ratified addition over 4.1's Name/Created-only list (the count is
    free — `data` is on the list read, NOT stripped, because a ConfigMap's
    `data` is public unlike a Secret's).
  - `const cluster = useClusterStore((s) => s.selectedCluster)`;
    `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`.
  - `type ConfigMapRow = { name: string; dataKeys: string; created: string }`:
    ```ts
    // The Data Keys column is the count of ``data`` keys (4.1's list showed
    // Name/Created only; this is the one ratified addition — the count is
    // free because ``data`` is on the list read, NOT stripped, unlike
    // secrets). ``0`` is a valid count (rendered as "0", NOT "—"); "—" only
    // when ``data`` is entirely absent. ``binaryData`` is NOT counted
    // (4.1's list read projected only ``data``).
    const toRow = (item: ConfigMapItem): ConfigMapRow => ({
      name: item.metadata?.name ?? '',
      dataKeys: item.data == null ? '—' : String(Object.keys(item.data).length),
      created: formatTimestamp(item.metadata?.creation_timestamp),
    })
    ```
  - query key `['configmaps', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/configmaps?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/storage/configmap/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Storage → ConfigMaps List; card title EXACTLY
    `Configmaps List` (4.1's casing, verbatim).
  - columns: Name (link) / Data Keys / Created.
  - pinned states: `No cluster selected.`, `Loading configmaps...`,
    `Error loading configmaps: {message}`, `No configmaps found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/configmaps.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Storage/ConfigMap.tsx frontend/tests/views/configmaps.test.tsx`
  `git commit -m "feat(frontend): configmap list view (4.1 port + data keys column)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `configmap-data-renders-detail`,
`configmap-data-missing-data`, `configmap-data-not-found-state`,
`configmap-data-missing-name`, `configmap-data-value-is-plain-pre`

**Files:**
- Create: `frontend/src/views/Storage/ConfigMapData.tsx`
- Test: `frontend/tests/views/configmap_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item list; `[]` =
  miss) and Task 2's link (the sole producer of the query strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/configmap_data.test.tsx`: clone
  `secrets.test.tsx`'s data-view section 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/configmaps?name=app-config&namespace=team-a`
    returning `{ kind: 'configmaps', items: [appConfig] }`; a miss handler
    (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/storage/configmap/data?name=app-config&namespace=team-a` — assert
    EXACTLY ONE fetch and that its URL has BOTH `name=app-config` and
    `namespace=team-a`; CTable rows: Name `app-config`, Namespace `team-a`,
    Kind `ConfigMap`, Version `4242`, a Created row (via
    `formatTimestamp`), a Labels sub-table `app: web`, an Annotations
    sub-table with BOTH the last-applied-configuration key AND `owner:
    platform` (rendered verbatim — the brief says `trimAnnotations` is NOT
    replicated, so 5.0 shows the kubectl noise the Secret view filters out);
    the Data table has rows `LOG_LEVEL: info` and `URL: https://internal`;
    the full-object block contains `"LOG_LEVEL": "info"` (the JSON block).
  - `data-value-is-plain-pre`: the Data table's value cells are
    `<pre>`-wrapped `<code>` (assert a `pre > code` descendant with the
    value text); NO eye/lock icon (no base64-decode toggle — ConfigMap
    values are plain strings, the `SecretValue` component's eye is
    Secret-only).
  - `data-missing-data`: a ConfigMap with no `data` field → the Data table
    shows `No data` (NOT the table at all, or an empty table with the
    `No data` copy).
  - `data-not-found-state`: `?name=ghost&namespace=team-a` → `No ConfigMap
    'ghost' found`; assert NO `.text-danger` node for it (a state, not an
    error).
  - `data-missing-name`: `/storage/configmap/data?namespace=team-a` (no
    name) → `Error: configmap name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]`.

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/configmap_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/Storage/ConfigMapData.tsx`: clone of
  `Security/SecretData.tsx` with the plain per-key value rows:
  - docstring: single `?name=&namespace=` fetch (no 4.1 list-then-filter),
    NOT_FOUND as a pinned STATE, the `json` hljs grammar as the truthful
    classifier (ratified 2026-10-28), the 4.1 deviations (the "Lables" typo
    NOT replicated, `trimAnnotations` NOT replicated — annotations render
    verbatim including last-applied-configuration, the per-key value is a
    plain `<pre><code>` with NO base64 decode and NO `secretLanguage`
    heuristic — ConfigMap `data` values are plain strings, unlike a
    Secret's base64 `data`).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read the params: `const name = params.get('name') ?? ''`;
    `const namespace = params.get('namespace') ??
    useClusterStore.getState().selectedNamespace ?? 'default'` (the page
    only renders with a cluster selected, so the store fallback is always
    available — the brief's R4 missing-namespace rule).
  - query key `['configmap-data', cluster?.id, name, namespace]`; enabled
    when `cluster != null && name !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/configmaps?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - **The `queryFn` throws on a miss** (the `SecretData.tsx` pattern):
    `const [cm] = r.data?.items ?? []; if (!cm) throw new Error(...)`.
    The view renders the throw as the pinned NOT_FOUND state (the
    `query.error` branch checks for the not-found message and renders it
    muted, not as `.text-danger`).
  - breadcrumb: Storage → ConfigMaps List (link) → `{name}`.
  - card title `Configmap Data` (4.1's title casing).
  - CTable rows (4.1's metadata row set, the "Lables" typo fixed,
    `trimAnnotations` NOT replicated): Name / Namespace (`namespace`) /
    Kind (`ConfigMap` — 4.1 hardcoded this) / Created
    (`formatTimestamp(cm?.metadata?.creation_timestamp)`) / Version
    (`cm?.metadata?.resource_version ?? '—'`) / Annotations (sub-table,
    `No annotations` when empty — rendered VERBATIM including
    last-applied-configuration, unlike the Secret view which filters it) /
    Labels (sub-table, `No labels` when empty).
  - **Data table** (a CTable, `No data` when `data` is absent or empty):
    one row per `data` entry, the key as the row label, the value in a
    `<pre><code>` block with `white-space: pre-wrap; word-break: break-word`
    (4.1's `<pre><code>` block, re-implemented — NO base64 decode, NO
    language detection, NO eye/lock toggle):
    ```tsx
    const data = Object.entries(cm?.data ?? {})
    // 4.1's per-key data table, one row per entry. The value is a plain
    // string (NOT base64, unlike a Secret's data) — no decode, no
    // secretLanguage heuristic, no eye toggle. A <pre><code> block with
    // pre-wrap + break-word (4.1's escaping of < and > is implicit in
    // React's text rendering — no manual escaping needed).
    {data.length > 0 ? (
      <CTable bordered className="mb-0">
        <tbody>
          {data.map(([key, value]) => (
            <tr key={key}>
              <th scope="row" className="text-nowrap">{key}:</th>
              <td className="w-100">
                <pre className="mb-0" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  <code>{value}</code>
                </pre>
              </td>
            </tr>
          ))}
        </tbody>
      </CTable>
    ) : (
      <div className="text-muted">No data</div>
    )}
    ```
  - full-object block: `JSON.stringify(cm, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No ConfigMap '{name}' found`,
    `Error: configmap name not provided`, `Loading configmap data...`,
    `No data`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/configmap_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/Storage/ConfigMapData.tsx frontend/tests/views/configmap_data.test.tsx`
  `git commit -m "feat(frontend): configmap data view (4.1 tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `configmap-stub-removed-and-routes-wired`

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
  (next to the secret imports, after line 44) and, after the secret pair
  (line ~347), mirror the block:
  ```tsx
  <Route
    path="/storage/configmap"
    element={
      <ProtectedRoute>
        <ConfigMapView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/storage/configmap/data"
    element={
      <ProtectedRoute>
        <ConfigMapDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 17
  (`{ path: '/storage/configmap', title: 'ConfigMaps', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/storage/configmap'` to the `viewPaths` set in `expectedStubs()` (the
  test derives expected stubs from the nav minus `viewPaths`; without the
  addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Tasks 2–3 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON
    block uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire configmap routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_configmaps.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/configmaps.test.tsx tests/views/configmap_data.test.tsx tests/views/Stub.test.tsx` — green.
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
