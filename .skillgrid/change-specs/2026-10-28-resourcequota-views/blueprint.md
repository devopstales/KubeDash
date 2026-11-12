# ResourceQuota Views — Implementation Blueprint (steps, files, verification)

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

**Goal:** Resolve the nav leaf `/other-resource/resource-quota` to a real,
SAR-gated, read-only list + data pair — the 4.1 ResourceQuota pages ported
with the ratified 5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`, and already threads
`namespace` (namespaced kinds: secrets, networkpolicies). This change adds
ONE kind: `K8sClient.list_resource_quotas` / `get_resource_quota` (kubernetes
`CoreV1Api`, core group, namespaced with the all-namespaces branch) + two
dict rows (`_KINDS` / `_GETTERS`). Frontend: two views (list cloned from
NetworkPolicy.tsx for the namespace handling, data cloned from
PriorityClassData.tsx for the CTable+JSON block), `ResourceQuotaItem` type,
App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CoreV1Api` (already a dependency, already used in
`K8sClient.__init__` as `self._v1`), Flask + Smorest (existing route), React
+ CoreUI + TanStack Query + MSW (existing), no new npm/Python dependency
(air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/other-resources/resource-quota.html.j2`
(list: Name/Namespace/Request/Limit badges),
`4.1:src/kubedash/templates/other-resources/resource-quota-data.html.j2`
(data: Name/Created/Namespace/Creation/Selectors/Scopes/Annotations/Labels/
Status table — note the duplicate Creation row and the unguarded
`status.used["..."]` index), `4.1:src/kubedash/lib/k8s/other.py:203`
(`k8sQuotaListGet`: `list_namespaced_resource_quota`, the
scope_selector overwrite bug, `trimAnnotations`). In-repo precedents —
`backend/app/services/k8s_client.py:722-746` (the `list_secrets`/`get_secret`
namespaced pair to mirror), `backend/app/api/resources.py`
`_KINDS`/`_GETTERS` + the `name` branch (line ~98-110, the
`namespace = namespace or "default"` fallback),
`frontend/src/views/Security/NetworkPolicy.tsx` (the namespaced list view:
`selectedNamespace ?? 'default'`, namespace in URL + query key),
`frontend/src/views/OtherResource/PriorityClassData.tsx` (the data view:
CTable + labels/annotations sub-tables + JSON block),
`frontend/tests/views/network_policies.test.tsx` +
`priority_class_data.test.tsx` (the test patterns to clone).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0010, ADR-0020, ADR-0021,
ADR-0022. None created.

## Terms

None (the spec's vocabulary; "ResourceQuota" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/resourcequotas?namespace=team-a` → 200,
  `kind: "resourcequotas"`, items in `to_dict` form, SAR-gated on
  `list resourcequotas` (core, namespace `team-a`), 403 names the resource
  and the client call is never made on deny
  (`resourcequotas-list-200-in-namespace`, `resourcequotas-sar-denied`).
- Without a namespace param the client uses
  `list_resource_quota_for_all_namespaces`
  (`resourcequotas-list-all-namespaces-without-param`).
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the object, miss = `[]` (`resourcequotas-get-by-name`).
- The singular `resourcequota` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (the 4.1 route name was singular; the API
  kind is the plural) (`resourcequota-kind-singular-rejected`).
- The list view fetches
  `/api/v1/clusters/<id>/resources/resourcequotas?namespace=<ns>` with
  `<ns> = selectedNamespace ?? 'default'`; card title EXACTLY `Resource
  Quota List`; columns Name/Namespace/Requests/Limits/Created; every name
  links to the data page with BOTH `name` and `namespace`
  (`resourcequota-list-renders-rows-with-data-links`).
- Request/Limit cells render the four 4.1 dimensions as `used / hard`; a
  missing key renders `—` (`resourcequota-list-request-limit-cells`,
  `resourcequota-list-missing-status-keys`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Name/Created/Namespace/Scope/Labels/Annotations) + the Status table
  (Resource/Used/Hard Limit, the four 4.1 dimensions) + a JSON-highlighted
  full-object block, and treats a miss as the pinned state
  `No ResourceQuota '<name>' found` — never an error style
  (`resourcequota-data-renders-detail`, `resourcequota-data-not-found-state`).
- `/other-resource/resource-quota` is gone from `views/Stub/routes.ts`; both
  real views are routed; the nav leaf is byte-identical
  (`resourcequota-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — the two methods (modified; `self._v1`
  already exists, no new attribute).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_resourcequotas.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `ResourceQuotaItem` (modified).
- `frontend/src/views/OtherResource/ResourceQuota.tsx` (new).
- `frontend/src/views/OtherResource/ResourceQuotaData.tsx` (new).
- `frontend/tests/views/resource_quotas.test.tsx` (new).
- `frontend/tests/views/resource_quota_data.test.tsx` (new).
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
  API error.
- The `name` branch of the generic route falls back to `namespace = "default"`
  when no namespace param is present — the data page ALWAYS sends the
  namespace (it has it from the link), so the fallback never fires for this
  view; the test suite pins that the data URL carries the namespace.
- `Stub.test.tsx` counts/labels the stub routes: removing the route without
  updating the test is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `CoreV1Api` is already vendored and already
  instantiated as `self._v1` (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Namespaced kind (core group): the list URL and the data URL carry
  `namespace=`; SAR namespace = the query namespace or `None`; the client
  methods use the `list_namespaced_resource_quota(namespace)` /
  `list_resource_quota_for_all_namespaces()` branch (the `list_secrets`
  pattern).
- The four quota dimensions are EXACTLY `limits.cpu`, `limits.memory`,
  `requests.cpu`, `requests.memory` (4.1's set, 4.1's order in the Status
  table). Missing values render `—`.
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Resource Quota List` (4.1's title, verbatim — the
  e2e-smoke contract).
- Pinned copy (do not reword): `No resource quotas found`,
  `No ResourceQuota '<name>' found`,
  `Error: resource quota name not provided`, `No cluster selected.`,
  `Loading resource quotas...`, `No labels`, `No annotations`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson) —
  type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_resource_quotas`
  next to `list_secrets` (line ~722), `get_resource_quota` next to
  `get_secret` (line ~739). No `__init__` change: `self._v1` is the
  `CoreV1Api`.
- `backend/app/api/resources.py` (modify) — `_KINDS["resourcequotas"]` +
  `_GETTERS["resourcequotas"]`.
- `backend/tests/services/test_k8s_client_resourcequotas.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_resource_quotas` / `get_resource_quota`; 6 new tests.
- `frontend/src/lib/types.ts` (modify) — `ResourceQuotaItem` next to
  `PriorityClassItem` / the security types.
- `frontend/src/views/OtherResource/ResourceQuota.tsx` (new) — namespace
  handling from NetworkPolicy.tsx, layout from PriorityClass.tsx.
- `frontend/src/views/OtherResource/ResourceQuotaData.tsx` (new) — clone of
  PriorityClassData.tsx + the 4.1 Status table.
- `frontend/tests/views/resource_quotas.test.tsx` (new).
- `frontend/tests/views/resource_quota_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (line ~381) + the two view imports.
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 26
  (`/other-resource/resource-quota`).
- `frontend/tests/views/Stub.test.tsx` (modify) — drop the Resource Quota
  expectation (route count / titles).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — resourcequotas kind (service + `_KINDS` + API tests)

**SATISFIES:** `resourcequotas-list-200-in-namespace`,
`resourcequotas-list-all-namespaces-without-param`,
`resourcequotas-sar-denied`, `resourcequotas-binding-404`,
`resourcequota-kind-singular-rejected`, `resourcequotas-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_resourcequotas.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_resource_quotas(namespace: str | None) -> list[dict]`
  and `K8sClient.get_resource_quota(namespace: str, name: str) -> list[dict]`
  — the exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the secrets/networkpolicies tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s with
  `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_resourcequotas.py`, mirroring the
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


  def test_list_resource_quotas_in_namespace() -> None:
      """[resourcequotas-list-200-in-namespace] a namespace is forwarded to
      ``list_namespaced_resource_quota`` (the ``list_secrets`` pattern)."""
      seen: list[object] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "compute", "namespace": "team-a"},
              "status": {
                  "hard": {"requests.cpu": "4", "limits.memory": "20Gi"},
                  "used": {"requests.cpu": "2", "limits.memory": "8Gi"},
              },
          }
      )
      v1 = SimpleNamespace(
          list_namespaced_resource_quota=lambda namespace: (
              seen.append(namespace),
              SimpleNamespace(items=[item]),
          )[1],
      )
      result = _client(v1).list_resource_quotas("team-a")
      assert result[0]["metadata"]["namespace"] == "team-a"
      assert seen == ["team-a"]  # the namespace is forwarded, not dropped


  def test_list_resource_quotas_all_namespaces_without_namespace() -> None:
      """[resourcequotas-list-all-namespaces-without-param] ``None`` uses
      the all-namespaces call (the ``list_secrets`` branch)."""
      seen: list[object] = []
      v1 = SimpleNamespace(
          list_resource_quota_for_all_namespaces=lambda: (
              seen.append(True),
              SimpleNamespace(items=[]),
          )[1],
      )
      assert _client(v1).list_resource_quotas(None) == []
      assert seen == [True]


  def test_list_resource_quotas_maps_500_to_unreachable() -> None:
      def list_all(namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_resource_quota=list_all)).list_resource_quotas("team-a")


  def test_get_resource_quota_404_returns_empty_list() -> None:
      """[resourcequotas-get-by-name] a miss is ``[]``, mirroring
      ``get_secret``'s 0/1-item contract."""
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=404)

      v1 = SimpleNamespace(read_namespaced_resource_quota=read)
      assert _client(v1).get_resource_quota("team-a", "ghost") == []


  def test_get_resource_quota_hit_returns_one_item() -> None:
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "compute"}})
      v1 = SimpleNamespace(read_namespaced_resource_quota=lambda name, namespace: item)
      assert _client(v1).get_resource_quota("team-a", "compute") == [
          {"metadata": {"name": "compute"}}
      ]


  def test_get_resource_quota_other_api_error_maps_to_unreachable() -> None:
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_resource_quota=read)).get_resource_quota("team-a", "compute")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_resourcequotas.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`, next to
  their secrets twins:

  Next to `list_secrets` (line 722):
  ```python
  def list_resource_quotas(self, namespace: str | None) -> list[dict[str, Any]]:
      """ResourceQuota list in the standard kubernetes dict form
      (``to_dict``) for one namespace, or across all namespaces when the
      namespace is ``None`` (the ``list_secrets`` branch). No field
      stripping — the view renders ``status.used``/``status.hard`` and the
      data page the full object. A transport ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          resp = (
              self._v1.list_namespaced_resource_quota(namespace)
              if namespace
              else self._v1.list_resource_quota_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_resource_quotas", e)
          raise AssertionError("unreachable") from e
      return [q.to_dict() for q in resp.items]
  ```

  Next to `get_secret` (line 739):
  ```python
  def get_resource_quota(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One ResourceQuota as a 0/1-item list; ``[]`` on 404. Any other
      ApiException maps to ``ClusterUnreachableError`` (502), matching
      ``get_secret``'s transport contract."""
      try:
          return [self._v1.read_namespaced_resource_quota(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_resource_quota", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "resourcequotas": ("list_resource_quotas", "resourcequotas", ""),
  ```
  in `_KINDS` (after the priorityclasses row; core group = `""`), and
  ```python
  "resourcequotas": "get_resource_quota",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py`:
  - FakeK8s gains (mirror the priorityclasses FakeK8s block, lines 296-317):
    ```python
    def list_resource_quotas(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (core): the namespace is forwarded (the real
        # K8sClient.list_resource_quotas pattern).
        quota = {
            "metadata": {
                "name": "compute",
                "namespace": namespace or "team-a",
                "creation_timestamp": "2026-01-02T03:04:05Z",
                "labels": {"team": "a"},
                "annotations": {"quota.kubernetes.io/managed-by": "kubedash"},
            },
            "spec": {
                "hard": {
                    "requests.cpu": "4",
                    "requests.memory": "10Gi",
                    "limits.cpu": "8",
                    "limits.memory": "20Gi",
                },
                "scopes": ["NotBestEffort"],
            },
            "status": {
                "hard": {
                    "requests.cpu": "4",
                    "requests.memory": "10Gi",
                    "limits.cpu": "8",
                    "limits.memory": "20Gi",
                },
                "used": {
                    "requests.cpu": "2",
                    "requests.memory": "4Gi",
                    "limits.cpu": "4",
                    "limits.memory": "8Gi",
                },
            },
        }
        return [quota]

    def get_resource_quota(self, namespace: str, name: str) -> list[dict]:
        if name == "compute":
            return self.list_resource_quotas(namespace)
        return []
    ```
  - Six new tests mirroring the priorityclasses block (lines 1247–1334),
    same docstring-tag style:
    - `test_list_resourcequotas_200_in_namespace` — 200,
      `body["kind"] == "resourcequotas"`, one item in `team-a`; assert the
      FakeK8s received `namespace="team-a"`.
    - `test_list_resourcequotas_all_namespaces_without_param` — no
      `namespace` param → 200; assert the FakeK8s received `None` (the
      all-namespaces branch).
    - `test_list_resourcequotas_get_by_name` — `?name=compute&namespace=team-a`
      → 1 item; `?name=ghost&namespace=team-a` → `items == []`.
    - `test_list_resourcequotas_sar_denied` — SAR denies; 403; assert
      `("list", "resourcequotas", "team-a", None, "")` in `asked` (namespace
      `team-a`, core group — the load-bearing assertions).
    - `test_resourcequotas_binding_404` — cluster 999, unbound user → 404.
    - `test_resourcequota_kind_singular_rejected` —
      `/resources/resourcequota` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_resourcequotas.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_resourcequotas.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): resourcequotas kind (core, namespaced, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `resourcequota-list-renders-rows-with-data-links`,
`resourcequota-list-request-limit-cells`,
`resourcequota-list-missing-status-keys`, `resourcequota-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/OtherResource/ResourceQuota.tsx`
- Test: `frontend/tests/views/resource_quotas.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `resourcequotas` list URL, namespaced).
- Produces: the data-page link
  `/other-resource/resource-quota/data?name=<name>&namespace=<ns>` — the
  SOLE producer of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedNamespace`
  (no new seam).
- Deletion test: deleting the view → the route (Task 4) 404s / the test
  file fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `PriorityClassItem`:

  ```ts
  /** A ResourceQuota item as returned by /api/v1/clusters/<id>/resources/resourcequotas (kubernetes to_dict, snake_case; namespaced, core group). */
  export interface ResourceQuotaItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      hard?: Record<string, string>
      scopes?: string[]
      scope_selector?: unknown
    }
    status?: {
      hard?: Record<string, string>
      used?: Record<string, string>
    }
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/resource_quotas.test.tsx`: clone
  `network_policies.test.tsx` 1:1 (KubeDataTable fake included) with the
  network_policies namespace setup (`selectProd` sets
  `selectedNamespace: 'team-a'`), and:
  - fixture `compute` (the to_dict shape, all four dimensions in
    `status.used` + `status.hard`):
    ```ts
    const compute = {
      apiVersion: 'v1',
      kind: 'ResourceQuota',
      metadata: {
        name: 'compute',
        namespace: 'team-a',
        creation_timestamp: '2026-01-02T03:04:05Z',
        labels: { team: 'a' },
        annotations: { 'quota.kubernetes.io/managed-by': 'kubedash' },
      },
      spec: {
        hard: {
          'requests.cpu': '4',
          'requests.memory': '10Gi',
          'limits.cpu': '8',
          'limits.memory': '20Gi',
        },
        scopes: ['NotBestEffort'],
      },
      status: {
        hard: {
          'requests.cpu': '4',
          'requests.memory': '10Gi',
          'limits.cpu': '8',
          'limits.memory': '20Gi',
        },
        used: {
          'requests.cpu': '2',
          'requests.memory': '4Gi',
          'limits.cpu': '4',
          'limits.memory': '8Gi',
        },
      },
    }
    ```
  - `renderAt` default path `/other-resource/resource-quota`; MSW handler on
    `*/api/v1/clusters/1/resources/resourcequotas`.
  - `list-renders-resource-quotas-with-data-links`: link `compute` →
    `/other-resource/resource-quota/data?name=compute&namespace=team-a`;
    fetch URL EXACTLY
    `/api/v1/clusters/1/resources/resourcequotas?namespace=team-a`; heading
    EXACTLY `Resource Quota List`; breadcrumb `Other Resources`; column
    headers `['Name', 'Namespace', 'Requests', 'Limits', 'Created']`; row
    shows `team-a` (namespace); created cell via `formatTimestamp` (no raw
    ISO `T` in the cell, matches `/2026/`).
  - `list-request-limit-cells`: the Requests cell text contains
    `requests.cpu: 2 / 4` and `requests.memory: 4Gi / 10Gi`; the Limits cell
    contains `limits.cpu: 4 / 8` and `limits.memory: 8Gi / 20Gi`.
  - `list-missing-status-keys`: a second fixture `objects` with
    `status.used = {'pods': '10'}` and `status.hard = {'pods': '20'}` (NO
    cpu/memory keys) → its Limits cell shows `limits.cpu: — / —` and its
    Requests cell shows `requests.memory: — / —` (no throw, no blank).
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-error-state`: 403 `RBAC_DENIED` →
    `Error loading resource quotas: RBAC_DENIED: list on resourcequotas`.
  - `list-empty-state`: `items: []` → `No resource quotas found`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/resource_quotas.test.tsx`
  Expected: FAIL (cannot find module
  `src/views/OtherResource/ResourceQuota`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/OtherResource/ResourceQuota.tsx`: layout from
  `PriorityClass.tsx`, namespace handling from `NetworkPolicy.tsx`:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement,
    the `?name=&namespace=` delta, the certainty rule for missing status
    keys.
  - `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`
  - `type QuotaRow = { name, namespace, requests: string[], limits: string[], created }`
    with a dimension helper:
    ```ts
    // 4.1's four dimensions, 4.1's order. A key missing from status.used or
    // status.hard renders "—" (certainty rule: 4.1 would KeyError the
    // template; 5.0 never guesses).
    const DIMENSIONS = [
      ['requests', 'requests.cpu', 'requests.memory'],
      ['limits', 'limits.cpu', 'limits.memory'],
    ] as const

    const dimensionCells = (
      item: ResourceQuotaItem,
      kind: 'requests' | 'limits',
    ): string[] => {
      const [_, ...keys] = DIMENSIONS.find(([, , ...]) => ...) // or inline:
      ...
    }
    ```
    (Implementation note: two small functions `requestCells(item)` /
    `limitCells(item)` are clearer than a generic — each returns
    `['requests.cpu: 2 / 4', 'requests.memory: 4Gi / 10Gi']` with `—` for
    absent keys:
    ```ts
    const cell = (
      item: ResourceQuotaItem,
      key: string,
    ): string => {
      const used = item.status?.used?.[key] ?? '—'
      const hard = item.status?.hard?.[key] ?? '—'
      return `${key}: ${used} / ${hard}`
    }
    ```
  - `toRow`:
    ```ts
    const toRow = (item: ResourceQuotaItem): QuotaRow => ({
      name: item.metadata?.name ?? '',
      namespace: item.metadata?.namespace ?? namespace,
      requests: [cell(item, 'requests.cpu'), cell(item, 'requests.memory')],
      limits: [cell(item, 'limits.cpu'), cell(item, 'limits.memory')],
      created: formatTimestamp(item.metadata?.creation_timestamp),
    })
    ```
  - query key `['resourcequotas', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/resourcequotas?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/other-resource/resource-quota/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(row.namespace)}`
    (the row's OWN namespace — an all-namespaces list would carry mixed
    namespaces; the link must follow the row, not the store).
  - breadcrumb: Other Resources → Resource Quota List; card title EXACTLY
    `Resource Quota List`.
  - columns: Name (link) / Namespace / Requests (cells joined by `<br/>`) /
    Limits (cells joined by `<br/>`) / Created.
  - pinned states: `No cluster selected.`, `Loading resource quotas...`,
    `Error loading resource quotas: {message}`, `No resource quotas found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/resource_quotas.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/OtherResource/ResourceQuota.tsx frontend/tests/views/resource_quotas.test.tsx`
  `git commit -m "feat(frontend): resource quota list view (4.1 port, namespaced)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `resourcequota-data-renders-detail`,
`resourcequota-data-not-found-state`, `resourcequota-data-missing-name`

**Files:**
- Create: `frontend/src/views/OtherResource/ResourceQuotaData.tsx`
- Test: `frontend/tests/views/resource_quota_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item list; `[]` =
  miss) and Task 2's link (the sole producer of the `?name=&namespace=`
  strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/resource_quota_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/resourcequotas?name=compute&namespace=team-a`
    returning `{ kind: 'resourcequotas', items: [compute] }`; a miss handler
    (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/other-resource/resource-quota/data?name=compute&namespace=team-a` —
    assert EXACTLY ONE fetch and that its URL has `name=compute` AND
    `namespace=team-a`; CTable rows: Name `compute`, Namespace `team-a`,
    Kind implied (card title `Resource Quota Data`), Scope `NotBestEffort`,
    Labels sub-table `team: a`, Annotations sub-table
    `quota.kubernetes.io/managed-by: kubedash`, a Created row (via
    `formatTimestamp`); the Status table has header
    `['Resource', 'Used', 'Hard Limit']` and rows `limits.cpu 4 / 8`,
    `limits.memory 8Gi / 20Gi`, `requests.cpu 2 / 4`,
    `requests.memory 4Gi / 10Gi` (the 4.1 order); the full-object block
    contains `"handler"` NO — contains `"scopes": ["NotBestEffort"]` (the
    JSON block).
  - `data-missing-status-keys`: a quota with only `pods` in status → its
    Status rows show `—` for the four cpu/memory dimensions (no throw).
  - `data-not-found-state`: `?name=ghost&namespace=team-a` →
    `No ResourceQuota 'ghost' found`; assert NO `.text-danger` node for it
    (a state, not an error).
  - `data-missing-name`: `/other-resource/resource-quota/data` (no param) →
    `Error: resource quota name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/resource_quota_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/OtherResource/ResourceQuotaData.tsx`: clone of
  `PriorityClassData.tsx` + the 4.1 Status table:
  - docstring: single `?name=&namespace=` fetch (no 4.1 list-then-filter),
    the four 4.1 dimensions with `—` for missing keys (certainty rule),
    NOT_FOUND as a pinned STATE, the `json` hljs grammar as the truthful
    classifier (ratified 2026-10-28), the 4.1 deviations (no Selectors
    table, no trimAnnotations, one Created row).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read both params: `const name = params.get('name') ?? ''`,
    `const namespace = params.get('namespace') ?? ''`.
  - query key `['resource-quota-data', cluster?.id, namespace, name]`;
    enabled when `cluster != null && name !== '' && namespace !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/resourcequotas?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Other Resources → Resource Quota List (link) → `{name}`.
  - card title `Resource Quota Data`.
  - CTable rows: Name / Created / Namespace / Scope
    (`spec.scopes?.join(', ') || '—'`, badge-style) / Labels / Annotations
    (sub-tables, `No labels` / `No annotations` when empty — the
    priorityclass twin's shape).
  - Status table (nested CTable, header Resource/Used/Hard Limit), the four
    4.1 dimensions in 4.1's order:
    ```tsx
    const STATUS_DIMENSIONS = ['limits.cpu', 'limits.memory', 'requests.cpu', 'requests.memory'] as const
    // row: <td>{dim}</td><td>{item.status?.used?.[dim] ?? '—'}</td><td>{item.status?.hard?.[dim] ?? '—'}</td>
    ```
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No ResourceQuota '{name}' found`,
    `Error: resource quota name not provided`,
    `Loading resource quota data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/resource_quota_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/OtherResource/ResourceQuotaData.tsx frontend/tests/views/resource_quota_data.test.tsx`
  `git commit -m "feat(frontend): resource quota data view (4.1 tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `resourcequota-stub-removed-and-routes-wired`

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
  (next to the priorityclass imports) and, after the priorityclass pair
  (line 381), mirror the block:
  ```tsx
  <Route
    path="/other-resource/resource-quota"
    element={
      <ProtectedRoute>
        <ResourceQuotaView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/other-resource/resource-quota/data"
    element={
      <ProtectedRoute>
        <ResourceQuotaDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 26
  (`{ path: '/other-resource/resource-quota', title: 'Resource Quota', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — remove the Resource Quota
  expectation (route count or title list) per that file's structure;
  re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

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
  `git commit -m "feat(frontend): wire resource-quota routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_resourcequotas.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/resource_quotas.test.tsx tests/views/resource_quota_data.test.tsx tests/views/Stub.test.tsx` — green.
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
