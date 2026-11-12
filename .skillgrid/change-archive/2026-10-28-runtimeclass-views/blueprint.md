# RuntimeClass Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files
> to touch, tests, and verification. The product *why* lives in `briefing.md`
> and the ADR manifest in `adr.md`. This blueprint is pure-technical and cites
> them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already
ratified twice: priorityclasses + CRDs).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service method → `_KINDS` row → API route → SAR deny) before any
frontend exists; Task 2 is the list view; Task 3 the data view; Task 4 the
routing cleanup. Each task is independently revertable.

**Goal:** Resolve the dead nav leaf `/other-resource/runtimeclass` to a real,
SAR-gated, read-only list + data pair (4.1 parity in placement and RBAC
treatment; 5.0 PriorityClass parity in shape).

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_runtime_classes` / `get_runtime_class` (kubernetes
`NodeV1Api`, `node.k8s.io/v1`, cluster-scoped) + two dict rows
(`_KINDS` / `_GETTERS`). Frontend: two views cloned from PriorityClass
(list + data), `RuntimeClassItem` type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `NodeV1Api` (already a dependency), Flask + Smorest
(existing route), React + CoreUI + TanStack Query + MSW (existing), no new
npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/other-resources/`
(NO runtimeclass template: dead nav link), `4.1:src/kubedash/functions/k8s.py`
(`runtimeclasses` in the reader/admin ClusterRole resource lists). In-repo
precedents — `backend/app/api/resources.py` `_KINDS`/`_GETTERS`,
`backend/app/services/k8s_client.py:264-273,775-786` (the priorityclass pair
to mirror), `frontend/src/views/OtherResource/PriorityClass.tsx` +
`PriorityClassData.tsx` (the views to clone),
`frontend/tests/views/priority_classes.test.tsx` +
`priority_class_data.test.tsx` (the test fakes to clone),
`backend/tests/services/test_k8s_client_priorityclasses.py` (the
`object.__new__` pattern), `backend/tests/api/test_resources.py:296-317`
(the FakeK8s methods to extend).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0010, ADR-0020, ADR-0021,
ADR-0022. None created.

## Terms

None (the spec's vocabulary; "RuntimeClass" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET /api/v1/clusters/<id>/resources/runtimeclasses` → 200,
  `kind: "runtimeclasses"`, items in `to_dict` form, SAR-gated on
  `list runtimeclasses` (node.k8s.io, namespace `None`), 403 names the
  resource and the client call is never made on deny
  (`runtimeclasses-list-200`, `runtimeclasses-list-ignores-namespace`,
  `runtimeclasses-sar-denied`).
- `?name=` returns a 0/1-item list through the SAME route — hit = the object,
  miss = `[]` (`runtimeclasses-get-by-name`).
- The singular `runtimeclass` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (the 4.1 nav/route name; the API kind is the
  plural) (`runtimeclass-kind-singular-rejected`).
- The list view's card title is EXACTLY `Runtime Classes`, columns are
  Name/Handler/Overwrite Node Sel No Toleration/Pod Level Overhead/Created,
  and every name links to the data page (`runtimeclass-list-renders-rows-with-data-links`).
- `pod_level_overhead` renders `100m / 128Mi` when present, `—` when absent
  (`runtimeclass-list-overhead-rendering`).
- The data view fetches ONCE with `?name=` (no namespace param), renders the
  CTable + a JSON-highlighted full-object block, and treats a miss as the
  pinned state `No RuntimeClass '<name>' found` — never an error style
  (`runtimeclass-data-renders-detail`, `runtimeclass-data-not-found-state`).
- `/other-resource/runtimeclass` is gone from `views/Stub/routes.ts`; both
  real views are routed; the nav leaf is byte-identical
  (`runtimeclass-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — the two methods + the `_node`
  attribute (modified, not new).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_runtimeclasses.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `RuntimeClassItem` (modified).
- `frontend/src/views/OtherResource/RuntimeClass.tsx` (new).
- `frontend/src/views/OtherResource/RuntimeClassData.tsx` (new).
- `frontend/tests/views/runtime_classes.test.tsx` (new).
- `frontend/tests/views/runtime_class_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- The list view's name-link href is the SOLE producer of the data page's
  `?name=` query strings — the data page parses the param, never constructs
  one (the priorityclass contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an
  API error.
- `Stub.test.tsx` counts/labels the stub routes: removing the route without
  updating the test is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `kubernetes.NodeV1Api` is already vendored
  (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Cluster-scoped kind: NO namespace in any URL, SAR namespace is `None`,
  the client methods accept-and-ignore the namespace argument (the
  `list_nodes` / `list_priority_classes` pattern).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Runtime Classes` (e2e-smoke contract).
- Pinned copy (do not reword): `No runtime classes found`,
  `No RuntimeClass '<name>' found`,
  `Error: runtime class name not provided`, `No cluster selected.`,
  `Loading runtime classes...`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson) —
  type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `__init__` gains
  `self._node = k8s_client.NodeV1Api(api_client)` (line ~226, next to
  `self._scheduling`); `list_runtime_classes` + `get_runtime_class` next to
  their priorityclass twins.
- `backend/app/api/resources.py` (modify) — `_KINDS["runtimeclasses"]` +
  `_GETTERS["runtimeclasses"]`.
- `backend/tests/services/test_k8s_client_runtimeclasses.py` (new) —
  `object.__new__` + `SimpleNamespace` fake, mirrors the priorityclasses
  file 1:1.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_runtime_classes` / `get_runtime_class`; 6 new tests mirroring the
  priorityclasses block (lines 1247–1334).
- `frontend/src/lib/types.ts` (modify) — `RuntimeClassItem` next to
  `PriorityClassItem`.
- `frontend/src/views/OtherResource/RuntimeClass.tsx` (new) — clone of
  PriorityClass.tsx.
- `frontend/src/views/OtherResource/RuntimeClassData.tsx` (new) — clone of
  PriorityClassData.tsx.
- `frontend/tests/views/runtime_classes.test.tsx` (new) — clone of
  priority_classes.test.tsx (KubeDataTable fake included).
- `frontend/tests/views/runtime_class_data.test.tsx` (new) — clone of
  priority_class_data.test.tsx.
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (lines 366–381) + the two view imports.
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 28.
- `frontend/tests/views/Stub.test.tsx` (modify) — drop the Runtime Class
  expectation (route count / titles).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — runtimeclasses kind (service + `_KINDS` + API tests)

**SATISFIES:** `runtimeclasses-list-200`, `runtimeclasses-list-ignores-namespace`,
`runtimeclasses-sar-denied`, `runtimeclasses-binding-404`,
`runtimeclass-kind-singular-rejected`, `runtimeclasses-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_runtimeclasses.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_runtime_classes(namespace: str | None) -> list[dict]`
  and `K8sClient.get_runtime_class(namespace: str, name: str) -> list[dict]`
  — the exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the priorityclasses tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s with
  `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_runtimeclasses.py`, mirroring
  `test_k8s_client_priorityclasses.py` 1:1 with the node API:

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient


  def _client(node: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._node = node
      return client


  def test_list_runtime_classes_ignores_namespace() -> None:
      """[runtimeclasses-list-ignores-namespace] cluster-scoped: the
      namespace argument is accepted and ignored (the ``list_nodes``
      pattern)."""
      seen: list[object] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "runc"},
              "handler": "runc",
          }
      )
      node = SimpleNamespace(
          list_runtime_class=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1],
      )
      result = _client(node).list_runtime_classes("team-a")
      assert result == [{"metadata": {"name": "runc"}, "handler": "runc"}]
      assert seen == [True]  # called once, cluster list


  def test_get_runtime_class_404_returns_empty_list() -> None:
      """[runtimeclasses-get-by-name] a miss is ``[]``, mirroring
      ``get_priority_class``'s 0/1-item contract."""
      def read(_name: str) -> None:
          raise ApiException(status=404)

      node = SimpleNamespace(read_runtime_class=read)
      assert _client(node).get_runtime_class(None, "gone") == []


  def test_get_runtime_class_other_api_error_maps_to_unreachable() -> None:
      def read(_name: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_runtime_class=read)).get_runtime_class(None, "runc")


  def test_list_runtime_classes_maps_500_to_unreachable() -> None:
      def list_all() -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_runtime_class=list_all)).list_runtime_classes(None)
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_runtimeclasses.py -q`.
  Expected: FAIL (no `_node` attribute / no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`:

  In `__init__` (line ~226, next to `self._scheduling`):
  ```python
  # RuntimeClass (node.k8s.io) — cluster-scoped, the R4 "runtimeclasses"
  # kind (the 4.1 nav leaf had no view; ADR-0022 placement, TASK-046).
  self._node = k8s_client.NodeV1Api(api_client)
  ```

  Next to `list_priority_classes` (line 264):
  ```python
  def list_runtime_classes(self, _namespace: str | None) -> list[dict[str, Any]]:
      """RuntimeClass list in the standard kubernetes dict form
      (``to_dict``). Cluster-scoped: the namespace argument is accepted
      and ignored (the ``list_nodes`` pattern)."""
      try:
          resp = self._node.list_runtime_class()
      except ApiException as e:
          self._unreachable("list_runtime_classes", e)
          raise AssertionError("unreachable") from e
      return [rc.to_dict() for rc in resp.items]
  ```

  Next to `get_priority_class` (line 775):
  ```python
  def get_runtime_class(self, _namespace: str, name: str) -> list[dict[str, Any]]:
      """One RuntimeClass as a 0/1-item list; ``[]`` on 404. Cluster-
      scoped: the namespace argument is accepted and ignored. Any other
      ApiException maps to ``ClusterUnreachableError`` (502), matching
      ``get_priority_class``'s transport contract."""
      try:
          return [self._node.read_runtime_class(name).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_runtime_class", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "runtimeclasses": ("list_runtime_classes", "runtimeclasses", "node.k8s.io"),
  ```
  in `_KINDS` (after the priorityclasses row), and
  ```python
  "runtimeclasses": "get_runtime_class",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py`:
  - FakeK8s (next to lines 296–317) gains:
    ```python
    def list_runtime_classes(self, _namespace: str | None) -> list[dict]:
        # Cluster-scoped: the namespace argument is accepted-and-ignored
        # (mirrors the real K8sClient.list_runtime_classes).
        return [
            {
                "metadata": {
                    "name": "runc",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"provider": "docker"},
                },
                "handler": "runc",
                "overwrite_node_sel_no_toleration": False,
                "scheduling": {
                    "node_selector": {"kubernetes.io/runtime": "runc"},
                    "tolerations": [],
                },
                "pod_level_overhead": {"memory": "128Mi", "cpu": "100m"},
            }
        ]

    def get_runtime_class(self, _namespace: str, name: str) -> list[dict]:
        if name == "runc":
            return self.list_runtime_classes(None)
        return []
    ```
  - Six new tests mirroring the priorityclasses block (lines 1247–1334),
    same docstring-tag style:
    - `test_list_runtimeclasses_200` — 200, `body["kind"] == "runtimeclasses"`,
      one item with `metadata.name == "runc"`.
    - `test_list_runtimeclasses_ignores_namespace` — `?namespace=team-a`
      returns the same list; assert the FakeK8s recorded `None`/ignored
      namespace (the priorityclasses test's assertion shape).
    - `test_list_runtimeclasses_get_by_name` — `?name=runc` → 1 item;
      `?name=ghost` → `items == []`.
    - `test_list_runtimeclasses_sar_denied` — SAR denies; 403; assert
      `("list", "runtimeclasses", None, None, "node.k8s.io")` in `asked`
      (the group is the load-bearing assertion — `node.k8s.io`, NOT
      `scheduling.k8s.io`).
    - `test_runtimeclasses_binding_404` — cluster 999, unbound user → 404.
    - `test_runtimeclass_kind_singular_rejected` —
      `/resources/runtimeclass` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_runtimeclasses.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_runtimeclasses.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): runtimeclasses kind (node.k8s.io, cluster-scoped, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `runtimeclass-list-renders-rows-with-data-links`,
`runtimeclass-list-overhead-rendering`, `runtimeclass-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/OtherResource/RuntimeClass.tsx`
- Test: `frontend/tests/views/runtime_classes.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `runtimeclasses` list URL).
- Produces: the data-page link `/other-resource/runtimeclass/data?name=<name>`
  — the SOLE producer of that query string.
- Seam: `apiFetch` + TanStack Query (no new seam).
- Deletion test: deleting the view → the route (Task 4) 404s / the test
  file fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `PriorityClassItem` (line 225):

  ```ts
  /** A RuntimeClass item as returned by /api/v1/clusters/<id>/resources/runtimeclasses (kubernetes to_dict, snake_case; cluster-scoped). */
  export interface RuntimeClassItem {
    metadata?: {
      name?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    handler?: string
    overwrite_node_sel_no_toleration?: boolean
    scheduling?: {
      node_selector?: Record<string, string>
      tolerations?: unknown[]
    }
    pod_level_overhead?: { memory?: string; cpu?: string }
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/runtime_classes.test.tsx`: clone
  `priority_classes.test.tsx` 1:1 (KubeDataTable fake included), with:
  - fixture `runc`:
    ```ts
    const runc = {
      apiVersion: 'node.k8s.io/v1',
      kind: 'RuntimeClass',
      metadata: {
        name: 'runc',
        creation_timestamp: '2026-01-02T03:04:05Z',
        labels: { provider: 'docker' },
      },
      handler: 'runc',
      overwrite_node_sel_no_toleration: false,
      scheduling: { node_selector: { 'kubernetes.io/runtime': 'runc' }, tolerations: [] },
      pod_level_overhead: { memory: '128Mi', cpu: '100m' },
    }
    ```
  - `renderAt` default path `/other-resource/runtimeclass`.
  - MSW handler on `*/api/v1/clusters/1/resources/runtimeclasses`.
  - `list-renders-runtime-classes`: link `runc` →
    `/other-resource/runtimeclass/data?name=runc`; fetch path EXACTLY
    `/api/v1/clusters/1/resources/runtimeclasses`, no `namespace` substring;
    heading EXACTLY `Runtime Classes`; breadcrumb `Other Resources`;
    column headers `['Name', 'Handler', 'Overwrite Node Sel No Toleration',
    'Pod Level Overhead', 'Created']`; row shows `runc` (handler), `false`
    (overwrite flag), `100m / 128Mi` (overhead); created cell rendered by
    `formatTimestamp` (no raw ISO `T` in the cell, matches `/2026/`).
  - `list-overhead-absent-state`: a second item without
    `pod_level_overhead` → its cell shows `—` (em dash).
  - `list-no-cluster-state`: no fetch made, `No cluster selected.`.
  - `list-error-state`: 403 `RBAC_DENIED` →
    `Error loading runtime classes: RBAC_DENIED: list on runtimeclasses`.
  - `list-empty-state`: `items: []` → `No runtime classes found`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/runtime_classes.test.tsx`
  Expected: FAIL (cannot find module `src/views/OtherResource/RuntimeClass`).

- [ ] **Step 4: Implement the view** — `frontend/src/views/OtherResource/RuntimeClass.tsx`:
  clone of `PriorityClass.tsx` with:
  - docstring: cite the 4.1 dead-link finding + ADR-0022 placement + the
    PriorityClass precedent (the ratified-deviation record).
  - `type RuntimeClassRow = { name, handler, overwriteNodeSelNoToleration, podLevelOverhead, created }`
    and `toRow`:
    ```ts
    const toRow = (item: RuntimeClassItem): RuntimeClassRow => ({
      name: item.metadata?.name ?? '',
      handler: item.handler ?? '—',
      overwriteNodeSelNoToleration:
        item.overwrite_node_sel_no_toleration == null
          ? '—'
          : String(item.overwrite_node_sel_no_toleration),
      podLevelOverhead: item.pod_level_overhead
        ? [item.pod_level_overhead.cpu, item.pod_level_overhead.memory]
            .filter(Boolean)
            .join(' / ')
        : '—',
      created: formatTimestamp(item.metadata?.creation_timestamp),
    })
    ```
  - query key `['runtimeclasses', cluster?.id]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/runtimeclasses`.
  - name link → `/other-resource/runtimeclass/data?name=${encodeURIComponent(name)}`.
  - breadcrumb: Other Resources → Runtime Classes; card title EXACTLY
    `Runtime Classes`.
  - columns: Name (link) / Handler / Overwrite Node Sel No Toleration /
    Pod Level Overhead / Created.
  - pinned states: `No cluster selected.`, `Loading runtime classes...`,
    `Error loading runtime classes: {message}`, `No runtime classes found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/runtime_classes.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/OtherResource/RuntimeClass.tsx frontend/tests/views/runtime_classes.test.tsx`
  `git commit -m "feat(frontend): runtimeclass list view (Other Resources, 4.1-parity nav leaf)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `runtimeclass-data-renders-detail`,
`runtimeclass-data-not-found-state`, `runtimeclass-data-missing-name`

**Files:**
- Create: `frontend/src/views/OtherResource/RuntimeClassData.tsx`
- Test: `frontend/tests/views/runtime_class_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=` contract (0/1-item list; `[]` = miss) and
  Task 2's link (the sole producer of the `?name=` strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/runtime_class_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on `*/api/v1/clusters/1/resources/runtimeclasses?name=runc`
    returning `{ kind: 'runtimeclasses', items: [runc] }`; a miss handler
    (`?name=ghost`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/other-resource/runtimeclass/data?name=runc` — assert EXACTLY ONE
    fetch and that its URL has `?name=runc` and NO `namespace` substring;
    CTable rows: Name `runc`, Kind `RuntimeClass`, Handler `runc`,
    Overwrite Node Sel No Toleration `false`, Pod Level Overhead
    `100m / 128Mi`, a Created row, Labels table with `provider: docker`;
    the full-object block contains `"handler": "runc"` (the JSON block);
    the block's syntax-highlighter element exists (language json).
  - `data-not-found-state`: `?name=ghost` →
    `No RuntimeClass 'ghost' found`; assert NO `.text-danger` node for it
    (a state, not an error).
  - `data-missing-name`: `/other-resource/runtimeclass/data` (no param) →
    `Error: runtime class name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/runtime_class_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/OtherResource/RuntimeClassData.tsx`: clone of
  `PriorityClassData.tsx` with:
  - docstring: single-`?name=` fetch (no 4.1 list-then-filter), cluster-
    scoped (no namespace param), NOT_FOUND as a pinned STATE, the `json`
    hljs grammar as the truthful classifier (ratified 2026-10-28).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless re-register —
    the module is a singleton).
  - query key `['runtime-class-data', cluster?.id, name]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/runtimeclasses?name=${encodeURIComponent(name)}`.
  - breadcrumb: Other Resources → Runtime Classes (link) → `{name}`.
  - CTable rows: Name / Kind (`RuntimeClass`) / Created / Handler /
    Overwrite Node Sel No Toleration / Pod Level Overhead (`cpu / memory`
    or N/A) / Labels / Annotations (sub-tables, same shape as the
    priorityclass twin).
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No RuntimeClass '{name}' found`,
    `Error: runtime class name not provided`, `Loading runtime class data...`,
    card title `Runtime Class Data`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/runtime_class_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/OtherResource/RuntimeClassData.tsx frontend/tests/views/runtime_class_data.test.tsx`
  `git commit -m "feat(frontend): runtimeclass data view (single ?name= fetch, JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `runtimeclass-stub-removed-and-routes-wired`

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
    path="/other-resource/runtimeclass"
    element={
      <ProtectedRoute>
        <RuntimeClassView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/other-resource/runtimeclass/data"
    element={
      <ProtectedRoute>
        <RuntimeClassDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 28
  (`{ path: '/other-resource/runtimeclass', title: 'Runtime Class', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — remove the Runtime Class
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
  `git commit -m "feat(frontend): wire runtimeclass routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_runtimeclasses.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/runtime_classes.test.tsx tests/views/runtime_class_data.test.tsx tests/views/Stub.test.tsx` — green.
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
schema, no dependency, no public contract change). Reverting Task 4 without
Tasks 2–3 is safe (the leaf goes back to the stub only if the stub removal
in Task 4 is reverted too — it is, same commit).
