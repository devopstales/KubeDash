# LimitRange Views — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files
> to touch, tests, and verification. The product *why* lives in `briefing.md`
> and the ADR manifest in `adr.md`. This blueprint is pure-technical and cites
> them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route; no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already
ratified three times: priorityclasses + secrets + CRDs).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service method → `_KINDS` row → API route → SAR deny) before any
frontend exists; Task 2 is the list view; Task 3 the data view; Task 4 the
routing cleanup. Each task is independently revertable.

**Goal:** Resolve the stub nav leaf `/other-resource/limit-range` to a real,
SAR-gated, read-only list + data pair (4.1 parity in placement, RBAC
treatment, and limits-table content; 5.0 PriorityClass/Secret parity in
shape).

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_limit_ranges` / `get_limit_range` (kubernetes `CoreV1Api`,
core group, namespaced) + two dict rows (`_KINDS` / `_GETTERS`). Frontend:
two views (list = PriorityClass shape + Secret namespace handling; data =
PriorityClassData shape + SecretData namespace handling + the 4.1
Container Limits table), `LimitRangeItem` type, App.tsx routes, stub-route
removal.

**Tech Stack:** kubernetes `CoreV1Api` (already a dependency), Flask + Smorest
(existing route), React + CoreUI + TanStack Query + MSW (existing), no new
npm/Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/other-resources/limit_range.html.j2`
(list: Name / Namespace / Creation, `ns_select` form, hidden-POST name
links), `4.1:src/kubedash/templates/other-resources/limit_range-data.html.j2`
(metadata card + Container Limits table, columns Resource / Minimum /
Maximum / Default Limit / Default Request / Minimum Limit Request Ratio,
`None` for absent, hardcoded cpu/memory rows per `spec.limits[]` entry),
`4.1:src/kubedash/functions/k8s.py:1212-1235` (`k8sLimitRangeListGet`,
`list_namespaced_limit_range`, list-only — no single-object read in 4.1),
`4.1:src/kubedash/functions/routes.py:968-1013` (the two routes; data route
is list-then-filter). In-repo precedents — `backend/app/api/resources.py`
`_KINDS`/`_GETTERS` (the namespaced-kind rows to mirror: secrets,
networkpolicies), `backend/app/services/k8s_client.py:748-773`
(`list_network_policies` / `get_network_policy` — the namespaced pair to
mirror), `frontend/src/views/OtherResource/PriorityClass.tsx` +
`PriorityClassData.tsx` (the view-pair shape to clone),
`frontend/src/views/Security/Secret.tsx` + `SecretData.tsx` (the namespace
handling to clone: `selectedNamespace ?? 'default'` on the list,
`params.get('namespace') || selectedNamespace || 'default'` on the data
page), `frontend/tests/views/priority_classes.test.tsx` +
`priority_class_data.test.tsx` (the test fakes to clone),
`backend/tests/services/test_k8s_client_priorityclasses.py` (the
`object.__new__` pattern), `backend/tests/api/test_resources.py:247-260`
(the FakeK8s networkpolicy methods to mirror) and `:1247-1334` (the
API-test block to mirror).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0010, ADR-0020, ADR-0021,
ADR-0022. None created.

## Terms

None (the spec's vocabulary; "LimitRange" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET /api/v1/clusters/<id>/resources/limitranges?namespace=<ns>` → 200,
  `kind: "limitranges"`, items in `to_dict` form, SAR-gated on
  `list limitranges` (core group, the namespace param), 403 names the
  resource and the client call is never made on deny
  (`limitranges-list-200`, `limitranges-list-respects-namespace`,
  `limitranges-sar-denied`).
- `?name=` (with `?namespace=`) returns a 0/1-item list through the SAME
  route — hit = the object, miss = `[]` (`limitranges-get-by-name`).
- The singular `limitrange` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (the 4.1 route name was the singular
  `limit_range`; the API kind is the plural) (`limitrange-kind-singular-rejected`).
- The list view's card title is EXACTLY `Limit Ranges`, columns are
  Name/Namespace/Created, the fetch carries the selected namespace, and
  every name links to the data page with `?name=` AND `?namespace=`
  (`limitrange-list-renders-rows-with-data-links`).
- The data view fetches ONCE with `?name=` (and `?namespace=`), renders the
  metadata CTable + the Container Limits table + a JSON-highlighted
  full-object block, and treats a miss as the pinned state
  `No LimitRange '<name>' found` — never an error style
  (`limitrange-data-renders-detail`, `limitrange-data-not-found-state`,
  `limitrange-data-limits-table`).
- `/other-resource/limit-range` is gone from `views/Stub/routes.ts`; both
  real views are routed; the nav leaf is byte-identical
  (`limitrange-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — the two methods (modified, not new;
  `self._v1` already exists — no `__init__` change).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_limitranges.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `LimitRangeItem` (modified).
- `frontend/src/views/OtherResource/LimitRange.tsx` (new).
- `frontend/src/views/OtherResource/LimitRangeData.tsx` (new).
- `frontend/tests/views/limit_ranges.test.tsx` (new).
- `frontend/tests/views/limit_range_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).
- `frontend/e2e/ui-smoke.spec.ts` (modified — move the limit-range entry out
  of `SMOKE_STUB_ROUTES`).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- The list view's name-link href (`?name=…&namespace=…`) is the SOLE producer
  of the data page's query strings — the data page parses the params, never
  constructs them (the Secret contract; keep it).
- The data view's namespace resolution order is
  `?namespace=` param → `selectedNamespace` → `default` (the SecretData
  pattern). The list view ALWAYS sends the namespace (store value or
  `default`), so the param branch of the data view is what real navigation
  exercises.
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an
  API error.
- `Stub.test.tsx` counts/labels the stub routes: removing the route without
  updating the test is a RED frontend suite. Same for
  `e2e/ui-smoke.spec.ts` `SMOKE_STUB_ROUTES` (it asserts the stub title
  `Limit Range` at that path — the real view's card title is `Limit Ranges`,
  a different string).

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `kubernetes.CoreV1Api` is already vendored
  (air-gap, ADR-0020); `list_namespaced_limit_range` /
  `read_namespaced_limit_range` are part of it (4.1 used the same
  `CoreV1Api` method).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Namespaced kind: the list fetch carries `?namespace=` (store value,
  default `default`); SAR namespace = the param; the client methods HONOR the
  namespace (the `list_network_policies` / `get_network_policy` pattern —
  NOT the accept-and-ignore cluster-scoped pattern).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Limit Ranges` (e2e-smoke convention).
- Pinned copy (do not reword): `No limit ranges found`,
  `No LimitRange '<name>' found`, `Error: limit range name not provided`,
  `No cluster selected.`, `Loading limit ranges...`, and `None` for absent
  limits-table cells (4.1's copy).
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson) —
  type any new test params explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_limit_ranges` +
  `get_limit_range` next to `list_network_policies` / `get_network_policy`
  (lines 748–773). No `__init__` change: `self._v1` already exists
  (`CoreV1Api` is 4.1's own client for this kind).
- `backend/app/api/resources.py` (modify) — `_KINDS["limitranges"]` +
  `_GETTERS["limitranges"]`.
- `backend/tests/services/test_k8s_client_limitranges.py` (new) —
  `object.__new__` + `SimpleNamespace` fake, mirrors the priorityclasses
  file with a namespaced `_v1` stub.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_limit_ranges` / `get_limit_range`; 6 new tests mirroring the
  priorityclasses block (lines 1247–1334) with namespace-aware assertions.
- `frontend/src/lib/types.ts` (modify) — `LimitRangeItem` next to
  `PriorityClassItem`.
- `frontend/src/views/OtherResource/LimitRange.tsx` (new) — PriorityClass.tsx
  shape + Secret.tsx namespace handling.
- `frontend/src/views/OtherResource/LimitRangeData.tsx` (new) —
  PriorityClassData.tsx shape + SecretData.tsx namespace handling + the
  4.1 Container Limits table.
- `frontend/tests/views/limit_ranges.test.tsx` (new) — clone of
  priority_classes.test.tsx (KubeDataTable fake included) + the namespace
  assertions from the Secret test.
- `frontend/tests/views/limit_range_data.test.tsx` (new) — clone of
  priority_class_data.test.tsx + limits-table + namespace tests.
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (lines 366–381) + the two view imports.
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 27.
- `frontend/tests/views/Stub.test.tsx` (modify) — drop the Limit Range
  expectation (route count / titles).
- `frontend/e2e/ui-smoke.spec.ts` (modify) — drop the limit-range entry from
  `SMOKE_STUB_ROUTES` (line 50) and add both paths to `REAL_ROUTES`
  (lines 58–87), mirroring `/security/secret` + `/security/secret/data`.
  NOTE: the priorityclass entry at line 51 is stale debt from TASK-046's
  execution (it is no longer a stub either) — OUT OF SCOPE here; fix in
  TASK-046's follow-up so this diff stays about LimitRange.
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — limitranges kind (service + `_KINDS` + API tests)

**SATISFIES:** `limitranges-list-200`, `limitranges-list-respects-namespace`,
`limitranges-sar-denied`, `limitranges-binding-404`,
`limitrange-kind-singular-rejected`, `limitranges-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_limitranges.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_limit_ranges(namespace: str | None) -> list[dict]`
  and `K8sClient.get_limit_range(namespace: str, name: str) -> list[dict]`
  — the exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the priorityclasses/networkpolicy tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s with
  `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_limitranges.py`, mirroring
  `test_k8s_client_priorityclasses.py` 1:1 with the namespaced `_v1` stub:

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient

  LR = {"metadata": {"name": "default", "namespace": "team-a"},
        "spec": {"limits": [{"type": "Container",
                             "max": {"cpu": "2", "memory": "4Gi"},
                             "min": {"cpu": "500m", "memory": "1Gi"}}]}}

  def _client(v1: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._v1 = v1
      return client

  def test_list_limit_ranges_uses_namespace() -> None:
      """[limitranges-list-respects-namespace] namespaced kind: the
      namespace argument drives ``list_namespaced_limit_range`` (the
      ``list_network_policies`` pattern — NOT the accept-and-ignore
      cluster-scoped one)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: dict(LR))
      v1 = SimpleNamespace(
          list_namespaced_limit_range=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1],
      )
      result = _client(v1).list_limit_ranges("team-a")
      assert result == [LR]
      assert seen == ["team-a"]  # the namespace was passed through

  def test_get_limit_range_hit_returns_one_item() -> None:
      """[limitranges-get-by-name] a hit is the single object."""
      item = SimpleNamespace(to_dict=lambda: dict(LR))
      v1 = SimpleNamespace(read_namespaced_limit_range=lambda name, ns: item)
      assert _client(v1).get_limit_range("team-a", "default") == [LR]

  def test_get_limit_range_404_returns_empty_list() -> None:
      """[limitranges-get-by-name] a miss is ``[]``, mirroring
      ``get_network_policy``'s 0/1-item contract."""
      def read(name, ns) -> None:
          raise ApiException(status=404)

      assert _client(SimpleNamespace(read_namespaced_limit_range=read)).get_limit_range("team-a", "gone") == []

  def test_get_limit_range_other_api_error_maps_to_unreachable() -> None:
      def read(name, ns) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_limit_range=read)).get_limit_range("team-a", "default")

  def test_list_limit_ranges_maps_500_to_unreachable() -> None:
      def list_all(ns) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_limit_range=list_all)).list_limit_ranges("team-a")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_limitranges.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`, next to
  `list_network_policies` (line 748):

  ```python
  def list_limit_ranges(self, namespace: str | None) -> list[dict[str, Any]]:
      """LimitRange list in the standard kubernetes dict form (``to_dict``).
      Namespaced kind: the namespace argument drives
      ``list_namespaced_limit_range`` (the ``list_network_policies`` pattern).
      A transport ApiException maps to ``ClusterUnreachableError`` (502)."""
      try:
          resp = self._v1.list_namespaced_limit_range(namespace)
      except ApiException as e:
          self._unreachable("list_limit_ranges", e)
          raise AssertionError("unreachable") from e
      return [lr.to_dict() for lr in resp.items]

  def get_limit_range(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One LimitRange as a 0/1-item list; ``[]`` on 404. Any other
      ApiException maps to ``ClusterUnreachableError`` (502), matching
      ``get_network_policy``'s transport contract."""
      try:
          return [self._v1.read_namespaced_limit_range(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_limit_range", e)
          raise AssertionError("unreachable") from e
  ```

  (4.1 used `CoreV1Api.list_namespaced_limit_range` — `self._v1` is the same
  API; no new client attribute is needed. Verify the exact method names
  against the vendored kubernetes client in `uv run python -c "from
  kubernetes.client import CoreV1Api; print(hasattr(CoreV1Api,
  'list_namespaced_limit_range'), hasattr(CoreV1Api,
  'read_namespaced_limit_range'))"` — both exist in the client 4.1 shipped
  with, expect True/True.)

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "limitranges": ("list_limit_ranges", "limitranges", ""),
  ```
  in `_KINDS` (after the networkpolicies row), and
  ```python
  "limitranges": "get_limit_range",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py`:
  - FakeK8s (next to the networkpolicy fakes, lines 247–260) gains:
    ```python
    def list_limit_ranges(self, namespace: str | None) -> list[dict]:
        # Namespaced kind: the namespace is honored like the real K8sClient.
        self.limitrange_ns_calls: list[str | None] = []
        self.limitrange_ns_calls.append(namespace)
        return [
            {
                "metadata": {
                    "name": "default",
                    "namespace": namespace,
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"app": "limits"},
                },
                "spec": {
                    "limits": [
                        {
                            "type": "Container",
                            "max": {"cpu": "2", "memory": "4Gi"},
                            "min": {"cpu": "500m", "memory": "1Gi"},
                            "default": {"cpu": "1", "memory": "2Gi"},
                            "defaultRequest": {"cpu": "250m", "memory": "512Mi"},
                            "maxLimitRequestRatio": {"cpu": "2", "memory": "4"},
                        }
                    ]
                },
            }
        ]

    def get_limit_range(self, namespace: str, name: str) -> list[dict]:
        if name != "default":
            return []
        return self.list_limit_ranges(namespace)
    ```
  - Six new tests mirroring the priorityclasses block (lines 1247–1334),
    same docstring-tag style:
    - `test_list_limitranges_200` — `?namespace=team-a`; 200,
      `body["kind"] == "limitranges"`, one item with `metadata.name ==
      "default"`, `metadata.namespace == "team-a"`, spec limits intact.
    - `test_list_limitranges_respects_namespace` — the FakeK8s recorded the
      passed namespace (`limitrange_ns_calls == ["team-a"]`) — the
      namespaced contrast to priorityclasses' ignores-namespace test.
    - `test_list_limitranges_get_by_name` — `?namespace=team-a&name=default`
      → 1 item; `?namespace=team-a&name=ghost` → `items == []`.
    - `test_list_limitranges_sar_denied` — SAR denies; 403; assert
      `("list", "limitranges", "team-a", None, "")` in `asked` (group `""`
      and the namespace are the load-bearing assertions — core group,
      namespaced).
    - `test_limitranges_binding_404` — cluster 999, unbound user → 404.
    - `test_limitrange_kind_singular_rejected` —
      `/resources/limitrange` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_limitranges.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_limitranges.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): limitranges kind (core, namespaced, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `limitrange-list-renders-rows-with-data-links`,
`limitrange-list-empty-state`, `limitrange-list-no-cluster-state`,
`limitrange-list-error-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/OtherResource/LimitRange.tsx`
- Test: `frontend/tests/views/limit_ranges.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `limitranges` list URL with `?namespace=`).
- Produces: the data-page link
  `/other-resource/limit-range/data?name=<name>&namespace=<namespace>` —
  the SOLE producer of those query strings.
- Seam: `apiFetch` + TanStack Query (no new seam).
- Deletion test: deleting the view → the route (Task 4) 404s / the test
  file fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `PriorityClassItem`:

  ```ts
  /** One spec.limits[] entry of a LimitRange (kubernetes to_dict snake_case). */
  export interface LimitRangeLimitItem {
    type?: string
    min?: { cpu?: string; memory?: string }
    max?: { cpu?: string; memory?: string }
    default?: { cpu?: string; memory?: string }
    default_request?: { cpu?: string; memory?: string }
    max_limit_request_ratio?: { cpu?: string; memory?: string }
  }

  /** A LimitRange item as returned by /api/v1/clusters/<id>/resources/limitranges (kubernetes to_dict, snake_case; namespaced). */
  export interface LimitRangeItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: { limits?: LimitRangeLimitItem[] }
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/limit_ranges.test.tsx`: clone
  `priority_classes.test.tsx` 1:1 (KubeDataTable fake included), with:
  - fixture:
    ```ts
    const limits = {
      apiVersion: 'v1',
      kind: 'LimitRange',
      metadata: {
        name: 'default',
        namespace: 'team-a',
        creation_timestamp: '2026-01-02T03:04:05Z',
        labels: { app: 'limits' },
      },
      spec: {
        limits: [
          {
            type: 'Container',
            max: { cpu: '2', memory: '4Gi' },
            min: { cpu: '500m', memory: '1Gi' },
            default: { cpu: '1', memory: '2Gi' },
            defaultRequest: { cpu: '250m', memory: '512Mi' },
            maxLimitRequestRatio: { cpu: '2', memory: '4' },
          },
        ],
      },
    }
    ```
  - `renderAt` default path `/other-resource/limit-range`; cluster store
    `selectedNamespace: 'team-a'` (the `selectProd` helper from the
    priorityclass test already sets it).
  - MSW handler on `*/api/v1/clusters/1/resources/limitranges`.
  - `list-renders-limit-ranges`: fetch URL EXACTLY
    `/api/v1/clusters/1/resources/limitranges?namespace=team-a`; heading
    EXACTLY `Limit Ranges`; breadcrumb `Other Resources`; column headers
    `['Name', 'Namespace', 'Created']`; row shows `default` (name) linking
    to `/other-resource/limit-range/data?name=default&namespace=team-a`,
    `team-a` (namespace); created cell rendered by `formatTimestamp` (no
    raw ISO `T` in the cell, matches `/2026/`).
  - `list-namespace-falls-back-to-default`: cluster store with
    `selectedNamespace: null` → fetch URL carries `?namespace=default`.
  - `list-no-cluster-state`: no fetch made, `No cluster selected.`.
  - `list-error-state`: 403 `RBAC_DENIED` →
    `Error loading limit ranges: RBAC_DENIED: list on limitranges`.
  - `list-empty-state`: `items: []` → `No limit ranges found`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/limit_ranges.test.tsx`
  Expected: FAIL (cannot find module `src/views/OtherResource/LimitRange`).

- [ ] **Step 4: Implement the view** — `frontend/src/views/OtherResource/LimitRange.tsx`:
  clone of `PriorityClass.tsx` with Secret's namespace handling:
  - docstring: cite the 4.1 templates + ADR-0022 placement + the
    PriorityClass/Secret precedents (the ratified-deviation record: the list
    columns are 4.1's Name / Namespace / Creation set; the namespace comes
    from the 5.0 header store, not 4.1's `ns_select` form).
  - `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`
  - query key `['limitranges', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/limitranges?namespace=${encodeURIComponent(namespace)}`.
  - row: `{ name, namespace: item.metadata?.namespace ?? namespace, created }`.
  - name link →
    `/other-resource/limit-range/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(ns)}`.
  - breadcrumb: Other Resources → Limit Ranges; card title EXACTLY
    `Limit Ranges`.
  - columns: Name (link) / Namespace / Created.
  - pinned states: `No cluster selected.`, `Loading limit ranges...`,
    `Error loading limit ranges: {message}`, `No limit ranges found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/limit_ranges.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/OtherResource/LimitRange.tsx frontend/tests/views/limit_ranges.test.tsx`
  `git commit -m "feat(frontend): limit-range list view (Other Resources, namespaced, 4.1-parity columns)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `limitrange-data-renders-detail`,
`limitrange-data-limits-table`, `limitrange-data-not-found-state`,
`limitrange-data-missing-name`

**Files:**
- Create: `frontend/src/views/OtherResource/LimitRangeData.tsx`
- Test: `frontend/tests/views/limit_range_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=` contract (0/1-item list; `[]` = miss) and
  Task 2's link (the sole producer of the `?name=`/`?namespace=` strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/limit_range_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on `*/api/v1/clusters/1/resources/limitranges` returning
    `{ kind: 'limitranges', items: [limits] }` for `?name=default`; a miss
    handler (`?name=ghost`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/other-resource/limit-range/data?name=default&namespace=team-a` —
    assert EXACTLY ONE fetch and that its URL carries `?name=default` AND
    `?namespace=team-a`; metadata CTable rows: Name `default`, Namespace
    `team-a`, Kind `LimitRange`, a Created row, Labels table with
    `app: limits`, `No annotations` (absent); the full-object block contains
    `"kind": "LimitRange"` (the JSON block); the syntax-highlighter element
    exists (language json).
  - `data-namespace-falls-back-to-store`: at
    `/other-resource/limit-range/data?name=default` (no namespace param)
    with store `selectedNamespace: 'team-a'` → fetch URL carries
    `?namespace=team-a` (the SecretData resolution order).
  - `data-limits-table`: the Container Limits table renders one row with
    Resource `Container`, Minimum `500m / 1Gi`, Maximum `2 / 4Gi`,
    Default Limit `1 / 2Gi`, Default Request `250m / 512Mi`, Minimum Limit
    Request Ratio `2 / 4`; an entry field that is absent renders `None`
    (second fixture: a limits entry with only `max.cpu` → its Memory column
    shows `None`).
  - `data-limits-absent`: item with `spec: {}` → the section shows no rows
    (an empty table body, 4.1's empty branch), not an error.
  - `data-not-found-state`: `?name=ghost` → `No LimitRange 'ghost' found`;
    assert NO `.text-danger` node for it (a state, not an error).
  - `data-missing-name`: `/other-resource/limit-range/data` (no param) →
    `Error: limit range name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/limit_range_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/OtherResource/LimitRangeData.tsx`: clone of
  `PriorityClassData.tsx` with SecretData's namespace handling and the
  4.1 limits table:
  - docstring: single-`?name=` fetch (no 4.1 list-then-filter), namespaced
    (namespace resolution `?namespace=` → store → `default`), NOT_FOUND as
    a pinned STATE, the `json` hljs grammar as the truthful classifier
    (ratified 2026-10-28), and the Container Limits table as 4.1 parity
    (iterated by `type` instead of 4.1's hardcoded cpu/memory rows — the
    deviation from `adr.md`).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless re-register —
    the module is a singleton).
  - `const selectedNamespace = useClusterStore((s) => s.selectedNamespace)`
    `const namespace = params.get('namespace') || selectedNamespace || 'default'`
    (the SecretData pattern, byte-for-byte).
  - query key `['limit-range-data', cluster?.id, namespace, name]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/limitranges?namespace=${encodeURIComponent(namespace)}&name=${encodeURIComponent(name)}`.
  - breadcrumb: Other Resources → Limit Ranges (link) → `{name}`.
  - metadata CTable rows: Name / Namespace / Kind (`LimitRange`) / Created /
    Annotations / Labels (sub-tables, the priorityclass twin's shape).
  - Container Limits section (a `CCard`-in-body block mirroring 4.1's
    second card), CTable bordered, columns Resource / Minimum / Maximum /
    Default Limit / Default Request / Minimum Limit Request Ratio:
    ```ts
    const limits = item?.spec?.limits ?? []
    const none = 'None'
    const pair = (v: { cpu?: string; memory?: string } | undefined) =>
      v ? [v.cpu, v.memory].filter(Boolean).join(' / ') || none : none
    // rows: for each entry, one row per resource. The entry's `type` names
    // the resource (4.1 hardcoded cpu+memory; for a standard LimitRange the
    // output is identical). Absent type → two rows, cpu and memory (4.1).
    const rows: { key: string; resource: string; min: string; max: string;
                  def: string; defReq: string; ratio: string }[] = []
    for (const entry of limits) {
      const resources = entry.type ? [entry.type] : ['cpu', 'memory']
      for (const r of resources) {
        rows.push({
          key: `${entry.type ?? 'entry'}-${r}-${rows.length}`,
          resource: r,
          min: pair(entry.min),
          max: pair(entry.max),
          def: pair(entry.default),
          defReq: pair(entry.default_request),
          ratio: pair(entry.max_limit_request_ratio),
        })
      }
    }
    ```
    (cell rendering: the `pair` value is `cpu / memory` compact, or `None`
    when the field is absent — 4.1's pinned copy.)
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No LimitRange '{name}' found`,
    `Error: limit range name not provided`, `Loading limit range data...`,
    card title `Limit Range Data`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/limit_range_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/OtherResource/LimitRangeData.tsx frontend/tests/views/limit_range_data.test.tsx`
  `git commit -m "feat(frontend): limit-range data view (single ?name= fetch, 4.1 limits table, JSON block)"`

### Task 4: Routing — App.tsx + stub removal + e2e move + full verification

**SATISFIES:** `limitrange-stub-removed-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/tests/views/Stub.test.tsx`
- Modify: `frontend/e2e/ui-smoke.spec.ts`

**Interfaces:**
- Consumes: Tasks 2–3's view components.
- Produces: the resolved nav leaf (the goal).
- Seam: react-router `Route` + the `stubRoutes` array + the e2e coverage map.
- Deletion test: delete the two `Route`s → both paths fall through to the
  stub list (or 404 once the stub entry is gone) — the nav leaf is dead
  again, the exact pre-change state.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the two view imports
  (next to the priorityclass imports) and, after the priorityclass pair
  (line 381), mirror the block:
  ```tsx
  <Route
    path="/other-resource/limit-range"
    element={
      <ProtectedRoute>
        <LimitRangeView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/other-resource/limit-range/data"
    element={
      <ProtectedRoute>
        <LimitRangeDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 27
  (`{ path: '/other-resource/limit-range', title: 'Limit Range', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — remove the Limit Range
  expectation (route count or title list) per that file's structure;
  re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Update the e2e smoke map** — `frontend/e2e/ui-smoke.spec.ts`:
  - remove `{ path: '/other-resource/limit-range', title: 'Limit Range' }`
    from `SMOKE_STUB_ROUTES` (line 50) — the path no longer renders the
    stub, and the stub-title assertion (`Limit Range`, exact) would fail
    against the real card title `Limit Ranges`.
  - add `'/other-resource/limit-range'` and
    `'/other-resource/limit-range/data'` to `REAL_ROUTES` (mirroring the
    `/security/secret` + `/security/secret/data` pair at lines 81–82).
  - do NOT touch the stale priorityclass entry (line 51) — out of scope
    (TASK-046 follow-up).

- [ ] **Step 5: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Task 3 must hold).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON
    block uses the already-vendored syntax highlighter).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 6: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx frontend/e2e/ui-smoke.spec.ts`
  `git commit -m "feat(frontend): wire limit-range routes, remove stub, move e2e route to real"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_limitranges.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/limit_ranges.test.tsx tests/views/limit_range_data.test.tsx tests/views/Stub.test.tsx` — green.
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

## Execution note (spec zone)

- Create the Backlog task first (TASK-054 per this spec's Backlog field):
  "Build 4.1-parity LimitRange views at /other-resource/limit-range
  (list + data)", label `feature`, priority MEDIUM, references
  `4.1:src/kubedash/templates/other-resources/limit_range.html.j2`,
  `4.1:src/kubedash/templates/other-resources/limit_range-data.html.j2`,
  `kubedash_4:frontend/src/views/OtherResource/PriorityClass.tsx`,
  `kubedash_4:frontend/src/views/Security/SecretData.tsx`,
  `kubedash_4:backend/app/api/resources.py` — mirroring TASK-046's
  structure (acceptance criteria R1–R5 → testable boxes).
- Then move this spec folder into `.skillgrid/specs/2026-10-28-limitrange-views/`
  (it was written to the plan directory because Plan mode is read-only on
  the repo).
