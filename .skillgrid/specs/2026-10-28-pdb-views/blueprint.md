# PodDisruptionBudget Views — Implementation Blueprint (steps, files, verification)

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

**Goal:** Resolve the nav leaf `/other-resource/pod-disruption-budget` to a
real, SAR-gated, read-only list + data pair — the 4.1 PodDisruptionBudget
pages ported with the ratified 5.0 deltas.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`, and already threads
`namespace` (namespaced kinds: secrets, networkpolicies). This change adds
ONE kind: `K8sClient.list_pod_disruption_budgets` / `get_pod_disruption_budget`
(kubernetes `PolicyV1Api`, group `policy` v1, namespaced with the
all-namespaces branch) + two dict rows (`_KINDS` / `_GETTERS`) + one new
`self._policy` attribute in `__init__`. Frontend: two views (list cloned from
NetworkPolicy.tsx for the namespace handling, data cloned from
PriorityClassData.tsx for the CTable+JSON block), `PodDisruptionBudgetItem`
type, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `PolicyV1Api` (already a dependency, already
instantiated in the 4.1 client; one new attribute `self._policy` in 5.0's
`K8sClient.__init__`), Flask + Smorest (existing route), React + CoreUI +
TanStack Query + MSW (existing), no new npm/Python dependency (air-gap,
ADR-0020).

**Spec:** `briefing.md` (R1–R5).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/other-resources/pod-disruption-budget.html.j2`
(list: Name/Namespace/Min Available/Max Unavailable/Allowed Disruptions — the
last indexes `pdp.status.disruptions_allowed` unguarded),
`4.1:src/kubedash/templates/other-resources/pod-disruption-budget-data.html.j2`
(data: Name/Created/Namespace/Creation/Annotations/Labels/Selector/Eviction
Policy/Status row/Conditions table — note the duplicate Creation row, the
`unhealthy_pod_eviction_policy` tuple bug in the read function, and the
dynamic-key Conditions table), `4.1:src/kubedash/lib/k8s/other.py:153`
(`k8sPodDisruptionBudgetListGet`: `list_namespaced_pod_disruption_budget`,
NAMESPACED — session ns_select; the `selector` read is `match_labels` only;
the eviction-policy trailing-comma tuple). In-repo precedents —
`backend/app/services/k8s_client.py:736-766` (the `list_secrets`/`get_secret`
namespaced pair to mirror), `backend/app/api/resources.py`
`_KINDS`/`_GETTERS` + the `name` branch (line ~104-114, the
`namespace = namespace or "default"` fallback),
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

None (the spec's vocabulary; "PodDisruptionBudget" is the k8s kind, not a new
term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/poddisruptionbudgets?namespace=team-a` → 200,
  `kind: "poddisruptionbudgets"`, items in `to_dict` form, SAR-gated on
  `list poddisruptionbudgets` (group `policy`, namespace `team-a`), 403
  names the resource and the client call is never made on deny
  (`poddisruptionbudgets-list-200-in-namespace`,
  `poddisruptionbudgets-sar-denied`).
- Without a namespace param the client uses
  `list_pod_disruption_budget_for_all_namespaces`
  (`poddisruptionbudgets-list-all-namespaces-without-param`).
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the object, miss = `[]` (`poddisruptionbudgets-get-by-name`).
- The singular `poddisruptionbudget` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (the 4.1 route name was singular; the API
  kind is the plural) (`poddisruptionbudget-kind-singular-rejected`).
- The list view fetches
  `/api/v1/clusters/<id>/resources/poddisruptionbudgets?namespace=<ns>` with
  `<ns> = selectedNamespace ?? 'default'`; card title EXACTLY `Pod
  Disruption Budget List`; columns Name/Namespace/Min Available/Max
  Unavailable/Allowed Disruptions; every name links to the data page with
  BOTH `name` and `namespace`
  (`pdb-list-renders-rows-with-data-links`).
- Min Available cell = `spec.min_available ?? '—'`, Max Unavailable cell =
  `spec.max_unavailable ?? '—'` (the k8s API enforces exactly one of the
  pair; the absent one renders `—`), Allowed Disruptions cell =
  `status.disruptions_allowed ?? '—'` (`pdb-list-min-max-cells`,
  `pdb-list-missing-status`).
- The data view fetches ONCE with `?name=&namespace=`, renders the CTable
  (Name/Created/Namespace/Selector/Eviction Policy/Labels/Annotations) + the
  Status table (Allowed disruptions/Current healthy/Desired) + the
  Conditions table (Type/Status/Reason/Message) + a JSON-highlighted
  full-object block, and treats a miss as the pinned state
  `No PodDisruptionBudget '<name>' found` — never an error style
  (`pdb-data-renders-detail`, `pdb-data-selector-and-eviction-policy`,
  `pdb-data-not-found-state`).
- `/other-resource/pod-disruption-budget` is gone from
  `views/Stub/routes.ts`; both real views are routed; the nav leaf is
  byte-identical (`pdb-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `self._policy` attribute + the two
  methods (modified).
- `backend/app/api/resources.py` — the two dict rows (modified).
- `backend/tests/services/test_k8s_client_poddisruptionbudgets.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 6 new tests
  (modified).
- `frontend/src/lib/types.ts` — `PodDisruptionBudgetItem` (modified).
- `frontend/src/views/OtherResource/PodDisruptionBudget.tsx` (new).
- `frontend/src/views/OtherResource/PodDisruptionBudgetData.tsx` (new).
- `frontend/tests/views/pod_disruption_budgets.test.tsx` (new).
- `frontend/tests/views/pod_disruption_budget_data.test.tsx` (new).
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
- The `name` branch of the generic route falls back to `namespace = "default"`
  when no namespace param is present — the data page ALWAYS sends the
  namespace (it has it from the link), so the fallback never fires for this
  view; the test suite pins that the data URL carries the namespace.
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend
  suite (the test expects the path to be excluded from stubs).

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive).

## Global Constraints

- No new Python dependency — `PolicyV1Api` is already vendored in the
  kubernetes client (the 4.1 code imported it); one new `self._policy`
  attribute in `K8sClient.__init__` (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by PriorityClassData/SecretData; the `json` grammar is already
  registered there (registering again is harmless — the module is a
  singleton).
- Namespaced kind (group `policy`, v1): the list URL and the data URL carry
  `namespace=`; SAR group = `"policy"`, namespace = the query namespace or
  `None`; the client methods use the `list_namespaced_pod_disruption_budget(namespace)`
  / `list_pod_disruption_budget_for_all_namespaces()` branch (the
  `list_secrets` pattern).
- The PDB spec has EXACTLY one of `min_available` / `max_unavailable` (the
  k8s API enforces it); the absent one renders `—`. `status.disruptions_allowed`
  renders `—` when `status` is absent (a fresh PDB) — 4.1's Jinja 3.1.6 would
  `UndefinedError` (verified; `adr.md` → Deviations).
- The full-object block on the data page is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Pod Disruption Budget List` (4.1's title, verbatim —
  the e2e-smoke contract).
- Pinned copy (do not reword): `No pod disruption budgets found`,
  `No PodDisruptionBudget '<name>' found`,
  `Error: pod disruption budget name not provided`, `No cluster selected.`,
  `Loading pod disruption budgets...`, `No labels`, `No annotations`,
  `No conditions`.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `self._policy =
  k8s_client.PolicyV1Api(api_client)` next to `self._node` (line ~229);
  `list_pod_disruption_budgets` next to `list_secrets` (line ~736),
  `get_pod_disruption_budget` next to `get_secret` (line ~753).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["poddisruptionbudgets"]` + `_GETTERS["poddisruptionbudgets"]`.
- `backend/tests/services/test_k8s_client_poddisruptionbudgets.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_pod_disruption_budgets` / `get_pod_disruption_budget`; 6 new tests.
- `frontend/src/lib/types.ts` (modify) — `PodDisruptionBudgetItem` next to
  `PriorityClassItem` / the security types.
- `frontend/src/views/OtherResource/PodDisruptionBudget.tsx` (new) —
  namespace handling from NetworkPolicy.tsx, layout from PriorityClass.tsx.
- `frontend/src/views/OtherResource/PodDisruptionBudgetData.tsx` (new) —
  clone of PriorityClassData.tsx + the 4.1 Selector/Eviction-Policy/Status/
  Conditions tables.
- `frontend/tests/views/pod_disruption_budgets.test.tsx` (new).
- `frontend/tests/views/pod_disruption_budget_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the priorityclass pair
  (line ~381) + the two view imports (after line 48).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 25
  (`/other-resource/pod-disruption-budget`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set (the test derives expected stubs from the nav minus
  `viewPaths`).
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — poddisruptionbudgets kind (service + `_KINDS` + API tests)

**SATISFIES:** `poddisruptionbudgets-list-200-in-namespace`,
`poddisruptionbudgets-list-all-namespaces-without-param`,
`poddisruptionbudgets-sar-denied`, `poddisruptionbudgets-binding-404`,
`poddisruptionbudget-kind-singular-rejected`, `poddisruptionbudgets-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_poddisruptionbudgets.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_pod_disruption_budgets(namespace: str | None) ->
  list[dict]` and `K8sClient.get_pod_disruption_budget(namespace: str, name:
  str) -> list[dict]` — the exact names `_KINDS`/`_GETTERS` reference via
  `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the secrets/networkpolicies tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_poddisruptionbudgets.py`, mirroring
  the secrets test pattern with `object.__new__` + `SimpleNamespace`:

  ```python
  from types import SimpleNamespace

  import pytest
  from kubernetes.client.exceptions import ApiException

  from app.core.errors import ClusterUnreachableError
  from app.services.k8s_client import K8sClient


  def _client(policy: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._policy = policy
      return client


  def test_list_pod_disruption_budgets_in_namespace() -> None:
      """[poddisruptionbudgets-list-200-in-namespace] a namespace is
      forwarded to ``list_namespaced_pod_disruption_budget`` (the
      ``list_secrets`` pattern)."""
      seen: list[object] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "web", "namespace": "team-a"},
              "spec": {"min_available": 3, "selector": {"match_labels": {"app": "web"}}},
              "status": {"disruptions_allowed": 1, "current_healthy": 4},
          }
      )
      policy = SimpleNamespace(
          list_namespaced_pod_disruption_budget=lambda namespace: (
              seen.append(namespace),
              SimpleNamespace(items=[item]),
          )[1],
      )
      result = _client(policy).list_pod_disruption_budgets("team-a")
      assert result[0]["metadata"]["namespace"] == "team-a"
      assert seen == ["team-a"]  # the namespace is forwarded, not dropped


  def test_list_pod_disruption_budgets_all_namespaces_without_namespace() -> None:
      """[poddisruptionbudgets-list-all-namespaces-without-param] ``None``
      uses the all-namespaces call (the ``list_secrets`` branch)."""
      seen: list[object] = []
      policy = SimpleNamespace(
          list_pod_disruption_budget_for_all_namespaces=lambda: (
              seen.append(True),
              SimpleNamespace(items=[]),
          )[1],
      )
      assert _client(policy).list_pod_disruption_budgets(None) == []
      assert seen == [True]


  def test_list_pod_disruption_budgets_maps_500_to_unreachable() -> None:
      def list_all(namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_pod_disruption_budget=list_all)).list_pod_disruption_budgets("team-a")


  def test_get_pod_disruption_budget_404_returns_empty_list() -> None:
      """[poddisruptionbudgets-get-by-name] a miss is ``[]``, mirroring
      ``get_secret``'s 0/1-item contract."""
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=404)

      policy = SimpleNamespace(read_namespaced_pod_disruption_budget=read)
      assert _client(policy).get_pod_disruption_budget("team-a", "ghost") == []


  def test_get_pod_disruption_budget_hit_returns_one_item() -> None:
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web"}})
      policy = SimpleNamespace(read_namespaced_pod_disruption_budget=lambda name, namespace: item)
      assert _client(policy).get_pod_disruption_budget("team-a", "web") == [
          {"metadata": {"name": "web"}}
      ]


  def test_get_pod_disruption_budget_other_api_error_maps_to_unreachable() -> None:
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_pod_disruption_budget=read)).get_pod_disruption_budget("team-a", "web")
  ```

- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_poddisruptionbudgets.py -q`.
  Expected: FAIL (no methods).

- [ ] **Step 3: Implement the service methods** — `k8s_client.py`:

  `__init__`, next to `self._node` (line ~229):
  ```python
  # PodDisruptionBudget (policy/v1, namespaced) — the R4
  # "poddisruptionbudgets" kind (4.1-parity nav leaf; ADR-0022 placement).
  self._policy = k8s_client.PolicyV1Api(api_client)
  ```

  Next to `list_secrets` (line ~736):
  ```python
  def list_pod_disruption_budgets(self, namespace: str | None) -> list[dict[str, Any]]:
      """PodDisruptionBudget list in the standard kubernetes dict form
      (``to_dict``) for one namespace, or across all namespaces when the
      namespace is ``None`` (the ``list_secrets`` branch). No field
      stripping — the view renders ``spec.min_available``/
      ``spec.max_unavailable``/``status.disruptions_allowed`` and the data
      page the full object. A transport ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          resp = (
              self._policy.list_namespaced_pod_disruption_budget(namespace)
              if namespace
              else self._policy.list_pod_disruption_budget_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_pod_disruption_budgets", e)
          raise AssertionError("unreachable") from e
      return [p.to_dict() for p in resp.items]
  ```

  Next to `get_secret` (line ~753):
  ```python
  def get_pod_disruption_budget(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One PodDisruptionBudget as a 0/1-item list; ``[]`` on 404. Any
      other ApiException maps to ``ClusterUnreachableError`` (502),
      matching ``get_secret``'s transport contract."""
      try:
          return [self._policy.read_namespaced_pod_disruption_budget(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_pod_disruption_budget", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 4: Wire the kind + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  "poddisruptionbudgets": (
      "list_pod_disruption_budgets",
      "poddisruptionbudgets",
      "policy",
  ),
  ```
  in `_KINDS` (after the runtimeclasses row; group `policy` v1), and
  ```python
  "poddisruptionbudgets": "get_pod_disruption_budget",
  ```
  in `_GETTERS`.

  Then `backend/tests/api/test_resources.py`:
  - FakeK8s gains (mirror the networkpolicy/priorityclasses FakeK8s block):
    ```python
    def list_pod_disruption_budgets(self, namespace: str | None) -> list[dict]:
        # Namespaced kind (policy/v1): the namespace is forwarded (the real
        # K8sClient.list_pod_disruption_budgets pattern).
        return [
            {
                "metadata": {
                    "name": "web",
                    "namespace": namespace or "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "labels": {"team": "a"},
                    "annotations": {"pdb.kubernetes.io/managed-by": "kubedash"},
                },
                "spec": {
                    "min_available": 3,
                    "selector": {"match_labels": {"app": "web"}},
                    "unhealthy_pod_eviction_policy": "AlwaysAllow",
                },
                "status": {
                    "observed_generation": 1,
                    "current_healthy": 4,
                    "desired": 3,
                    "total_pods": 4,
                    "expected_pods": 3,
                    "disruptions_allowed": 1,
                    "conditions": [
                        {
                            "type": "Available",
                            "status": "True",
                            "reason": "SufficientPods",
                            "message": "PodDisruptionBudget is available",
                        }
                    ],
                },
            }
        ]

    def get_pod_disruption_budget(self, namespace: str, name: str) -> list[dict]:
        if name == "web":
            return self.list_pod_disruption_budgets(namespace)
        return []
    ```
  - Six new tests mirroring the networkpolicy block (lines 1033–1090), same
    docstring-tag style:
    - `test_list_poddisruptionbudgets_200_in_namespace` — 200,
      `body["kind"] == "poddisruptionbudgets"`, one item in `team-a`; assert
      the FakeK8s received `namespace="team-a"`.
    - `test_list_poddisruptionbudgets_all_namespaces_without_param` — no
      `namespace` param → 200; assert the FakeK8s received `None` (the
      all-namespaces branch).
    - `test_list_poddisruptionbudgets_get_by_name` —
      `?name=web&namespace=team-a` → 1 item; `?name=ghost&namespace=team-a`
      → `items == []`.
    - `test_list_poddisruptionbudgets_sar_denied` — SAR denies; 403; assert
      `("list", "poddisruptionbudgets", "team-a", None, "policy")` in
      `asked` (namespace `team-a`, group `policy` — the load-bearing
      assertions).
    - `test_poddisruptionbudgets_binding_404` — cluster 999, unbound user →
      404.
    - `test_poddisruptionbudget_kind_singular_rejected` —
      `/resources/poddisruptionbudget` → 404
      `RESOURCE_KIND_NOT_SUPPORTED`.

- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_poddisruptionbudgets.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_poddisruptionbudgets.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): poddisruptionbudgets kind (policy, namespaced, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `pdb-list-renders-rows-with-data-links`,
`pdb-list-min-max-cells`, `pdb-list-missing-status`, `pdb-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/OtherResource/PodDisruptionBudget.tsx`
- Test: `frontend/tests/views/pod_disruption_budgets.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `poddisruptionbudgets` list URL, namespaced).
- Produces: the data-page link
  `/other-resource/pod-disruption-budget/data?name=<name>&namespace=<ns>` —
  the SOLE producer of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedNamespace`
  (no new seam).
- Deletion test: deleting the view → the route (Task 4) 404s / the test file
  fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the type** — `frontend/src/lib/types.ts`, next to
  `PriorityClassItem`:

  ```ts
  /** A PodDisruptionBudget item as returned by /api/v1/clusters/<id>/resources/poddisruptionbudgets (kubernetes to_dict, snake_case; namespaced, policy/v1). */
  export interface PodDisruptionBudgetItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      min_available?: number
      max_unavailable?: number
      selector?: {
        match_labels?: Record<string, string>
        match_expressions?: unknown[]
      }
      unhealthy_pod_eviction_policy?: string
    }
    status?: {
      observed_generation?: number
      current_healthy?: number
      desired?: number
      total_pods?: number
      expected_pods?: number
      disruptions_allowed?: number
      conditions?: Array<{
        type?: string
        status?: string
        reason?: string
        message?: string
        last_transition_time?: string
      }>
    }
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/pod_disruption_budgets.test.tsx`: clone
  `network_policies.test.tsx` 1:1 (KubeDataTable fake included) with the
  network_policies namespace setup (`selectProd` sets
  `selectedNamespace: 'team-a'`), and:
  - fixture `web` (the to_dict shape, `min_available` set, status present):
    ```ts
    const web = {
      apiVersion: 'policy/v1',
      kind: 'PodDisruptionBudget',
      metadata: {
        name: 'web',
        namespace: 'team-a',
        creation_timestamp: '2026-01-02T03:04:05Z',
        labels: { team: 'a' },
        annotations: { 'pdb.kubernetes.io/managed-by': 'kubedash' },
      },
      spec: {
        min_available: 3,
        selector: { match_labels: { app: 'web' } },
        unhealthy_pod_eviction_policy: 'AlwaysAllow',
      },
      status: {
        observed_generation: 1,
        current_healthy: 4,
        desired: 3,
        total_pods: 4,
        expected_pods: 3,
        disruptions_allowed: 1,
        conditions: [
          { type: 'Available', status: 'True', reason: 'SufficientPods', message: 'PodDisruptionBudget is available' },
        ],
      },
    }
    const maxBudget = { ...web, spec: { ...web.spec, min_available: undefined, max_unavailable: 1 } }
    const freshBudget = { ...web, status: undefined } // a fresh PDB has no status
    ```
  - `renderAt` default path `/other-resource/pod-disruption-budget`; MSW
    handler on `*/api/v1/clusters/1/resources/poddisruptionbudgets`.
  - `list-renders-pdb-rows-with-data-links`: link `web` →
    `/other-resource/pod-disruption-budget/data?name=web&namespace=team-a`;
    fetch URL EXACTLY
    `/api/v1/clusters/1/resources/poddisruptionbudgets?namespace=team-a`;
    heading EXACTLY `Pod Disruption Budget List`; breadcrumb `Other
    Resources`; column headers `['Name', 'Namespace', 'Min Available', 'Max
    Unavailable', 'Allowed Disruptions']`; row shows `team-a` (namespace).
  - `list-min-max-cells`: the `web` row shows Min Available `3`, Max
    Unavailable `—`; the `maxBudget` row shows Max Unavailable `1`, Min
    Available `—` (exactly one of the pair; the absent one is `—`).
  - `list-missing-status`: the `freshBudget` row (no `status`) shows Allowed
    Disruptions `—` (no throw — 4.1 would `UndefinedError`).
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-error-state`: 403 `RBAC_DENIED` →
    `Error loading pod disruption budgets: RBAC_DENIED: list on
    poddisruptionbudgets`.
  - `list-empty-state`: `items: []` → `No pod disruption budgets found`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/pod_disruption_budgets.test.tsx`
  Expected: FAIL (cannot find module
  `src/views/OtherResource/PodDisruptionBudget`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/OtherResource/PodDisruptionBudget.tsx`: layout from
  `PriorityClass.tsx`, namespace handling from `NetworkPolicy.tsx`:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement,
    the `?name=&namespace=` delta, the certainty rule for the absent
    min/max and for a missing status (4.1's `UndefinedError`).
  - `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`
  - `type PdbRow = { name, namespace, minAvailable: string, maxUnavailable: string, allowedDisruptions: string }`:
    ```ts
    // The k8s API enforces exactly one of min_available / max_unavailable;
    // the absent one renders "—" (certainty rule: 4.1 rendered blank). A
    // fresh PDB has no status at all — 4.1's Jinja would UndefinedError on
    // `pdp.status.disruptions_allowed`; 5.0 renders "—", never guesses.
    const toRow = (item: PodDisruptionBudgetItem): PdbRow => ({
      name: item.metadata?.name ?? '',
      namespace: item.metadata?.namespace ?? namespace,
      minAvailable: item.spec?.min_available != null ? String(item.spec.min_available) : '—',
      maxUnavailable: item.spec?.max_unavailable != null ? String(item.spec.max_unavailable) : '—',
      allowedDisruptions: item.status?.disruptions_allowed != null ? String(item.status.disruptions_allowed) : '—',
    })
    ```
  - query key `['poddisruptionbudgets', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/poddisruptionbudgets?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/other-resource/pod-disruption-budget/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(row.namespace)}`
    (the row's OWN namespace — an all-namespaces list would carry mixed
    namespaces; the link must follow the row, not the store).
  - breadcrumb: Other Resources → Pod Disruption Budget List; card title
    EXACTLY `Pod Disruption Budget List`.
  - columns: Name (link) / Namespace / Min Available / Max Unavailable /
    Allowed Disruptions.
  - pinned states: `No cluster selected.`, `Loading pod disruption
    budgets...`, `Error loading pod disruption budgets: {message}`,
    `No pod disruption budgets found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/pod_disruption_budgets.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/OtherResource/PodDisruptionBudget.tsx frontend/tests/views/pod_disruption_budgets.test.tsx`
  `git commit -m "feat(frontend): pod disruption budget list view (4.1 port, namespaced)"`

### Task 3: Frontend — data view + test

**SATISFIES:** `pdb-data-renders-detail`,
`pdb-data-selector-and-eviction-policy`, `pdb-data-not-found-state`,
`pdb-data-missing-name`

**Files:**
- Create: `frontend/src/views/OtherResource/PodDisruptionBudgetData.tsx`
- Test: `frontend/tests/views/pod_disruption_budget_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item list; `[]` =
  miss) and Task 2's link (the sole producer of the `?name=&namespace=`
  strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` (no new seam).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/pod_disruption_budget_data.test.tsx`: clone
  `priority_class_data.test.tsx` 1:1 with:
  - MSW handler on
    `*/api/v1/clusters/1/resources/poddisruptionbudgets?name=web&namespace=team-a`
    returning `{ kind: 'poddisruptionbudgets', items: [web] }`; a miss
    handler (`?name=ghost&namespace=team-a`) returning `{ items: [] }`.
  - `data-renders-detail`: at
    `/other-resource/pod-disruption-budget/data?name=web&namespace=team-a` —
    assert EXACTLY ONE fetch and that its URL has `name=web` AND
    `namespace=team-a`; CTable rows: Name `web`, Namespace `team-a`, a
    Created row (via `formatTimestamp`); the Status table has rows `Allowed
    disruptions` `1`, `Current healthy` `4`, `Desired` `3`; the Conditions
    table has a row `Available / True / SufficientPods /
    PodDisruptionBudget is available`; the full-object block contains
    `"min_available": 3` (the JSON block).
  - `data-selector-and-eviction-policy`: the Selector row shows `app: web`
    (the `match_labels` key:value); the Eviction Policy row shows
    `AlwaysAllow`.
  - `data-missing-status`: a budget with no `status` → its Status rows show
    `—` for all three (no throw).
  - `data-not-found-state`: `?name=ghost&namespace=team-a` →
    `No PodDisruptionBudget 'ghost' found`; assert NO `.text-danger` node for
    it (a state, not an error).
  - `data-missing-name`: `/other-resource/pod-disruption-budget/data` (no
    param) → `Error: pod disruption budget name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]` (the CRDs
    post-ship tsc lesson — fe-build typechecks test files).

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/pod_disruption_budget_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/OtherResource/PodDisruptionBudgetData.tsx`: clone of
  `PriorityClassData.tsx` + the 4.1 Selector/Eviction-Policy/Status/
  Conditions tables:
  - docstring: single `?name=&namespace=` fetch (no 4.1 list-then-filter),
    the absent min/max and missing status render `—` (certainty rule),
    `unhealthy_pod_eviction_policy` as a proper list (4.1's tuple bug
    dropped), NOT_FOUND as a pinned STATE, the `json` hljs grammar as the
    truthful classifier (ratified 2026-10-28), the 4.1 deviations (no
    Creation duplicate row, no trimAnnotations, typed Conditions table).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read both params: `const name = params.get('name') ?? ''`,
    `const namespace = params.get('namespace') ?? ''`.
  - query key `['pdb-data', cluster?.id, namespace, name]`; enabled when
    `cluster != null && name !== '' && namespace !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/poddisruptionbudgets?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Other Resources → Pod Disruption Budget List (link) →
    `{name}`.
  - card title `Pod Disruption Budget Data`.
  - CTable rows: Name / Created / Namespace / Selector
    (`Object.entries(spec.selector?.match_labels ?? {})` as `key: value`
    lines, `—` when empty — 4.1 read ONLY `match_labels`) / Eviction Policy
    (`spec.unhealthy_pod_eviction_policy` or `—`; a proper value, not 4.1's
    tuple) / Labels / Annotations (sub-tables, `No labels` /
    `No annotations` when empty — the priorityclass twin's shape).
  - Status table (nested CTable, header `Key / Value`), rows: `Allowed
    disruptions` (`status.disruptions_allowed ?? '—'`), `Current healthy`
    (`status.current_healthy ?? '—'`), `Desired` (`status.desired ??
    '—'` — the controller-computed value from `to_dict`; no client-side
    floor math, the raw field is the source of truth).
  - Conditions table (nested CTable, header `Type / Status / Reason /
    Message`), one row per `status.conditions[]` entry (`No conditions`
    when empty) — the typed shape replacing 4.1's dynamic-key table.
  - full-object block: `JSON.stringify(item, null, 2)`, language `json`,
    style `anOldHope`, `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - pinned copy: `No PodDisruptionBudget '{name}' found`,
    `Error: pod disruption budget name not provided`,
    `Loading pod disruption budget data...`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/pod_disruption_budget_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/views/OtherResource/PodDisruptionBudgetData.tsx frontend/tests/views/pod_disruption_budget_data.test.tsx`
  `git commit -m "feat(frontend): pod disruption budget data view (4.1 tables + JSON block)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `pdb-stub-removed-and-routes-wired`

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
    path="/other-resource/pod-disruption-budget"
    element={
      <ProtectedRoute>
        <PodDisruptionBudgetView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/other-resource/pod-disruption-budget/data"
    element={
      <ProtectedRoute>
        <PodDisruptionBudgetDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 25
  (`{ path: '/other-resource/pod-disruption-budget', title: 'Pod Disruption Budget', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/other-resource/pod-disruption-budget'` to the `viewPaths` set in
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
  `git commit -m "feat(frontend): wire pod-disruption-budget routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_poddisruptionbudgets.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/pod_disruption_budgets.test.tsx tests/views/pod_disruption_budget_data.test.tsx tests/views/Stub.test.tsx` — green.
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
