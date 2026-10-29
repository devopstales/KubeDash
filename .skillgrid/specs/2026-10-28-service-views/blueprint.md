# Service Views (List + Data + Pods tab) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pair on an existing generic route + one additive
param to the existing pods route; no migration, no new dependency, no
public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, pattern already ratified
for namespaced core kinds: secrets/resourcequotas/networkpolicies; the 4.1
template pair is the source of truth for the page shape; the three-tab data
page uses the already-vendored `@coreui/react` `CTabs`/`CTab`/`CTabContent` —
confirmed present in the installed CoreUI).

**Build shape:** Tracer thread — Task 1 proves the kind end-to-end in the
backend (service methods → `_KINDS` row → API route → SAR deny) AND the
`?labelSelector=` param on the pods route (the Pods tab's second fetch needs
it) before any frontend exists; Task 2 is the list view; Task 3 the data view
(three tabs); Task 4 the routing cleanup. Each task is independently
revertable.

**Goal:** Resolve the nav leaf `/network/service` to a real, SAR-gated,
read-only list + three-tab data pair — the 4.1 Service pages ported with the
ratified 5.0 deltas — plus the `?labelSelector=` param on the pods route that
feeds the data page's Pods tab.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds ONE kind:
`K8sClient.list_services` / `get_service` (kubernetes `CoreV1Api`, core
group, **namespaced** — the `list_secrets` / `get_resource_quota` pattern, NO
field stripping, NO new `__init__` attribute — `self._v1` already exists) +
two dict rows (`_KINDS` / `_GETTERS`). Plus ONE param addition:
`K8sClient.list_pods(namespace, label_selector=None)` + the pods route reads
`request.args.get("labelSelector")` and forwards it (4.1's
`k8sPodSelectorListGet` behavior, re-implemented as a pass-through param —
the route does NOT parse or validate the selector; the kubernetes API server
is the authority). Frontend: two views (list cloned from
`Security/Secret.tsx` — namespaced, KubeDataTable; data is a NEW three-tab
layout — a CoreUI `CTabs`/`CTab`/`CTabContent` switcher — with the Service
tab a CTable + JSON block clone of `SecretData.tsx`'s shape, the Ports tab a
per-`spec.ports` CTable, and the Pods tab a per-pod CTable fed by a SECOND
parallel query on the pods route with `?labelSelector=`), `ServiceItem` /
`ServicePort` types, App.tsx routes, stub-route removal.

**Tech Stack:** kubernetes `CoreV1Api` (already the client's `self._v1` — no
new attribute; the 4.1 code used the same API), Flask + Smorest (existing
route), React + CoreUI (`CTabs`/`CTab`/`CTabContent` confirmed in the
installed `@coreui/react`) + TanStack Query + MSW (existing), no new npm/
Python dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R6).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/network/service.html.j2`
(list: Name/Type/Cluster IP/External IP — card title EXACTLY `Service List`;
the name cell is a hidden-form POST link carrying `service_name` +
`ns_select`; External IP is `service.status.load_balancer.ingress[0].ip` for
LoadBalancer else empty — a latent 500 on a pending LoadBalancer),
`4.1:src/kubedash/templates/network/service-data.html.j2` (data: a
THREE-tab page — Service / Ports / Pods — via Bootstrap-JS
`data-bs-toggle="tab"` tabs; the Service tab is Name/Type/Created/
Annotations(inline last-applied filter)/Labels("Lables" typo)/Cluster IP/
External IP; the Ports tab is Name/Port/Protocol/Target/Node Port per
`spec.ports`; the Pods tab is Status(badge)/Name(link)/IP/Node(link)/
Owner(link) per the selector-matched pods; the Ingresses tab is COMMENTED
OUT, never rendered), `4.1:src/kubedash/lib/k8s/network.py:111`
(`k8sServiceListGet`: `CoreV1Api().list_namespaced_service(ns,
_request_timeout=1)`, generates `name`/`type`/`created`/`annotations`
(trimmed)/`labels`/`selector`/`ports`/`cluster_ip`/`external_ip`),
`4.1:src/kubedash/lib/k8s/network.py:147` (`k8sPodSelectorListGet`:
`CoreV1Api().list_namespaced_pod(ns, label_selector=<comma-separated
key=value>, _request_timeout=1)`, generates `status`/`name`/`pod_ip`/
`node_name`/`owner` (the owner format `"%ss/%s" % (owner.kind.lower(),
owner.name)` is a 4.1 typo — a stray `s`)), `4.1:src/kubedash/blueprint/
network.py:119` (the list + data routes; the data page re-lists then filters
by `service_name`, and only calls `k8sPodSelectorListGet` when
`service_data["selector"]` is truthy). In-repo precedents —
`backend/app/services/k8s_client.py:250-258` (`list_pods` — the method that
gains the optional `label_selector` param), `backend/app/services/
k8s_client.py:822-852` (the `list_secrets` / `get_secret` namespaced
core-kind pattern to mirror — the `list_namespaced_*` vs
`list_*_for_all_namespaces` branch, 0/1-item getter; `list_services` differs
from `list_secrets` ONLY in NOT popping any field),
`backend/app/api/resources.py` `_KINDS`/`_GETTERS` + the `name` branch
(line ~104-114, the `namespace = namespace or "default"` fallback — the data
page always sends its namespace so the fallback is never used in practice) +
the `list_resources` route (the `pods` route that gains the
`?labelSelector=` read), `backend/tests/api/test_resources.py` (the
secrets/resourcequotas API tests to mirror + the pods tests to extend with
the labelSelector case), `frontend/src/views/Security/Secret.tsx` (the
namespaced list view to clone — header-selected namespace, ALWAYS sends
`?namespace=`, KubeDataTable), `frontend/src/views/Security/SecretData.tsx`
(the data view's CTable + `KeyValueTable` sub-tables + the JSON-block shape
to clone for the Service tab; the Pods/Ports tabs are new),
`frontend/src/views/Cluster/Pods.tsx` (the existing pod table's
`PHASE_COLOR` badge palette — the Pods tab reuses the same phase→color
mapping, re-expressed as a CoreUI badge class),
`frontend/tests/views/secrets.test.tsx` (the test pattern to clone, including
the KubeDataTable fake + the MSW `server.use` setup).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0009, ADR-0010, ADR-0020,
ADR-0021, ADR-0022. None created.

## Terms

None (the spec's vocabulary; "Service" is the k8s kind, not a new term).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/services?namespace=<ns>` → 200, `kind: "services"`,
  items in `to_dict` snake_case form WITH `spec`/`status` present (NOT
  stripped), SAR-gated on `list services` (core, the query namespace), 403
  names the resource and the client call is never made on deny
  (`services-list-200`, `services-sar-denied`).
- Without `?namespace=` the list spans all namespaces
  (`list_service_for_all_namespaces` — the `list_secrets` branch)
  (`services-list-all-namespaces`).
- `?name=&namespace=` returns a 0/1-item list through the SAME route — hit =
  the object, miss = `[]` (`services-get-by-name`).
- The singular `service` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`service-kind-singular-rejected`).
- `GET .../resources/pods?namespace=<ns>&labelSelector=<expr>` → 200, the
  pods filtered server-side by the selector (the kubernetes client's
  `label_selector` kwarg); without the param the behavior is UNCHANGED
  (`pods-labelselector-filters`, `pods-labelselector-absent-unchanged`).
- The list view fetches
  `/api/v1/clusters/<id>/resources/services?namespace=<ns>` (namespace ALWAYS
  from `useClusterStore.selectedNamespace ?? 'default'`); card title EXACTLY
  `Service List`; columns Name/Type/Cluster IP/External IP; every name links
  to `/network/service/data?name=<name>&namespace=<ns>`
  (`service-list-renders-rows-with-data-links`).
- Type cell = `spec.type` (`—` when absent); Cluster IP cell =
  `spec.cluster_ip` (`—` when absent); External IP cell =
  `status.load_balancer.ingress[0].ip` ONLY for `spec.type ==
  "LoadBalancer"`, else `—` (`service-list-external-ip-cell`).
- The data view fetches the Service ONCE with `?name=&namespace=`, renders
  three tabs (Service/Ports/Pods) via CoreUI `CTabs`, and treats a miss as
  the pinned state `No Service '<name>' found` — never an error style
  (`service-data-renders-three-tabs`, `service-data-not-found-state`).
- The Service tab renders the CTable (Name/Type/Created/Annotations/Labels/
  Cluster IP/External IP) + the JSON-highlighted full-object block;
  Annotations render VERBATIM (no last-applied filter)
  (`service-data-service-tab`).
- The Ports tab renders one row per `spec.ports` entry (Name/Port/Protocol/
  Target/Node Port, each `—` when the field is absent), `No ports` when
  `spec.ports` is absent or empty (`service-data-ports-tab`,
  `service-data-no-ports`).
- The Pods tab fires a SECOND parallel fetch on the pods route with
  `?labelSelector=<built-from-spec.selector>` ONLY when `spec.selector` is
  non-empty; renders Status(badge)/Name(plain text)/IP/Node(plain text)/
  Owner(`kind.name` with a slash, `—` when no owner refs); when
  `spec.selector` is empty OR the pods fetch returns `items: []`, renders
  `No pods match this service's selector` (muted, NOT an error, and NO fetch
  at all when the selector is empty)
  (`service-data-pods-tab`, `service-data-pods-tab-empty-selector`,
  `service-data-pods-tab-no-match`).
- The pod Owner cell is `kind.lower() + "/" + name` (the 4.1 stray-`s` typo
  is fixed — `deployment/web-abc`, not `deploymentss/web-abc`)
  (`service-data-pod-owner-format`).
- `/network/service` is gone from `views/Stub/routes.ts`; both real views are
  routed; the nav leaf is byte-identical
  (`service-stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `list_services`, `get_service`
  (new); `list_pods` (modified — gains the optional `label_selector` param).
- `backend/app/api/resources.py` — the two dict rows (modified); the
  `list_resources` route reads `?labelSelector=` for the `pods` kind
  (modified).
- `backend/tests/services/test_k8s_client_services.py` (new).
- `backend/tests/services/test_k8s_client_pods.py` (extend — the
  labelSelector cases; create if absent).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 7 new services
  tests + the pods labelSelector test (modified).
- `frontend/src/lib/types.ts` — `ServiceItem`, `ServicePort` (modified).
- `frontend/src/views/Network/Service.tsx` (new).
- `frontend/src/views/Network/ServiceData.tsx` (new).
- `frontend/tests/views/services.test.tsx` (new).
- `frontend/tests/views/service_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior: the same route
  branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows
  land in the same commit as the service methods.
- `list_services` MUST NOT strip any field — the data page's Ports tab reads
  `spec.ports`, the Pods tab reads `spec.selector`, and the list's External
  IP cell reads `status.load_balancer.ingress` — all from the full `to_dict`.
  A future refactor that "optimizes" the list by stripping `spec`/`status`
  silently breaks all three. The service method's docstring must say WHY it
  keeps the full object.
- The `?labelSelector=` param is a PLAIN STRING pass-through — the route
  forwards it to `list_pods(namespace, label_selector=...)` and does NOT
  parse or validate it (the kubernetes API server is the authority on
  selector syntax; a malformed selector is a 400 from the API, which the
  existing `ClusterUnreachableError` mapping turns into a 502). The VIEW
  builds the selector string from `spec.selector` (the view has the dict,
  the route just forwards the string). A `labelSelector` without a
  `namespace` is IGNORED (the param applies to the namespaced branch only —
  the Pods tab always sends both).
- The data view's Pods tab fires its pods query ONLY when
  `service?.spec?.selector` is a non-empty object — a headless/ExternalName
  Service with an empty selector must NOT fire a pods fetch (the query's
  `enabled` is `cluster != null && service != null &&
  Object.keys(service.spec?.selector ?? {}).length > 0`).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an
  API error (the NOT_FOUND-as-throw-not-found-state pattern from
  `SecretData.tsx`, where the `queryFn` throws on a miss and the view
  renders the throw as the pinned state).
- The `to_dict` form is snake_case for `metadata` fields
  (`creation_timestamp`, `resource_version`) and the `spec`/`status` field
  names are the API's casing: `spec.type`, `spec.cluster_ip`,
  `spec.selector`, `spec.ports`, `spec.node_name`, `status.load_balancer.
  ingress`, `status.pod_ip`, `status.phase`, `metadata.owner_references`
  (verify against the kubernetes Python client's `to_dict` — the field names
  for `spec`/`status` are snake_case in the generated model: `cluster_ip`,
  `load_balancer`, `pod_ip`, `node_name`, `owner_references`, `target_port`,
  `node_port`).
- `Stub.test.tsx`'s `expectedStubs()` builds the expected list from the nav
  minus a `viewPaths` set of real-view paths: removing the route from
  `stubRoutes` WITHOUT adding the path to `viewPaths` is a RED frontend suite.

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table and the pods param are additive).

## Global Constraints

- No new Python dependency — `CoreV1Api` is already the client's `self._v1`
  (NO new `__init__` attribute needed); the Service methods and the
  `list_pods` param change use the same `self._v1` attribute (air-gap,
  ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported by `SecretData.tsx`; the `json` grammar is already registered
  there; `@coreui/react` already exports `CTabs`/`CTab`/`CTabContent`
  (confirmed in the installed package).
- Namespaced kind (core group, v1): the list URL carries `?namespace=` when
  given; the data URL carries `?name=&namespace=` (the page always sends
  both); SAR group = `""`, namespace = the query namespace or `None`.
- The `to_dict` form: `metadata` fields are snake_case
  (`creation_timestamp`, `resource_version`, `owner_references`), the
  `spec`/`status` field names are snake_case in the generated model
  (`cluster_ip`, `load_balancer`, `pod_ip`, `node_name`, `target_port`,
  `node_port`), `spec.type`/`spec.selector`/`spec.ports`/`spec.protocol`
  are the field names unchanged.
- The `?labelSelector=` param is a plain string (comma-separated
  `key=value`), passed through to `list_namespaced_pod`'s `label_selector`
  kwarg — NOT parsed, NOT validated by the route.
- The full-object block on the Service tab is `JSON.stringify(item, null, 2)`
  with hljs grammar `json`, style `anOldHope` (the truthful-classifier rule,
  ratified PriorityClassData final review 2026-10-28). NOT YAML.
- Card title EXACTLY `Service List` (4.1's title, verbatim — the e2e-smoke
  contract).
- Pinned copy (do not reword): `No services found`,
  `No Service '<name>' found`, `Error: service name not provided`,
  `No cluster selected.`, `Loading services...`, `No labels`,
  `No annotations`, `No ports`, `No pods match this service's selector`.
- The three tabs are CoreUI `CTabs`/`CTab`/`CTabContent` (React tabs), NOT
  4.1's Bootstrap-JS `data-bs-toggle="tab"` tabs.
- Conventional commits; spec-zone commits precede code-zone commits
  (pre-commit zone guard); WHY-comments on load-bearing invariants
  (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too (CRDs post-ship lesson)
  — type any new test params (e.g. MSW `server.use` spreads) explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `list_pods` (line ~250,
  gains the optional `label_selector` param); `list_services` next to
  `list_secrets` (line ~822); `get_service` next to `get_secret`
  (line ~839).
- `backend/app/api/resources.py` (modify) —
  `_KINDS["services"]` + `_GETTERS["services"]`; the `list_resources` route
  reads `request.args.get("labelSelector")` and forwards it to
  `list_pods` when the kind is `pods`.
- `backend/tests/services/test_k8s_client_services.py` (new) —
  `object.__new__` + `SimpleNamespace` fake.
- `backend/tests/services/test_k8s_client_pods.py` (new or extend) — the
  `list_pods` labelSelector cases.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `list_services` / `get_service` + the `list_pods` labelSelector fake; 7
  new services tests + 1 pods labelSelector test.
- `frontend/src/lib/types.ts` (modify) — `ServiceItem`, `ServicePort` next
  to `K8sSecret`.
- `frontend/src/views/Network/Service.tsx` (new) — namespaced layout from
  `Security/Secret.tsx` with the Type/Cluster IP/External IP columns.
- `frontend/src/views/Network/ServiceData.tsx` (new) — a NEW three-tab
  layout (CoreUI `CTabs`) — the Service tab a CTable + JSON block (the
  `SecretData.tsx` shape), the Ports tab a per-`spec.ports` CTable, the Pods
  tab a per-pod CTable fed by a second pods query with `?labelSelector=`.
- `frontend/tests/views/services.test.tsx` (new).
- `frontend/tests/views/service_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — two routes after the secret pair
  (line ~343-355) + the two view imports (after line 44).
- `frontend/src/views/Stub/routes.ts` (modify) — drop line 15
  (`/network/service`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the path to the
  `viewPaths` set.
- `frontend/src/_nav.tsx` (UNCHANGED — listed for the deletion test).

---

### Task 1: Backend — services kind + pods `?labelSelector=` (service + `_KINDS` + API tests)

**SATISFIES:** `services-list-200`, `services-list-all-namespaces`,
`services-sar-denied`, `services-binding-404`,
`service-kind-singular-rejected`, `services-get-by-name`,
`pods-labelselector-filters`, `pods-labelselector-absent-unchanged`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_services.py` (new)
- Test: `backend/tests/services/test_k8s_client_pods.py` (new or extend)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing from other tasks (this is the first code task).
- Produces: `K8sClient.list_services(namespace: str | None) -> list[dict]`
  and `K8sClient.get_service(namespace: str, name: str) -> list[dict]` —
  the exact names `_KINDS`/`_GETTERS` reference via `getattr`; and
  `K8sClient.list_pods(namespace: str | None, label_selector: str | None =
  None) -> list[dict]` — the existing method with an optional param.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the secrets/resourcequotas/pods tests).
- Deletion test: delete the two `_KINDS`/`_GETTERS` rows → the kind 404s
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail at the `object.__new__` stub setup; revert the
  `list_pods` param → the pods labelSelector test fails.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** —
  `backend/tests/services/test_k8s_client_services.py`, mirroring the
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


  def test_list_services_namespaced_keeps_spec_status() -> None:
      """[services-list-200] the namespaced branch uses
      ``list_namespaced_service`` and, UNLIKE ``list_secrets``, does NOT
      strip any field — the data page's Ports/Pods tabs and the list's
      External IP cell read ``spec``/``status`` from the full ``to_dict``."""
      seen: list[str] = []
      item = SimpleNamespace(
          to_dict=lambda: {
              "metadata": {"name": "web-svc", "namespace": "team-a",
                           "creation_timestamp": "2026-01-02T03:04:05Z",
                           "resource_version": "4242",
                           "labels": {"app": "web"}},
              "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                       "selector": {"app": "web"},
                       "ports": [{"name": "http", "port": 80,
                                  "target_port": 8080, "protocol": "TCP"}]},
              "status": {"load_balancer": {"ingress": [{"ip": "203.0.113.5"}]}},
          }
      )
      v1 = SimpleNamespace(
          list_namespaced_service=lambda ns: (seen.append(ns), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_services("team-a")
      assert result[0]["metadata"]["name"] == "web-svc"
      assert result[0]["spec"]["cluster_ip"] == "10.0.0.1"
      assert result[0]["status"]["load_balancer"]["ingress"][0]["ip"] == "203.0.113.5"
      assert seen == ["team-a"]


  def test_list_services_all_namespaces_when_namespace_none() -> None:
      """[services-list-all-namespaces] ``None`` uses the all-namespaces
      call (the ``list_secrets`` branch)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-svc"}})
      v1 = SimpleNamespace(
          list_service_for_all_namespaces=lambda: (seen.append(True), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_services(None)
      assert result[0]["metadata"]["name"] == "web-svc"
      assert seen == [True]


  def test_list_services_maps_500_to_unreachable() -> None:
      def list_all() -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(list_namespaced_service=list_all)).list_services("team-a")


  def test_get_service_404_returns_empty_list() -> None:
      """[services-get-by-name] a miss is ``[]`` (the ``get_secret``
      contract)."""
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=404)

      assert _client(SimpleNamespace(read_namespaced_service=read))
          .get_service("team-a", "ghost") == []


  def test_get_service_hit_returns_one_item_with_spec() -> None:
      item = SimpleNamespace(to_dict=lambda: {
          "metadata": {"name": "web-svc"},
          "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                   "selector": {"app": "web"}},
      })
      v1 = SimpleNamespace(read_namespaced_service=lambda name, ns: item)
      assert _client(v1).get_service("team-a", "web-svc") == [
          {"metadata": {"name": "web-svc"},
           "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                    "selector": {"app": "web"}}}
      ]


  def test_get_service_other_api_error_maps_to_unreachable() -> None:
      def read(name: str, namespace: str) -> None:
          raise ApiException(status=500)

      with pytest.raises(ClusterUnreachableError):
          _client(SimpleNamespace(read_namespaced_service=read))
          .get_service("team-a", "web-svc")
  ```

- [ ] **Step 2: Write the failing `list_pods` labelSelector tests** —
  `backend/tests/services/test_k8s_client_pods.py` (new, or extend the
  existing pods test file if one exists):

  ```python
  from types import SimpleNamespace

  def _client(v1: object) -> K8sClient:
      client = object.__new__(K8sClient)
      client._v1 = v1
      return client


  def test_list_pods_forwards_label_selector() -> None:
      """[pods-labelselector-filters] the ``label_selector`` is passed
      through to ``list_namespaced_pod`` (4.1's ``k8sPodSelectorListGet``
      behavior, re-implemented as a pass-through param)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-abc"}})
      v1 = SimpleNamespace(
          list_namespaced_pod=lambda ns, label_selector=None: (
              seen.append(label_selector), SimpleNamespace(items=[item]))[1]
      )
      result = _client(v1).list_pods("team-a", label_selector="app=web")
      assert result[0]["metadata"]["name"] == "web-abc"
      assert seen == ["app=web"]


  def test_list_pods_no_label_selector_unchanged() -> None:
      """[pods-labelselector-absent-unchanged] without a ``label_selector``
      the call is the existing unfiltered list (``label_selector=None``)."""
      seen: list[object] = []
      item = SimpleNamespace(to_dict=lambda: {"metadata": {"name": "web-abc"}})
      v1 = SimpleNamespace(
          list_namespaced_pod=lambda ns, label_selector=None: (
              seen.append(label_selector), SimpleNamespace(items=[item]))[1]
      )
      _client(v1).list_pods("team-a")
      assert seen == [None]
  ```

- [ ] **Step 3: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_services.py tests/services/test_k8s_client_pods.py -q`.
  Expected: FAIL (no `list_services`/`get_service`; `list_pods` has no
  `label_selector` param).

- [ ] **Step 4: Implement the service methods + the `list_pods` param** —
  `k8s_client.py`:

  `list_pods` (line ~250) — add the optional param:
  ```python
  def list_pods(self, namespace: str | None, label_selector: str | None = None) -> list[dict[str, Any]]:
      """Pod list in the standard kubernetes dict form (``to_dict``).
      ``label_selector`` (optional) is a comma-separated ``key=value``
      equality expression passed through to ``list_namespaced_pod``'s
      ``label_selector`` kwarg (4.1's ``k8sPodSelectorListGet`` behavior) —
      it applies to the namespaced branch only; a ``label_selector`` without
      a ``namespace`` is ignored (the all-namespaces branch is unchanged).
      The route does NOT parse or validate the selector (the kubernetes API
      server is the authority on selector syntax)."""
      resp = (
          self._v1.list_namespaced_pod(namespace, label_selector=label_selector)
          if namespace
          else self._v1.list_pod_for_all_namespaces()
      )
      return [p.to_dict() for p in resp.items]
  ```

  Next to `list_secrets` (line ~822):
  ```python
  def list_services(self, namespace: str | None) -> list[dict[str, Any]]:
      """Service list in the standard kubernetes dict form (``to_dict``) for
      one namespace, or across all namespaces when the namespace is ``None``
      (the ``list_secrets`` branch). UNLIKE ``list_secrets`` this does NOT
      strip any field: a Service's ``spec`` (type, cluster_ip, ports,
      selector) and ``status`` (load_balancer) are public, and the data
      page's Ports/Pods tabs + the list's External IP cell read them —
      stripping would silently break all three. A transport ApiException
      maps to ``ClusterUnreachableError`` (502)."""
      try:
          resp = (
              self._v1.list_namespaced_service(namespace)
              if namespace
              else self._v1.list_service_for_all_namespaces()
          )
      except ApiException as e:
          self._unreachable("list_services", e)
          raise AssertionError("unreachable") from e
      return [svc.to_dict() for svc in resp.items]
  ```

  Next to `get_secret` (line ~839):
  ```python
  def get_service(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One Service (full ``spec``/``status`` intact) as a 0/1-item list;
      ``[]`` on 404. Any other ApiException maps to
      ``ClusterUnreachableError`` (502), matching ``get_secret``'s transport
      contract."""
      try:
          return [self._v1.read_namespaced_service(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_service", e)
          raise AssertionError("unreachable") from e
  ```

- [ ] **Step 5: Wire the kind + the pods param + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # Service (core, namespaced) — the 4.1-parity nav leaf resolved by the
  # service-views change (list + three-tab data views; ADR-0022 placement).
  # The 4.1 route name was "service"; the API kind is the plural.
  "services": ("list_services", "services", ""),
  ```
  in `_KINDS` (after the resourcequotas row; core group = `""`), and
  ```python
  "services": "get_service",
  ```
  in `_GETTERS`.

  In the `list_resources` route, the pods branch (line ~120-122) — read the
  `?labelSelector=` param and forward it ONLY for the `pods` kind:
  ```python
  # The existing list branch (line ~120-122) becomes:
  label_selector = request.args.get("labelSelector") if kind == "pods" else None
  items = getattr(pool.get(cluster), method)(
      namespace, label_selector
  ) if kind == "pods" else getattr(pool.get(cluster), method)(namespace)
  ```
  (the `label_selector` is forwarded to `list_pods` only — the other kinds'
  `list_*` methods take a single `namespace` arg; do NOT change their
  call signature. The cleanest form: a small `if kind == "pods"` branch
  that calls `list_pods(namespace, label_selector)`, else the existing
  `method(namespace)` — keep the other kinds' call untouched.)

  Then `backend/tests/api/test_resources.py` (mirror the secrets/resourcequotas
  block + extend the pods tests):
  - FakeK8s gains:
    ```python
    def list_services(self, namespace: str | None) -> list[dict]:
        # Namespaced (core v1): None -> all-namespaces branch (mirrors the
        # real K8sClient.list_services). Full spec/status present (NOT
        # stripped) — the data page's Ports/Pods tabs + the list's External
        # IP cell read them.
        self.last_service_namespace = namespace
        return [
            {
                "metadata": {
                    "name": "web-svc", "namespace": "team-a",
                    "creation_timestamp": "2026-01-02T03:04:05Z",
                    "resource_version": "4242",
                    "labels": {"app": "web"},
                    "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}", "owner": "platform"},
                },
                "spec": {"type": "ClusterIP", "cluster_ip": "10.0.0.1",
                         "selector": {"app": "web"},
                         "ports": [{"name": "http", "port": 80,
                                    "target_port": 8080, "protocol": "TCP"}]},
            },
            {
                "metadata": {"name": "lb-svc", "namespace": "team-a",
                             "creation_timestamp": "2026-01-03T00:00:00Z"},
                "spec": {"type": "LoadBalancer", "cluster_ip": "10.0.0.2",
                         "selector": {"app": "lb"}},
                "status": {"load_balancer": {"ingress": [{"ip": "203.0.113.9"}]}},
            },
            {"metadata": {"name": "headless-svc", "namespace": "team-a",
                          "creation_timestamp": "2026-01-04T00:00:00Z"},
             "spec": {"type": "ClusterIP", "cluster_ip": "None",
                      "selector": {}}},
        ]

    def get_service(self, namespace: str, name: str) -> list[dict]:
        return [svc for svc in self.list_services(namespace)
                if svc["metadata"]["name"] == name]
    ```
  - AND the FakeK8s `list_pods` (the existing pods fake) gains the
    `label_selector` param + records it:
    ```python
    def list_pods(self, namespace: str | None, label_selector: str | None = None) -> list[dict]:
        self.last_pod_label_selector = label_selector
        # return the existing fake pod list (unchanged)
        ...
    ```
  - Seven new services tests mirroring the secrets block, same docstring-tag
    style:
    - `test_list_services_200` — `?namespace=team-a` → 200,
      `body["kind"] == "services"`, items in `to_dict` form; assert the
      first item's `spec`/`status` are present (NOT stripped).
    - `test_list_services_all_namespaces` — no `?namespace=` → 200; assert
      the FakeK8s received `None` (the all-namespaces branch).
    - `test_list_services_get_by_name` —
      `?name=web-svc&namespace=team-a` → 1 item;
      `?name=ghost&namespace=team-a` → `items == []`.
    - `test_list_services_sar_denied` — SAR denies; 403; assert
      `("list", "services", "team-a", None, "")` in `asked` (the namespace
      forwarded, core group `""` — the load-bearing assertions).
    - `test_services_binding_404` — cluster 999, unbound user → 404.
    - `test_service_kind_singular_rejected` —
      `/resources/service` → 404 `RESOURCE_KIND_NOT_SUPPORTED`.
    - `test_pods_labelselector_forwarded` —
      `GET .../resources/pods?namespace=team-a&labelSelector=app=web` → 200;
      assert the FakeK8s `list_pods` received `label_selector="app=web"`
      (the pass-through, the load-bearing assertion).
    - `test_pods_no_labelselector_unchanged` —
      `GET .../resources/pods?namespace=team-a` → 200; assert the FakeK8s
      `list_pods` received `label_selector=None` (the existing behavior).

- [ ] **Step 6: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_services.py tests/services/test_k8s_client_pods.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).

- [ ] **Step 7: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_services.py backend/tests/services/test_k8s_client_pods.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): services kind + pods labelSelector param (core, namespaced, SAR-gated)"`

### Task 2: Frontend — list view + test

**SATISFIES:** `service-list-renders-rows-with-data-links`,
`service-list-external-ip-cell`, `service-list-empty-state`

**Files:**
- Modify: `frontend/src/lib/types.ts`
- Create: `frontend/src/views/Network/Service.tsx`
- Test: `frontend/tests/views/services.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `services` list URL, namespaced).
- Produces: the data-page link
  `/network/service/data?name=<name>&namespace=<ns>` — the SOLE producer
  of those query strings.
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` +
  `useClusterStore.selectedNamespace` (the secret view's seams).
- Deletion test: deleting the view → the route (Task 4) 404s / the test
  file fails at import.
- Adapters: 1 (in-process); no port.

- [ ] **Step 1: Add the types** — `frontend/src/lib/types.ts`, next to
  `K8sSecret`:

  ```ts
  /** A Service port entry (kubernetes to_dict, snake_case). */
  export interface ServicePort {
    name?: string
    port: number
    protocol?: string
    target_port?: number | string
    node_port?: number
  }

  /** A Service item as returned by /api/v1/clusters/<id>/resources/services (kubernetes to_dict; namespaced, core v1). ``spec``/``status`` are present (NOT stripped, unlike secrets). */
  export interface ServiceItem {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      resource_version?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
    }
    spec?: {
      type?: string
      cluster_ip?: string
      selector?: Record<string, string>
      ports?: ServicePort[]
    }
    status?: {
      load_balancer?: { ingress?: { ip?: string; hostname?: string }[] }
    }
    [key: string]: unknown
  }
  ```

- [ ] **Step 2: Write the failing view tests** —
  `frontend/tests/views/services.test.tsx`: clone
  `secrets.test.tsx` (the namespaced pattern + the KubeDataTable fake + the
  MSW `server.use` setup) and:
  - fixtures (the to_dict shape from Task 1's FakeK8s):
    ```ts
    const webSvc = {
      metadata: { name: 'web-svc', namespace: 'team-a',
        creation_timestamp: '2026-01-02T03:04:05Z', resource_version: '4242',
        labels: { app: 'web' } },
      spec: { type: 'ClusterIP', cluster_ip: '10.0.0.1', selector: { app: 'web' },
        ports: [{ name: 'http', port: 80, target_port: 8080, protocol: 'TCP' }] },
    }
    const lbSvc = {
      metadata: { name: 'lb-svc', namespace: 'team-a',
        creation_timestamp: '2026-01-03T00:00:00Z' },
      spec: { type: 'LoadBalancer', cluster_ip: '10.0.0.2', selector: { app: 'lb' } },
      status: { load_balancer: { ingress: [{ ip: '203.0.113.9' }] } },
    }
    const headlessSvc = {
      metadata: { name: 'headless-svc', namespace: 'team-a',
        creation_timestamp: '2026-01-04T00:00:00Z' },
      spec: { type: 'ClusterIP', cluster_ip: 'None', selector: {} },
    }
    ```
  - `renderAt` default path `/network/service`; MSW handler on
    `*/api/v1/clusters/1/resources/services`.
  - `list-renders-service-rows-with-data-links`: links `web-svc` →
    `/network/service/data?name=web-svc&namespace=team-a`; fetch URL has
    `namespace=team-a`; heading EXACTLY `Service List`; breadcrumb `Network`;
    column headers `['Name', 'Type', 'Cluster IP', 'External IP']`.
  - `list-external-ip-cell`: `lb-svc` (LoadBalancer) External IP =
    `203.0.113.9`; `web-svc` (ClusterIP) External IP = `—`; a LoadBalancer
    with no `status.load_balancer.ingress` External IP = `—` (the 4.1
    deep-index 500 fix).
  - `list-no-cluster-state`: no fetch, `No cluster selected.`.
  - `list-empty-state`: `items: []` → `No services found`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]`.

- [ ] **Step 3: Run, confirm RED** — from `frontend/`:
  `corepack pnpm vitest run tests/views/services.test.tsx`
  Expected: FAIL (cannot find module `src/views/Network/Service`).

- [ ] **Step 4: Implement the view** —
  `frontend/src/views/Network/Service.tsx`: namespaced layout from
  `Security/Secret.tsx` with the Type/Cluster IP/External IP columns:
  - docstring: cite the 4.1 templates (the real port), ADR-0022 placement
    (Network), the `?name=&namespace=` delta, the External IP cell's
    LoadBalancer-only + deep-index-500-fix contract.
  - `const cluster = useClusterStore((s) => s.selectedCluster)`;
    `const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'`.
  - `type ServiceRow = { name: string; type: string; clusterIp: string; externalIp: string }`:
    ```ts
    // 4.1's External IP: status.load_balancer.ingress[0].ip for a
    // LoadBalancer, else "—". The 4.1 deep-index (ingress[0].ip) 500s on a
    // pending LoadBalancer with no ingress yet — 5.0 renders "—" for absent
    // ingress/ip (certainty rule: never crash the row).
    const externalIp = (item: ServiceItem): string => {
      if (item.spec?.type !== 'LoadBalancer') return '—'
      const ingress = item.status?.load_balancer?.ingress?.[0]
      return ingress?.ip ?? '—'
    }
    const toRow = (item: ServiceItem): ServiceRow => ({
      name: item.metadata?.name ?? '',
      type: item.spec?.type ?? '—',
      clusterIp: item.spec?.cluster_ip ?? '—',
      externalIp: externalIp(item),
    })
    ```
  - query key `['services', cluster?.id, namespace]`; URL
    `/api/v1/clusters/${cluster!.id}/resources/services?namespace=${encodeURIComponent(namespace)}`.
  - name link →
    `/network/service/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
  - breadcrumb: Network → Service List; card title EXACTLY `Service List`.
  - columns: Name (link) / Type / Cluster IP / External IP.
  - pinned states: `No cluster selected.`, `Loading services...`,
    `Error loading services: {message}`, `No services found`.

- [ ] **Step 5: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/services.test.tsx`.

- [ ] **Step 6: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Network/Service.tsx frontend/tests/views/services.test.tsx`
  `git commit -m "feat(frontend): service list view (4.1 port, external-ip 500 fix)"`

### Task 3: Frontend — three-tab data view + test

**SATISFIES:** `service-data-renders-three-tabs`,
`service-data-service-tab`, `service-data-ports-tab`,
`service-data-no-ports`, `service-data-pods-tab`,
`service-data-pods-tab-empty-selector`,
`service-data-pods-tab-no-match`,
`service-data-pod-owner-format`,
`service-data-not-found-state`, `service-data-missing-name`

**Files:**
- Create: `frontend/src/views/Network/ServiceData.tsx`
- Test: `frontend/tests/views/service_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's `?name=&namespace=` contract (0/1-item list; `[]` =
  miss) AND Task 1's pods `?labelSelector=` contract (the Pods tab's second
  fetch); Task 2's link (the sole producer of the `?name=&namespace=`
  strings).
- Produces: nothing downstream.
- Seam: `apiFetch` + `useSearchParams` + TanStack Query (TWO queries — the
  service fetch + the conditional pods fetch).
- Deletion test: deleting the view → the data route (Task 4) 404s.
- Adapters: 1; no port.

- [ ] **Step 1: Write the failing view tests** —
  `frontend/tests/views/service_data.test.tsx`: clone
  `secrets.test.tsx`'s data-view section 1:1 + the CTabs assertions:
  - MSW handlers:
    - `*/api/v1/clusters/1/resources/services?name=web-svc&namespace=team-a`
      → `{ kind: 'services', items: [webSvc] }`; a miss handler
      (`?name=ghost&namespace=team-a`) → `{ items: [] }`.
    - `*/api/v1/clusters/1/resources/pods?namespace=team-a&labelSelector=app=web`
      → `{ kind: 'pods', items: [pod1, pod2] }` where
      ```ts
      const pod1 = { metadata: { name: 'web-abc', namespace: 'team-a',
        owner_references: [{ kind: 'ReplicaSet', name: 'web-abc123' }] },
        status: { phase: 'Running', pod_ip: '10.1.0.5' },
        spec: { node_name: 'node-1' } }
      const pod2 = { metadata: { name: 'web-def', namespace: 'team-a' },
        status: { phase: 'Pending' } }
      ```
    - For the empty-selector case, a service fixture with
      `spec.selector = {}` (no pods fetch should fire).
  - `data-renders-three-tabs`: at
    `/network/service/data?name=web-svc&namespace=team-a` — assert the CTabs
    renders three tabs (Service active by default, Ports, Pods); assert
    EXACTLY ONE service fetch with `name=web-svc` AND `namespace=team-a`.
  - `data-service-tab`: the Service tab (default active) shows the CTable
    rows Name `web-svc`, Type `ClusterIP`, Cluster IP `10.0.0.1`, External
    IP `—` (ClusterIP), a Created row (via `formatTimestamp`), a Labels
    sub-table `app: web`, an Annotations sub-table with BOTH the
    last-applied-configuration key AND `owner: platform` (verbatim — no
    trim); the full-object block contains `"cluster_ip": "10.0.0.1"`.
  - `data-ports-tab`: clicking the Ports tab shows the CTable with ONE row
    (Name `http`, Port `80`, Protocol `TCP`, Target `8080`, Node Port `—`
    — ClusterIP has no node_port).
  - `data-no-ports`: a service with no `spec.ports` → the Ports tab shows
    `No ports`.
  - `data-pods-tab`: clicking the Pods tab fires a SECOND fetch on
    `*/resources/pods?namespace=team-a&labelSelector=app=web`; shows two
    rows — pod1: Status `Running` (success badge), Name `web-abc`, IP
    `10.1.0.5`, Node `node-1`, Owner `replicaset/web-abc123` (the kind
    lowercased + `/` + name — the 4.1 stray-`s` typo fixed); pod2: Status
    `Pending` (warning badge), Name `web-def`, IP `—`, Node `—`, Owner `—`.
  - `data-pods-tab-empty-selector`: a service with `spec.selector = {}` →
    the Pods tab shows `No pods match this service's selector` AND NO pods
    fetch is made (assert the MSW pods handler was not called).
  - `data-pods-tab-no-match`: a service with a non-empty selector but the
    pods fetch returns `items: []` → the Pods tab shows `No pods match this
    service's selector` (muted, NOT an error).
  - `data-not-found-state`: `?name=ghost&namespace=team-a` → `No Service
    'ghost' found`; assert NO `.text-danger` node for it.
  - `data-missing-name`: `/network/service/data?namespace=team-a` (no name)
    → `Error: service name not provided`.
  - Type any `server.use(...)` handler spreads as `AnyHandler[]`.

- [ ] **Step 2: Run, confirm RED** —
  `corepack pnpm vitest run tests/views/service_data.test.tsx`
  Expected: FAIL (module not found).

- [ ] **Step 3: Implement the view** —
  `frontend/src/views/Network/ServiceData.tsx`: a NEW three-tab layout
  (CoreUI `CTabs`/`CTab`/`CTabContent`) — the Service tab a CTable + JSON
  block (the `SecretData.tsx` shape), the Ports tab a per-`spec.ports`
  CTable, the Pods tab a per-pod CTable:
  - docstring: single `?name=&namespace=` service fetch (no 4.1
    list-then-filter) + a SECOND conditional pods fetch with
    `?labelSelector=` (built from `spec.selector`, only when non-empty);
    NOT_FOUND as a pinned STATE; the `json` hljs grammar as the truthful
    classifier (ratified 2026-10-28); the three tabs are CoreUI `CTabs`
    (NOT 4.1's Bootstrap-JS tabs); the 4.1 deviations (the "Lables" typo NOT
    replicated, `trimAnnotations` NOT replicated — annotations verbatim, the
    pod/node cells plain text not hidden-form links, the pod owner format
    fixed, the External IP deep-index 500 fixed).
  - `SyntaxHighlighter.registerLanguage('json', json)` (harmless
    re-register — the module is a singleton).
  - read the params: `const name = params.get('name') ?? ''`;
    `const namespace = params.get('namespace') ??
    useClusterStore.getState().selectedNamespace ?? 'default'`.
  - **Service query**: key `['service-data', cluster?.id, name, namespace]`;
    enabled when `cluster != null && name !== ''`; URL
    `/api/v1/clusters/${cluster!.id}/resources/services?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`.
    The `queryFn` throws on a miss (the `SecretData.tsx` pattern); the view
    renders the throw as the pinned NOT_FOUND state.
  - **Pods query** (the second fetch): key
    `['service-pods', cluster?.id, namespace, name, labelSelector]` where
    `labelSelector = Object.entries(service?.spec?.selector ?? {})
    .map(([k, v]) => `${k}=${v}`).join(',')` (4.1's format); enabled when
    `cluster != null && service != null && labelSelector !== ''` (NO fetch
    when the selector is empty — the load-bearing `enabled` gate); URL
    `/api/v1/clusters/${cluster!.id}/resources/pods?namespace=${encodeURIComponent(namespace)}&labelSelector=${encodeURIComponent(labelSelector)}`.
  - breadcrumb: Network → Service List (link) → `{name}`.
  - card title `Service Data`.
  - **CTabs** (the three-tab switcher — CoreUI `CTabs`/`CTab`/`CTabContent`):
    ```tsx
    <CTabs>
      <CTab title="Service" contentClassName="pt-3">
        {/* the Service tab: CTable + JSON block */}
      </CTab>
      <CTab title="Ports">
        {/* the Ports tab: per-spec.ports CTable */}
      </CTab>
      <CTab title="Pods">
        {/* the Pods tab: per-pod CTable or the empty state */}
      </CTab>
    </CTabs>
    ```
  - **Service tab** CTable rows (4.1's Service tab row set, the "Lables"
    typo fixed, `trimAnnotations` NOT replicated): Name / Type
    (`service?.spec?.type ?? '—'`) / Created
    (`formatTimestamp(service?.metadata?.creation_timestamp)`) / Annotations
    (sub-table, `No annotations` when empty — rendered VERBATIM including
    last-applied-configuration) / Labels (sub-table, `No labels` when empty)
    / Cluster IP (`service?.spec?.cluster_ip ?? '—'`) / External IP (the
    `externalIp()` helper from Task 2, `—` when not a LoadBalancer or no
    ingress). Below the CTable, the full-object block:
    `JSON.stringify(service, null, 2)`, language `json`, style `anOldHope`,
    `wrapLongLines`, `customStyle={{ margin: 0 }}`.
  - **Ports tab** CTable (one row per `spec.ports` entry, `No ports` when
    `spec.ports` is absent or empty): Name (`port.name ?? '—'`) / Port
    (`port.port`) / Protocol (`port.protocol ?? '—'`) / Target
    (`port.target_port ?? '—'`) / Node Port (`port.node_port ?? '—'`).
  - **Pods tab**: when `labelSelector === ''` OR the pods query is not
    enabled → `<div className="text-muted">No pods match this service's
    selector</div>`. When enabled and loading → `Loading pods...`. When
    enabled and `items: []` → the same `No pods match this service's
    selector` muted state. When enabled and items present → a CTable
    (Status/Name/IP/Node/Owner):
    ```tsx
    const PHASE_BADGE: Record<string, string> = {
      Running: 'badge-success',
      Pending: 'badge-warning',
      Succeeded: 'badge-secondary',
      // else info (4.1's four-tier badge pair)
    }
    // Status = phase badge (Running→success, Pending→warning,
    // Succeeded→secondary, else info; "—" when absent)
    // Name = metadata.name (PLAIN TEXT — the 4.1 pod-data link is NOT
    // replicated; 5.0 has no /workload/pod/data destination yet)
    // IP = status.pod_ip ?? "—"
    // Node = spec.node_name ?? "—" (PLAIN TEXT — the 4.1 node-data link is
    // a non-goal for this change)
    // Owner = the first metadata.owner_references entry, rendered
    // kind.lower() + "/" + name (4.1's "%ss/%s" typo is fixed — the stray
    // "s" is dropped); "—" when there are no owner references
    const owner = (pod: Pod): string => {
      const ref = pod.metadata?.owner_references?.[0]
      if (!ref) return '—'
      return `${String((ref as { kind?: string }).kind ?? '').toLowerCase()}/${(ref as { name?: string }).name ?? ''}`
    }
    ```
    (the `Pod` type needs `spec.node_name` + `metadata.owner_references` —
    add them to the existing `Pod` interface in `types.ts` if absent, with
    the `[key: string]: unknown` index signature already present).
  - pinned copy: `No Service '{name}' found`,
    `Error: service name not provided`, `Loading service data...`,
    `Loading pods...`, `No ports`, `No pods match this service's selector`,
    `No labels`, `No annotations`.

- [ ] **Step 4: Run, confirm GREEN** —
  `corepack pnpm vitest run tests/views/service_data.test.tsx`.

- [ ] **Step 5: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Network/ServiceData.tsx frontend/tests/views/service_data.test.tsx`
  `git commit -m "feat(frontend): service three-tab data view (4.1 port + pods labelSelector)"`

### Task 4: Routing — App.tsx + stub removal + full verification

**SATISFIES:** `service-stub-removed-and-routes-wired`

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
  (line ~355), mirror the block:
  ```tsx
  <Route
    path="/network/service"
    element={
      <ProtectedRoute>
        <ServiceView />
      </ProtectedRoute>
    }
  />
  <Route
    path="/network/service/data"
    element={
      <ProtectedRoute>
        <ServiceDataView />
      </ProtectedRoute>
    }
  />
  ```

- [ ] **Step 2: Remove the stub** — `views/Stub/routes.ts`: delete line 15
  (`{ path: '/network/service', title: 'Services', admin: false }`).
  `_nav.tsx` is UNCHANGED (verify with `git diff --stat` — it must not
  appear).

- [ ] **Step 3: Update Stub.test.tsx** — add
  `'/network/service'` to the `viewPaths` set in `expectedStubs()` (the test
  derives expected stubs from the nav minus `viewPaths`; without the
  addition the removed route is a RED suite).
  Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.

- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build — tsc covers test
    files; the AnyHandler typing from Tasks 2–3 must hold; the `Pod` type
    extension in Task 3 must typecheck).
  - `task fe-check` (air-gap assertion — no new external refs; the JSON
    block uses the already-vendored syntax highlighter; the `CTabs` are from
    the already-vendored `@coreui/react`).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures — users/groups/admin_permissions — are the baseline, nothing
    new).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).

- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire service routes, remove stub"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_services.py tests/services/test_k8s_client_pods.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/services.test.tsx tests/views/service_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` absent; no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend kind + pods param) ──► Task 2 (list view) ──► Task 4 (routing)
                          └──────────► Task 3 (three-tab data view) ──┘
```

Tasks 2 and 3 are independent of each other (both consume Task 1; Task 3
also consumes Task 1's pods `?labelSelector=` param for the Pods tab); either
can run first or in parallel. Task 4 last (it removes the stub, so the views
must exist first).

## Rollback

Each task is one conventional commit and independently revertable (no
schema, no dependency, no public contract change). Reverting Task 4 is
self-contained (route + stub removal + test in one commit). Reverting Task
1's pods `?labelSelector=` param (while keeping the services kind) leaves
the data page's Pods tab permanently empty (its query 404s on the unknown
param and the client-side degrade renders the empty state) — a valid
degraded state, not a broken one.
