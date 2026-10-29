# Pods + Deployments Views (List + Data) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pairs on existing generic routes (pods kind
already wired; deployments kind added); one orphan file deleted; no
migration, no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, both kinds namespaced
core APIs — the exact pattern of the HPA / ResourceQuota / NetworkPolicies
ports. The 4.1 template pairs are the source of truth for the page shapes;
the multi-tab data pages follow the CoreUI `CTabs` pattern already used by
the Service view's three-tab data page).

**Build shape:** Tracer thread — Task 1 proves both kinds end-to-end in the
backend (service methods → `_KINDS`/`_GETTERS` rows → API route → SAR deny)
before any frontend exists; Task 2 is the pods views; Task 3 the deployments
views; Task 4 the routing + orphan deletion. Each task is independently
revertable.

**Goal:** Resolve the Workloads nav leaves `/workload/pods` (the 4.1 port,
replacing the orphaned `Cluster/Pods.tsx`) and `/workload/deployments` (the
4.1 port) to real, SAR-gated, read-only, namespaced list + data pairs.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds TWO kinds:
- **pods** (namespaced core, group `""`): the `_KINDS["pods"]` row ALREADY
  exists (`list_pods`). This change adds the MISSING `_GETTERS["pods"] =
  "get_pod"` row + a new `K8sClient.get_pod(namespace, name)` method
  (`read_namespaced_pod`, `[]` on 404). NO new `__init__` attribute
  (`self._v1` already exists). NO `list_pods` signature change (the
  `?labelSelector=` param is the not-yet-landed service-views spec's concern).
- **deployments** (namespaced core, group `apps`): ADD the
  `_KINDS["deployments"]` row + `_GETTERS["deployments"] = "get_deployment"`
  row + new `K8sClient.list_deployments(namespace)` /
  `get_deployment(namespace, name)` methods + ONE new `__init__` attribute
  (`self._apps = k8s_client.AppsV1Api(api_client)`, if absent).

Frontend: four views (Pods list cloned from the HPA list for the namespaced
layout, Pod data a five-tab `CTabs` page; Deployments list cloned from the
HPA list, Deployment data a six-tab `CTabs` page), `PodItem` (extended) +
`DeploymentItem` types, App.tsx routes, the orphan `Cluster/Pods.tsx`
DELETED, both stubs removed.

**Tech Stack:** kubernetes `CoreV1Api` (pods — `self._v1` already exists) +
`AppsV1Api` (deployments — one possible new attribute `self._apps`), Flask +
Smoarest (existing route), React + CoreUI (`CTabs`/`CTab`/`CTabContent` —
confirmed present in `@coreui/react`, used by the Service data page) +
TanStack Query + MSW (existing), no new npm/Python dependency (air-gap,
ADR-0020).

**Spec:** `briefing.md` (R1–R9).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/workload/pod.html.j2`
(list: **Status / Name / Pod IP / Owner** — card title EXACTLY `Pod List`;
the Report columns + delete action are COMMENTED OUT in 4.1; the Name cell is
a hidden-form POST carrying `po_name` + `ns_select`; the Owner cell is a
hidden-form POST to `/workload/<owner-kind-lowercase>`),
`4.1:src/kubedash/templates/workload/pod-data.html.j2` (data: card title
EXACTLY `Pod Data`; a 5-tab page — Pod / Containers / Conditions / Security
Contexts / Related Resources; exec + logs buttons + a commented-out
vuln-report block; the Pod tab's "Lables" typo; the Related Resources tab
deep-links owner (Refered By) + image-pull-secrets / service-account /
secrets / configmaps / PVCs (Refers To) via hidden-form POSTs),
`4.1:src/kubedash/lib/k8s/workload.py:317` (`k8sPodListGet`:
`CoreV1Api().list_namespaced_pod(ns, _request_timeout=1)`, generates
`name`/`status`(phase, overridden to `Terminated` on deletion_timestamp +
`waiting.reason` for containers)/`owner`(`"%ss/%s" % (kind.lower(), name)`)/
`pod_ip`), `4.1:src/kubedash/lib/k8s/workload.py:349` (`k8sPodGet`:
`read_namespaced_pod`, the full curated pod data — resterts from
`container_statuses[0].restart_count` only, containers/init_containers with
`ready` state, conditions, security_context dict, related resources from
volumes + env), `4.1:src/kubedash/templates/workload/deployment.html.j2`
(list: **Name / Status / Created** — card title EXACTLY `Deployments List`;
Status = `desired/ready`; Name cell hidden-form POST),
`4.1:src/kubedash/templates/workload/deployment-data.html.j2` (data: card
title EXACTLY `Deployment Data`; a 6-tab page — Deployment / Containers /
Variables / Conditions / Security Contexts / Related Resources; an Admin-only
replica spinner; the "Lables" typo),
`4.1:src/kubedash/lib/k8s/workload.py:151` (`k8sDeploymentsGet`:
`AppsV1Api().list_namespaced_deployment(ns, _request_timeout=1)`, generates
`name`/`replicas`(spec.replicas)/`ready`(status.ready_replicas, 0)/
`desired`(status.replicas, 0)/`updated`/`selectors`(spec.selector.match_labels)
/annotations(labels trimmed)/containers + init_containers (name+image)/
environment_variables (env name+value)/related resources from template
volumes + env). In-repo precedents —
`backend/app/services/k8s_client.py:254` (`list_pods` — the existing method,
`list_namespaced_pod`/`list_pod_for_all_namespaces`), the
`get_network_policy` / `get_resource_quota` namespaced-core getters (the
`read_namespaced_*` → `[]` on 404 pattern to mirror for `get_pod` /
`get_deployment`), `backend/app/api/resources.py` `_KINDS` (line ~43,
`"pods": ("list_pods", "pods", "")` — ALREADY present) + `_GETTERS` (line
~97, NO `pods` row yet) + the `name` branch (line ~139-149, the `namespace =
namespace or "default"` fallback), `backend/tests/api/test_resources.py`
(the HPA / resourcequota API test blocks to mirror: 200 in-namespace,
get-by-name hit+miss, SAR deny, binding 404, singular kind rejected),
`frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx` +
`HorizontalPodAutoscalerData.tsx` (the namespaced list/data views to clone —
the namespace selector, the card title, the CTable + sub-tables + JSON
block; the `NOT_FOUND`-as-throw-not-found-state pattern),
`frontend/src/views/Security/Secret.tsx` (the landed Secret data link shape
`/security/secret/data?name=<n>&namespace=<ns>` — the deep-link destination
for the Related Resources secrets), `frontend/src/views/Cluster/Nodes.tsx`
(line 269, the landed Node data link shape `/cluster/node/data?name=<node>`
— cluster-scoped, no namespace), `frontend/src/views/Cluster/Pods.tsx`
(the ORPHAN to DELETE — an all-namespaces CTable, nothing imports it),
`frontend/src/_nav.tsx:88-89` (the Workloads group — the `Pods` +
`Deployments` leaves ALREADY exist, NO nav change), `frontend/src/views/Stub/
routes.ts:10-11` (the two stubs to remove),
`frontend/tests/views/horizontal_pod_autoscalers*.test.tsx` (the namespaced
list/data test patterns to clone), `frontend/src/lib/types.ts:51` (the `Pod`
type to extend with `spec.node_name` + `metadata.owner_references` +
`status.container_statuses`).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0009, ADR-0010, ADR-0020,
ADR-0021, ADR-0022. None created.

## Terms

None (the spec's vocabulary; "Pod" / "Deployment" are the k8s kinds, not new
terms).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/pods?namespace=<ns>` → 200, `kind: "pods"`, items in
  `to_dict` snake_case form, SAR-gated on `list pods` (group `""`, the
  namespace) (`pods-list-200-in-namespace`, `pods-sar-denied`).
- `GET .../resources/pods?namespace=<ns>&name=<name>` → a 0/1-item list
  through the SAME route — hit = the full object, miss = `[]`
  (`pods-get-by-name`).
- The singular `pod` kind is rejected with `RESOURCE_KIND_NOT_SUPPORTED`
  (`pod-kind-singular-rejected`).
- `GET .../resources/deployments?namespace=<ns>` → 200, `kind:
  "deployments"`, items in `to_dict` snake_case form, SAR-gated on
  `list deployments` (group `apps`, the namespace)
  (`deployments-list-200-in-namespace`, `deployments-sar-denied`).
- `GET .../resources/deployments?namespace=<ns>&name=<name>` → a 0/1-item
  list — hit = the full object, miss = `[]` (`deployments-get-by-name`).
- The singular `deployment` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`deployment-kind-singular-rejected`).
- The pods list view: card title EXACTLY `Pod List`; columns Status/Name/Pod
  IP/Owner; every name links to
  `/workload/pods/data?name=<name>&namespace=<ns>`; the Status cell is the
  effective-phase badge (Running/Pending/Succeeded/Terminated/CrashLoopBackOff
  mapping, deletion_timestamp → Terminated); the Owner cell is plain text
  (`<kind-lowercase>s/<name>`) (`pods-list-renders-rows`,
  `pods-list-owner-plain-text`, `pods-list-status-badge`).
- The pod data view: five `CTabs` (Pod/Containers/Conditions/Security
  Contexts/Related Resources) + the JSON block; the Pod tab's Restarts is the
  SUM of `container_statuses[].restart_count`; the Node cell deep-links to
  `/cluster/node/data?name=<node>`; a miss is the pinned state `No pod
  '<name>' found` — never an error style (`pod-data-renders-detail`,
  `pod-data-restarts-summed`, `pod-data-node-deep-link`,
  `pod-data-not-found-state`).
- The pod data Related Resources tab deep-links Secrets to
  `/security/secret/data?name=<n>&namespace=<ns>` and renders ConfigMap/PVC/
  ServiceAccount/ImagePullSecret/owner as plain text
  (`pod-data-related-resources-deep-link-secrets`).
- The deployments list view: card title EXACTLY `Deployments List`; columns
  Name/Status/Created; every name links to
  `/workload/deployments/data?name=<name>&namespace=<ns>`; the Status cell is
  `<desired>/<ready>` (`deployments-list-renders-rows`,
  `deployments-list-status-format`).
- The deployment data view: six `CTabs` (Deployment/Containers/Variables/
  Conditions/Security Contexts/Related Resources) + the JSON block; the
  Deployment tab's Replicas is plain text (NO spinner); a miss is the pinned
  state `No deployment '<name>' found` — never an error style
  (`deployment-data-renders-detail`, `deployment-data-replicas-plain-text`,
  `deployment-data-not-found-state`).
- The deployment data Related Resources tab deep-links Secrets (landed) and
  renders the rest as plain text (`deployment-data-related-resources-
  deep-link-secrets`).
- Both stubs are removed from `views/Stub/routes.ts`; both view pairs are
  routed; the orphan `Cluster/Pods.tsx` is DELETED; the nav leaves are
  UNCHANGED (`stub-removed-and-routes-wired`, `orphan-pods-deleted`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `get_pod` + `list_deployments` /
  `get_deployment` + `self._apps` attribute (if absent) (modified).
- `backend/app/api/resources.py` — the `_GETTERS["pods"]` row + the
  `_KINDS["deployments"]` + `_GETTERS["deployments"]` rows (modified).
- `backend/tests/services/test_k8s_client_pods.py` (new).
- `backend/tests/services/test_k8s_client_deployments.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 10 new tests
  (modified).
- `frontend/src/lib/types.ts` — `Pod` extended + `DeploymentItem` (modified).
- `frontend/src/views/Workload/Pods.tsx` (new).
- `frontend/src/views/Workload/PodData.tsx` (new).
- `frontend/src/views/Workload/Deployments.tsx` (new).
- `frontend/src/views/Workload/DeploymentData.tsx` (new).
- `frontend/src/views/Cluster/Pods.tsx` (DELETED — the orphan).
- `frontend/tests/views/pods.test.tsx` (new).
- `frontend/tests/views/pod_data.test.tsx` (new).
- `frontend/tests/views/deployments.test.tsx` (new).
- `frontend/tests/views/deployment_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_GETTERS` row and the client method are ONE behavior per kind: the
  same route branch serves `?name=`. A `_GETTERS["pods"]` row without a
  `get_pod` method is a 500 at `getattr(pool.get(cluster), "get_pod")` — the
  row + method land in the same commit (pods: 1 row + 1 method; deployments:
  2 rows + 2 methods).
- **pods is namespaced**: `get_pod` uses `read_namespaced_pod(name, namespace)`
  (the namespace is REAL — this is NOT cluster-scoped). The `?name=` branch's
  `namespace = namespace or "default"` fallback applies when the view omits
  `?namespace=` (the data page always sends it).
- **deployments is namespaced**: `list_deployments` uses
  `list_namespaced_deployment(namespace)` and `get_deployment` uses
  `read_namespaced_deployment(name, namespace)` — the `self._apps`
  (`AppsV1Api`) API, NOT `self._v1`.
- **The `Pod` type must be extended** before the views compile: `fe-build`
  runs `tsc --noEmit` over TEST files too. The views read
  `status.container_statuses[].restart_count`, `metadata.owner_references`,
  `spec.node_name`, `spec.security_context`, `spec.template` (deployments),
  `status.conditions`, `spec.selector.match_labels`, `spec.replicas`,
  `status.ready_replicas` / `status.replicas` — the current `Pod` type has
  only `metadata.name`/`namespace` + `status.phase`. Extend `Pod` (add the
  optional fields) + add `DeploymentItem` (the `spec.template.spec` shape).
- The list view's name-link href is the SOLE producer of the data page's
  `?name=&namespace=` query strings — the data page parses the params, never
  constructs one (the HPA contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an API
  error (the `NOT_FOUND`-as-throw-not-found-state pattern from
  `HorizontalPodAutoscalerData.tsx`).
- **The orphan `Cluster/Pods.tsx` is deleted, not moved** — nothing imports
  it (`Cluster/index.tsx` documents the move to Workloads). Deleting it in
  the same commit as adding the `/workload/pods` route keeps the "replace in
  place" atomic. Verify with `grep -rn "Cluster/Pods" frontend/src` that
  nothing references it before deletion.
- **The Related Resources deep-links only to LANDED destinations** — Secrets
  → `/security/secret/data?name=<n>&namespace=<ns>` (landed); ConfigMap /
  PVC / ServiceAccount / ImagePullSecret / owner → plain text (their views
  are not yet landed). Do NOT deep-link to non-landed kinds (the links would
  404). The Node deep-link → `/cluster/node/data?name=<node>` (landed,
  cluster-scoped, no namespace).

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive; the orphan deletion is a file
removal with no importer).

## Global Constraints

- No new Python dependency — `CoreV1Api` + `AppsV1Api` are already in the
  kubernetes client; at most ONE new attribute (`self._apps`) in
  `K8sClient.__init__` (air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported (the `json` grammar already registered); `CTabs`/`CTab`/
  `CTabContent` + `KubeDataTable` + CoreUI are existing.
- Both kinds are namespaced (group `""` for pods, `apps` for deployments):
  the list URL and the data URL carry `namespace=<ns>`; SAR group = `""` /
  `apps` respectively, namespace = the query value; the client methods use
  `list_namespaced_pod` / `read_namespaced_pod` / `list_namespaced_deployment`
  / `read_namespaced_deployment`.
- **No `?labelSelector=` in THIS spec** — the pods route does NOT read or
  forward `?labelSelector=` (that is the not-yet-landed service-views spec's
  concern; do NOT add it here). The pod list is the namespace's full set.
- The full-object blocks are `JSON.stringify(item, null, 2)` with hljs
  grammar `json`, style `anOldHope` (the truthful-classifier rule).
- Card titles EXACTLY: `Pod List`, `Pod Data`, `Deployments List`,
  `Deployment Data` (the e2e-smoke contracts).
- Pinned copy (do not reword): `No pods found`, `No pod '<name>' found`,
  `Error: pod name not provided`, `No deployments found`,
  `No deployment '<name>' found`, `Error: deployment name not provided`,
  `No cluster selected.`, `Loading pods...`, `Loading deployments...`,
  `No labels`, `No annotations`, `No init containers`, `No variables`,
  `No security context`, `No selectors`.
- Conventional commits; spec-zone commits precede code-zone commits;
  WHY-comments on load-bearing invariants (AGENTS.md).
- `fe-build` runs `tsc --noEmit` over TEST files too — type any new test
  params explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `get_pod` next to
  `get_pod_disruption_budget` (line ~936) or next to `list_pods` (line ~254);
  `list_deployments` / `get_deployment` next to the HPA methods (the
  namespaced-core pattern); `self._apps` in `__init__` (if absent, next to
  `self._v1`).
- `backend/app/api/resources.py` (modify) — `_GETTERS["pods"] = "get_pod"`;
  `_KINDS["deployments"] = ("list_deployments", "deployments", "apps")` +
  `_GETTERS["deployments"] = "get_deployment"`.
- `backend/tests/services/test_k8s_client_pods.py` (new) —
  `object.__new__` + `SimpleNamespace` fake (the `CoreV1Api` fake for
  `read_namespaced_pod`).
- `backend/tests/services/test_k8s_client_deployments.py` (new) — the
  `AppsV1Api` fake for `list_namespaced_deployment` /
  `read_namespaced_deployment`.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains
  `get_pod` / `list_deployments` / `get_deployment`; 10 new tests.
- `frontend/src/lib/types.ts` (modify) — extend `Pod` (add
  `status.container_statuses`, `metadata.owner_references`, `spec.node_name`,
  `spec.security_context`, `spec.containers`/`init_containers`/`volumes`,
  `spec.service_account_name`, `spec.priority`/`priority_class_name`/
  `runtime_class_name`, `status.conditions`); add `DeploymentItem` (the
  `spec.template.spec` shape + `spec.selector.match_labels` +
  `spec.replicas` + `status.ready_replicas`/`replicas`/`conditions`).
- `frontend/src/views/Workload/Pods.tsx` (new) — namespaced layout from
  `HorizontalPodAutoscaler.tsx` (the Status/Name/Pod IP/Owner columns).
- `frontend/src/views/Workload/PodData.tsx` (new) — five-tab `CTabs` page
  (Pod/Containers/Conditions/Security Contexts/Related Resources) + the JSON
  block.
- `frontend/src/views/Workload/Deployments.tsx` (new) — namespaced layout
  from `HorizontalPodAutoscaler.tsx` (the Name/Status/Created columns).
- `frontend/src/views/Workload/DeploymentData.tsx` (new) — six-tab `CTabs`
  page (Deployment/Containers/Variables/Conditions/Security Contexts/
  Related Resources) + the JSON block.
- `frontend/src/views/Cluster/Pods.tsx` (DELETE — the orphan).
- `frontend/tests/views/pods.test.tsx` (new).
- `frontend/tests/views/pod_data.test.tsx` (new).
- `frontend/tests/views/deployments.test.tsx` (new).
- `frontend/tests/views/deployment_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — the four routes + the four imports.
- `frontend/src/views/Stub/routes.ts` (modify) — remove lines 10–11
  (`/workload/pods` + `/workload/deployments`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the two paths to the
  `viewPaths` set (the stubs are removed; the test must not expect them).

---

### Task 1: Backend — pods `?name=` getter + deployments kind (service + `_KINDS`/`_GETTERS` + API tests)

**SATISFIES:** `pods-list-200-in-namespace`, `pods-sar-denied`,
`pod-kind-singular-rejected`, `pods-get-by-name`,
`deployments-list-200-in-namespace`, `deployments-sar-denied`,
`deployment-kind-singular-rejected`, `deployments-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_pods.py` (new)
- Test: `backend/tests/services/test_k8s_client_deployments.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing (first code task).
- Produces: `K8sClient.get_pod(namespace: str, name: str) -> list[dict]`,
  `K8sClient.list_deployments(namespace: str | None) -> list[dict]`,
  `K8sClient.get_deployment(namespace: str, name: str) -> list[dict]` — the
  exact names `_KINDS`/`_GETTERS` reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the HPA / resourcequota / VPA tests).
- Deletion test: delete the `_GETTERS["pods"]` row → `?name=` on pods 404s
  with `RESOURCE_KIND_NOT_SUPPORTED`; delete the `_KINDS["deployments"]` row →
  the deployments kind 404s again; delete the service methods → the service
  tests fail.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing pods getter service test** —
  `backend/tests/services/test_k8s_client_pods.py`, mirroring the
  `get_resource_quota` / `get_network_policy` test pattern with
  `object.__new__` + `SimpleNamespace` (a `CoreV1Api` fake for
  `read_namespaced_pod`): the namespaced call (`read_namespaced_pod(name,
  namespace)`), `to_dict` form, 404 → `[]` on the getter, 500 →
  `ClusterUnreachableError`.
- [ ] **Step 2: Write the failing deployments service tests** —
  `backend/tests/services/test_k8s_client_deployments.py`, mirroring the HPA
  test pattern (an `AppsV1Api` fake for `list_namespaced_deployment` /
  `read_namespaced_deployment`): the namespaced call, `to_dict` form with
  `spec.replicas` + `status.ready_replicas` + `spec.template.spec`, list
  500 → `ClusterUnreachableError`, getter 404 → `[]`.
- [ ] **Step 3: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_pods.py tests/services/test_k8s_client_deployments.py -q`.
  Expected: FAIL (no `get_pod` / `list_deployments` / `get_deployment`).
- [ ] **Step 4: Implement the pods getter** — `k8s_client.py`, next to
  `get_pod_disruption_budget` (line ~936):
  ```python
  def get_pod(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One pod as a 0/1-item list in the standard kubernetes dict form
      (``to_dict``); ``[]`` on 404. Namespaced (``read_namespaced_pod``). Any
      other ApiException maps to ``ClusterUnreachableError`` (502)."""
      try:
          return [self._v1.read_namespaced_pod(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_pod", e)
          raise AssertionError("unreachable") from e
  ```
- [ ] **Step 5: Implement the deployments methods** — next to the HPA methods
  (the namespaced-core pattern). Verify `self._apps` exists in `__init__`; if
  absent, add `self._apps = k8s_client.AppsV1Api(api_client)` next to
  `self._v1`:
  ```python
  def list_deployments(self, namespace: str | None) -> list[dict[str, Any]]:
      """Deployment list in the standard kubernetes dict form (``to_dict``).
      Namespaced (apps/v1): ``list_namespaced_deployment``. A transport
      ApiException maps to ``ClusterUnreachableError`` (502)."""
      if not namespace:
          return []
      try:
          resp = self._apps.list_namespaced_deployment(namespace)
      except ApiException as e:
          self._unreachable("list_deployments", e)
          raise AssertionError("unreachable") from e
      return [d.to_dict() for d in resp.items]

  def get_deployment(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One deployment as a 0/1-item list in the standard kubernetes dict
      form (``to_dict``); ``[]`` on 404. Namespaced (apps/v1,
      ``read_namespaced_deployment``). Any other ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          return [self._apps.read_namespaced_deployment(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_deployment", e)
          raise AssertionError("unreachable") from e
  ```
  (match the HPA method's exact namespace handling — if `list_horizontal_pod_autoscalers`
  falls back to all-namespaces when the namespace is `None`, mirror that
  decision here; verify against the HPA source.)
- [ ] **Step 6: Wire the kinds + write the failing API tests** —
  `backend/app/api/resources.py`:
  - `_GETTERS`: add `"pods": "get_pod"` + `"deployments": "get_deployment"`.
  - `_KINDS`: add `"deployments": ("list_deployments", "deployments", "apps")`
    (the `pods` row ALREADY exists — do NOT re-add it).
  ```python
  # Pods (core, namespaced) — the _KINDS row already exists; the _GETTERS row
  # is added by the pods-deployments-views change (the 4.1-parity /workload/pods
  # data page needs ?name=).
  # Deployments (apps/v1, namespaced) — the 4.1-parity nav leaf resolved by
  # the pods-deployments-views change (list + data views; ADR-0022 placement).
  "deployments": ("list_deployments", "deployments", "apps"),
  ```
  Then `backend/tests/api/test_resources.py` (mirror the HPA block):
  - FakeK8s gains `get_pod` (returns a `to_dict`-shaped pod with
    `metadata.owner_references` + `status.container_statuses` +
    `spec.node_name`), `list_deployments` (a `to_dict`-shaped deployment with
    `spec.replicas` + `status.ready_replicas` + `spec.template.spec`),
    `get_deployment`.
  - 10 new tests (5 per kind, same docstring-tag style):
    - pods: `list_200_in_namespace` (kind + to_dict form), `get_by_name`
      (hit + miss), `sar_denied` (assert `("list", "pods", <ns>, None, "")` in
      `asked`), `binding_404`, `singular_rejected` (`pod`).
    - deployments: `list_200_in_namespace` (kind + to_dict form),
      `get_by_name` (hit + miss), `sar_denied` (assert `("list", "deployments",
      <ns>, None, "apps")` in `asked`), `binding_404`, `singular_rejected`
      (`deployment`).
- [ ] **Step 7: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_pods.py tests/services/test_k8s_client_deployments.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).
- [ ] **Step 8: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_pods.py backend/tests/services/test_k8s_client_deployments.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): pods getter + deployments kind (namespaced, SAR-gated)"`

### Task 2: Frontend — pods list + data views + tests + orphan deletion

**SATISFIES:** `pods-list-renders-rows`, `pods-list-owner-plain-text`,
`pods-list-status-badge`, `pod-data-renders-detail`,
`pod-data-restarts-summed`, `pod-data-node-deep-link`,
`pod-data-related-resources-deep-link-secrets`, `pod-data-not-found-state`,
`orphan-pods-deleted`

**Files:**
- Modify: `frontend/src/lib/types.ts` (extend `Pod`)
- Create: `frontend/src/views/Workload/Pods.tsx`
- Create: `frontend/src/views/Workload/PodData.tsx`
- Delete: `frontend/src/views/Cluster/Pods.tsx` (the orphan)
- Test: `frontend/tests/views/pods.test.tsx` (new)
- Test: `frontend/tests/views/pod_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `pods` list + `?name=` URLs, namespaced).
- Produces: the data-page link
  `/workload/pods/data?name=<name>&namespace=<ns>` (the sole producer).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` +
  the selected-namespace store.
- Deletion test: deleting the views → the routes (Task 4) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Extend the `Pod` type** — `frontend/src/lib/types.ts` (line
  ~51), add the optional fields the views read:
  ```ts
  export interface Pod {
    metadata?: {
      name?: string
      namespace?: string
      creation_timestamp?: string
      deletion_timestamp?: string
      labels?: Record<string, string>
      annotations?: Record<string, string>
      owner_references?: { kind?: string; name?: string; [k: string]: unknown }[]
      [key: string]: unknown
    }
    spec?: {
      node_name?: string
      priority?: number
      priority_class_name?: string
      runtime_class_name?: string
      service_account_name?: string
      security_context?: Record<string, unknown>
      containers?: { name?: string; image?: string; env?: { name?: string; value?: string; value_from?: { secret_key_ref?: { name?: string } } } }[]
      init_containers?: { name?: string; image?: string }[]
      volumes?: { persistent_volume_claim?: { claim_name?: string }; config_map?: { name?: string }; secret?: { secret_name?: string } }[]
      image_pull_secrets?: { name?: string }[]
      [key: string]: unknown
    }
    status?: {
      phase?: string
      pod_ip?: string
      conditions?: { type?: string; status?: string; reason?: string; message?: string }[]
      container_statuses?: { name?: string; ready?: boolean; restart_count?: number; state?: Record<string, unknown>; last_state?: Record<string, unknown> }[]
      init_container_statuses?: { name?: string; ready?: boolean; restart_count?: number; state?: Record<string, unknown> }[]
      [key: string]: unknown
    }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone
  `horizontal_pod_autoscalers.test.tsx` (the namespaced pattern) +
  `horizontal_pod_autoscaler_data.test.tsx`:
  - list: card title `Pod List`, columns Status/Name/Pod IP/Owner, name link
    `/workload/pods/data?name=<n>&namespace=<ns>`, the Status badge mapping
    (Running/Pending/Succeeded/Terminated/CrashLoopBackOff +
    deletion_timestamp→Terminated), Owner plain text (`replicaset/<name>`),
    no-cluster, no-namespace, empty.
  - data: five tabs (Pod/Containers/Conditions/Security Contexts/Related
    Resources) + the JSON block; Restarts SUMMED across
    `container_statuses`; the Node deep-link
    `/cluster/node/data?name=<node>`; the Related Resources tab deep-links
    Secrets to `/security/secret/data?name=<n>&namespace=<ns>` and renders
    ConfigMap/PVC/ServiceAccount as plain text; not-found state; missing-name.
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `Pods.tsx` (namespaced layout from
  `HorizontalPodAutoscaler.tsx`; Status = the effective-phase badge; Pod IP =
  `status.pod_ip ?? '—'`; Owner = first `owner_references` →
  `${kind.toLowerCase()}s/${name}`, plain text); `PodData.tsx` (five-tab
  `CTabs` page — the Pod tab CTable + Containers tab (Init + main CTables with
  the effective-state badge) + Conditions tab + Security Contexts tab +
  Related Resources tab (Refered By + Refers To, the deep-links) + the JSON
  block; the NOT_FOUND state).
- [ ] **Step 5: Delete the orphan** — `git rm frontend/src/views/Cluster/Pods.tsx`.
  Verify first: `grep -rn "Cluster/Pods" frontend/src` returns nothing (no
  importer). Re-run `task fe-build` to confirm no dangling import.
- [ ] **Step 6: Run, confirm GREEN.**
- [ ] **Step 7: Commit** —
  `git add frontend/src/lib/types.ts frontend/src/views/Workload/Pods.tsx frontend/src/views/Workload/PodData.tsx frontend/src/views/Cluster/Pods.tsx frontend/tests/views/pods.test.tsx frontend/tests/views/pod_data.test.tsx`
  `git commit -m "feat(frontend): pods list + data views (4.1 port, namespaced) + delete orphan Cluster/Pods"`

### Task 3: Frontend — deployments list + data views + tests

**SATISFIES:** `deployments-list-renders-rows`,
`deployments-list-status-format`, `deployment-data-renders-detail`,
`deployment-data-replicas-plain-text`,
`deployment-data-related-resources-deep-link-secrets`,
`deployment-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts` (add `DeploymentItem`)
- Create: `frontend/src/views/Workload/Deployments.tsx`
- Create: `frontend/src/views/Workload/DeploymentData.tsx`
- Test: `frontend/tests/views/deployments.test.tsx` (new)
- Test: `frontend/tests/views/deployment_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `deployments` list + `?name=` URLs, namespaced).
- Produces: the data-page link
  `/workload/deployments/data?name=<name>&namespace=<ns>` (the sole producer).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` +
  the selected-namespace store.
- Deletion test: deleting the views → the routes (Task 4) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `DeploymentItem` next to `Pod`:
  ```ts
  /** A Deployment item (kubernetes to_dict, snake_case; namespaced apps/v1). */
  export interface DeploymentItem {
    metadata?: { name?: string; namespace?: string; creation_timestamp?: string;
      labels?: Record<string, string>; annotations?: Record<string, string> }
    spec?: {
      replicas?: number
      selector?: { match_labels?: Record<string, string> }
      template?: { spec?: {
        service_account_name?: string
        security_context?: Record<string, unknown>
        containers?: { name?: string; image?: string; env?: { name?: string; value?: string; value_from?: { secret_key_ref?: { name?: string } } } }[]
        init_containers?: { name?: string; image?: string }[]
        volumes?: { persistent_volume_claim?: { claim_name?: string }; config_map?: { name?: string }; secret?: { secret_name?: string } }[]
        image_pull_secrets?: { name?: string }[]
      } }
    }
    status?: {
      replicas?: number
      ready_replicas?: number
      updated_replicas?: number
      conditions?: { type?: string; reason?: string; message?: string; last_transition_time?: string }[]
    }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone
  `horizontal_pod_autoscalers.test.tsx` + `horizontal_pod_autoscaler_data.test.tsx`:
  list (card title `Deployments List`, columns Name/Status/Created, Status =
  `<desired>/<ready>`, name link `/workload/deployments/data?name=<n>&namespace=<ns>`,
  no-cluster, no-namespace, empty) + data (six tabs Deployment/Containers/
  Variables/Conditions/Security Contexts/Related Resources + the JSON block;
  Replicas plain text (NO spinner); the Related Resources tab deep-links
  Secrets + plain-texts the rest; not-found state; missing-name).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `Deployments.tsx` (namespaced layout from
  `HorizontalPodAutoscaler.tsx`; Status =
  `${status.replicas ?? 0}/${status.ready_replicas ?? 0}`; Created =
  `formatTimestamp`); `DeploymentData.tsx` (six-tab `CTabs` page — the
  Deployment tab CTable (Replicas plain text, Selectors sub-table) +
  Containers tab (Init + main CTables, name+image) + Variables tab +
  Conditions tab + Security Contexts tab + Related Resources tab (deep-links)
  + the JSON block; the NOT_FOUND state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): deployments list + data views (4.1 port, namespaced)"`

### Task 4: Routing + stub removal + full verification

**SATISFIES:** `stub-removed-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 2–3's view components.
- Produces: the resolved nav leaves (the goal).
- Seam: react-router `Route` + the stub routes + the `viewPaths` set.
- Deletion test: delete the four `Route`s → the paths 404; re-add the stubs →
  the pages stub again.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the four view imports +
  the four routes (mirroring the HPA route block — the namespaced pattern):
  ```tsx
  <Route path="/workload/pods" element={<ProtectedRoute><PodsWorkloadView /></ProtectedRoute>} />
  <Route path="/workload/pods/data" element={<ProtectedRoute><PodDataView /></ProtectedRoute>} />
  <Route path="/workload/deployments" element={<ProtectedRoute><DeploymentsView /></ProtectedRoute>} />
  <Route path="/workload/deployments/data" element={<ProtectedRoute><DeploymentDataView /></ProtectedRoute>} />
  ```
  (import as `PodsWorkloadView` etc. to avoid clashing with any existing
  `Pods` symbol — the orphan is deleted, but keep the import names explicit.)
- [ ] **Step 2: Remove the stubs** — `views/Stub/routes.ts`: delete line 10
  (`/workload/pods`) and line 11 (`/workload/deployments`).
- [ ] **Step 3: Update Stub.test.tsx** — add `/workload/pods` +
  `/workload/deployments` to the `viewPaths` set in `expectedStubs()` (the
  stubs are removed; without the addition the test expects them to be stubs
  — RED). Re-run `corepack pnpm vitest run tests/views/Stub.test.tsx`.
- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build) — confirms the
    orphan deletion + the type extensions compile.
  - `task fe-check` (air-gap — no new external refs).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures are the baseline).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).
- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire pods + deployments routes, remove stubs"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_pods.py tests/services/test_k8s_client_deployments.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/pods.test.tsx tests/views/pod_data.test.tsx tests/views/deployments.test.tsx tests/views/deployment_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `grep -rn "Cluster/Pods" frontend/src` — empty (the orphan is deleted, no dangling import).
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` UNCHANGED (the leaves already exist); no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend: pods getter + deployments kind) ──► Task 2 (pods views + orphan) ──► Task 4 (routing + stubs)
                                └────────────────► Task 3 (deployments views) ──────┘
```

Tasks 2 and 3 are independent of each other (both consume Task 1); either
can run first or in parallel. Task 4 last (it wires the routes + removes the
stubs, so the views must exist first). The orphan deletion (Task 2) and the
`/workload/pods` route (Task 4) are the "replace in place" pair — Task 2
deletes the orphan, Task 4 adds the route; both land before the change is
complete.

## Rollback

Each task is one conventional commit and independently revertable (no schema,
no dependency, no public contract change). Reverting Task 4 re-adds the two
stubs (self-contained: routes + stubs + test in one commit). Reverting Task 1
reverts both kinds (the pods `?name=` 404s, the deployments kind 404s).
Tasks 2 and 3 are independent reverts (the pods and deployments views are
separate commits; Task 2's revert restores the orphan `Cluster/Pods.tsx`).
The orphan deletion is atomic with the pods views (Task 2) — reverting Task 2
restores the orphan AND removes the `/workload/pods` views.
