# StatefulSets + DaemonSets + ReplicaSets Views (List + Data) — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps,
> files to touch, tests, and verification. The product *why* lives in
> `briefing.md` and the ADR manifest in `adr.md`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T1 — additive view pairs on existing generic routes; three `apps/v1`
kinds wired through `_KINDS`/`_GETTERS`; one shared `self._apps` attribute (the
companion `pods-deployments-views` spec adds it too — deduped); no migration,
no new dependency, no public-API break.

**Classification:** `low-risk` (read-only, SAR-gated, all three kinds are
namespaced `apps/v1` core APIs — the exact pattern of the HPA / deployments
ports. The 4.1 template pairs are the source of truth for the page shapes; the
multi-tab data pages follow the CoreUI `CTabs` pattern already used by the
Deployment data page).

**Build shape:** Tracer thread — Task 1 proves all three kinds end-to-end in
the backend (service methods → `_KINDS`/`_GETTERS` rows → API route → SAR deny)
before any frontend exists; Task 2 is the StatefulSet views; Task 3 the
DaemonSet views; Task 4 the ReplicaSet views; Task 5 the routing + stub
removal. Each task is independently revertable.

**Goal:** Resolve the Workloads nav leaves `/workload/statefulsets`,
`/workload/daemonsets`, and `/workload/replicasets` (all stubs) to real,
SAR-gated, read-only, namespaced list + data pairs.

**Architecture:** The existing generic resource route
(`backend/app/api/resources.py` `list_resources`) already implements binding
gate → SAR → client call for list AND `?name=`. This change adds THREE kinds,
all `apps/v1` (group `apps`), all on the shared `self._apps` (`AppsV1Api`):
- **statefulsets**: `_KINDS["statefulsets"]` + `_GETTERS["statefulsets"]` rows
  + `K8sClient.list_stateful_sets(namespace)` /
  `get_stateful_set(namespace, name)`.
- **daemonsets**: `_KINDS["daemonsets"]` + `_GETTERS["daemonsets"]` rows +
  `K8sClient.list_daemon_sets(namespace)` /
  `get_daemon_set(namespace, name)`.
- **replicasets**: `_KINDS["replicasets"]` + `_GETTERS["replicasets"]` rows +
  `K8sClient.list_replica_sets(namespace)` /
  `get_replica_set(namespace, name)`.

**The `self._apps` seam (the not-yet-landed dependency):** all three methods
use `self._apps` (`AppsV1Api`). The companion `pods-deployments-views` spec
(adds `list_deployments` / `get_deployment`) ALSO adds `self._apps` and has NOT
landed. **This spec adds `self._apps` to `__init__` if absent** (next to
`self._v1`); when the deployments spec lands, the shared attribute is
deduplicated (not re-added) — a WHY-comment on the attribute notes the shared
ownership (so the deployments spec's implementer knows not to re-add it). The
three kinds are self-contained on it (they work whether the deployments spec
lands before or after).

Frontend: six views (StatefulSet list cloned from the HPA list for the
namespaced layout + StatefulSet data a five-tab `CTabs` page; DaemonSet list
cloned from the HPA list + DaemonSet data a five-tab `CTabs` page; ReplicaSet
list cloned from the HPA list + ReplicaSet data a five-tab `CTabs` page — the
Deployment-tab shape, the same `spec.template.spec` for all three),
`StatefulSetItem` + `DaemonSetItem` + `ReplicaSetItem` types, App.tsx routes,
the three stubs removed.

**Tech Stack:** kubernetes `AppsV1Api` (all three kinds — the `self._apps`
attribute, shared with the deployments spec), Flask + Smoarest (existing
route), React + CoreUI (`CTabs`/`CTab`/`CTabContent` — confirmed present in
`@coreui/react`) + TanStack Query + MSW (existing), no new npm/Python
dependency (air-gap, ADR-0020).

**Spec:** `briefing.md` (R1–R11).
**Findings:** 4.1 audit — `4.1:src/kubedash/templates/workload/statefulset.html
.j2` (list: **Name / Desired / Current / Ready / Created** — card title has the
4.1 typo `Statefullset List`; Name cell hidden-form POST),
`4.1:src/kubedash/templates/workload/statefulset-data.html.j2` (data: card
title is the copy-paste bug `Deployment Data`; a 5-tab page — the first tab
mislabeled `Deployment` (should be StatefulSet) / Containers / Variables /
Security Contexts / Related Resources; an Admin-only replica spinner; the
"Lables" typo), `4.1:src/kubedash/lib/k8s/workload.py:694`
(`k8sStatefulSetsGet`: `AppsV1Api().list_namespaced_stateful_set(ns,
_request_timeout=1)`, generates `name`/`replicas`(spec.replicas)/
`desired`(status.replicas,0)/`current`(status.current_replicas,0)/
`ready`(status.ready_replicas,0)/`selectors`(spec.selector.match_labels) + a
LATENT BUG: `annotations` is set to `trimAnnotations(sfs.metadata.labels)` —
passing the LABELS — 5.0 renders `metadata.annotations` verbatim; containers +
init_containers (name+image); env vars; related resources from template
volumes + env), `4.1:src/kubedash/templates/workload/daemonset.html.j2` (list:
**Name / Desired / Current / Ready / Created** — card title `DaemonSet List`;
Name cell hidden-form POST), `4.1:src/kubedash/templates/workload/daemonset-
data.html.j2` (data: card title `Daemonset Data`; a 5-tab page — the first tab
mislabeled `Deployment` (should be DaemonSet) / Containers / Variables /
Security Contexts / Related Resources; an Admin spinner bound to `desired`;
the "Lables" typo), `4.1:src/kubedash/lib/k8s/workload.py:19`
(`k8sDaemonSetsGet`: `AppsV1Api().list_namespaced_daemon_set(ns,
_request_timeout=1)`, generates `desired`(status.desired_number_scheduled,0)/
`current`(status.current_number_scheduled,0)/`ready`(status.number_ready,0)/
`selectors`/containers/env/related resources), `4.1:src/kubedash/templates/
workload/replicaset.html.j2` (list: **Name / Desired / Current / Ready /
Owner** — card title `ReplicaSet List`; the Name cell is NOT a link (no data
page in 4.1); the Owner cell is a hidden-form POST to
`/workload/<owner-kind-lowercase>`), `4.1:src/kubedash/lib/k8s/workload.py:650`
(`k8sReplicaSetsGet`: `AppsV1Api().list_namespaced_replica_set(ns,
_request_timeout=1)`, generates `name`/`owner`(`"%ss/%s" % (kind.lower(),
name)`)/`desired`(status.fully_labeled_replicas,0)/`current`
(status.available_replicas,0)/`ready`(status.ready_replicas,0)). 5.0 in-repo
precedents — `backend/app/services/k8s_client.py:212` (`self._v1` — where
`self._apps` goes, next to it, if absent), the HPA service methods
(`list_horizontal_pod_autoscalers` / `get_horizontal_pod_autoscaler` — the
namespaced-core pattern to mirror for the three kinds, swapping the API for
`self._apps`), `backend/app/api/resources.py` `_KINDS` (line ~42) + `_GETTERS`
(line ~97) — the three kinds are added here, `backend/tests/api/test_resources
.py` (the HPA API test blocks to mirror: 200 in-namespace, get-by-name hit+miss,
SAR deny, binding 404, singular kind rejected — ×3 kinds),
`frontend/src/views/OtherResource/HorizontalPodAutoscaler.tsx` +
`HorizontalPodAutoscalerData.tsx` (the namespaced list/data views to clone —
the namespace selector, the card title, the CTable + sub-tables + JSON block;
the `NOT_FOUND`-as-throw-not-found-state pattern),
`frontend/src/views/Security/Secret.tsx` (the landed Secret data link shape
`/security/secret/data?name=<n>&namespace=<ns>` — the deep-link destination
for the Related Resources secrets), `frontend/src/_nav.tsx:90-92` (the
Workloads group — the three leaves ALREADY exist, NO nav change),
`frontend/src/views/Stub/routes.ts:12-14` (the three stubs to remove),
`frontend/tests/views/horizontal_pod_autoscalers*.test.tsx` (the namespaced
list/data test patterns to clone), `frontend/src/lib/types.ts` (where the three
types go, next to `DeploymentItem`).

**In-force ADRs:** per `adr.md` — ADR-0004, ADR-0009, ADR-0010, ADR-0020,
ADR-0021, ADR-0022. None created.

## Terms

None (the spec's vocabulary; "StatefulSet" / "DaemonSet" / "ReplicaSet" are
the k8s kinds, not new terms).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- `GET .../resources/statefulsets?namespace=<ns>` → 200, `kind:
  "statefulsets"`, items in `to_dict` snake_case form, SAR-gated on
  `list statefulsets` (group `apps`, the namespace)
  (`statefulsets-list-200-in-namespace`, `statefulsets-sar-denied`).
- `GET .../resources/statefulsets?namespace=<ns>&name=<name>` → a 0/1-item
  list — hit = the full object, miss = `[]` (`statefulsets-get-by-name`).
- The singular `statefulset` kind is rejected with
  `RESOURCE_KIND_NOT_SUPPORTED` (`statefulset-kind-singular-rejected`).
- `GET .../resources/daemonsets?namespace=<ns>` → 200, `kind: "daemonsets"`,
  SAR-gated on `list daemonsets` (group `apps`, the namespace)
  (`daemonsets-list-200-in-namespace`, `daemonsets-sar-denied`).
- `GET .../resources/daemonsets?namespace=<ns>&name=<name>` → a 0/1-item list
  (`daemonsets-get-by-name`). The singular `daemonset` is rejected
  (`daemonset-kind-singular-rejected`).
- `GET .../resources/replicasets?namespace=<ns>` → 200, `kind:
  "replicasets"`, SAR-gated on `list replicasets` (group `apps`, the namespace)
  (`replicasets-list-200-in-namespace`, `replicasets-sar-denied`).
- `GET .../resources/replicasets?namespace=<ns>&name=<name>` → a 0/1-item list
  (`replicasets-get-by-name`). The singular `replicaset` is rejected
  (`replicaset-kind-singular-rejected`).
- The StatefulSet list view: card title EXACTLY `Statefulset List` (the 4.1
  `Statefullset` typo is NOT replicated); columns Name/Desired/Current/Ready/
  Created (Desired=`status.replicas`, Current=`status.current_replicas`,
  Ready=`status.ready_replicas`, all default 0); every name links to
  `/workload/statefulsets/data?name=<name>&namespace=<ns>`
  (`statefulset-list-renders-rows`, `statefulset-list-status-fields`).
- The StatefulSet data view: card title `StatefulSet Data` (the 4.1
  `Deployment Data` bug is FIXED); five `CTabs` (StatefulSet/Containers/
  Variables/Security Contexts/Related Resources — the first tab labeled
  `StatefulSet`, NOT `Deployment`) + the JSON block; the StatefulSet tab's
  Replicas is plain text (NO spinner); a miss is the pinned state `No
  statefulset '<name>' found` — never an error style
  (`statefulset-data-renders-detail`, `statefulset-data-title-fixed`,
  `statefulset-data-replicas-plain-text`, `statefulset-data-not-found-state`).
- The DaemonSet list view: card title EXACTLY `DaemonSet List`; columns
  Name/Desired/Current/Ready/Created (Desired=`status.desired_number_scheduled`,
  Current=`status.current_number_scheduled`, Ready=`status.number_ready`, all
  default 0); every name links to
  `/workload/daemonsets/data?name=<name>&namespace=<ns>`
  (`daemonset-list-renders-rows`, `daemonset-list-status-fields`).
- The DaemonSet data view: card title `DaemonSet Data` (the 4.1 `Daemonset
  Data` is FIXED to proper casing); five `CTabs` (DaemonSet/Containers/
  Variables/Security Contexts/Related Resources — the first tab labeled
  `DaemonSet`, NOT `Deployment`) + the JSON block; the DaemonSet tab's Desired
  is plain text (NO spinner); a miss is the pinned state `No daemonset '<name>'
  found` (`daemonset-data-renders-detail`, `daemonset-data-title-fixed`,
  `daemonset-data-not-found-state`).
- The ReplicaSet list view: card title EXACTLY `ReplicaSet List`; columns
  Name/Desired/Current/Ready/Owner (Desired=`status.fully_labeled_replicas`,
  Current=`status.available_replicas`, Ready=`status.ready_replicas`, all
  default 0; Owner=first `owner_references` `<kind-lowercase>s/<name>`, plain
  text until the deployments view is landed); every name links to
  `/workload/replicasets/data?name=<name>&namespace=<ns>` (a 5.0 addition —
  4.1's Name cell was not a link) (`replicaset-list-renders-rows`,
  `replicaset-list-status-fields`, `replicaset-list-name-links-added`).
- The ReplicaSet data view (a 5.0 addition — 4.1 had no data page): card title
  `ReplicaSet Data`; five `CTabs` (ReplicaSet/Containers/Variables/Security
  Contexts/Related Resources) + the JSON block; the ReplicaSet tab's Desired is
  plain text + the Owner is plain text (until the deployments view is landed);
  a miss is the pinned state `No replicaset '<name>' found`
  (`replicaset-data-renders-detail`, `replicaset-data-not-found-state`).
- All three Related Resources tabs deep-link Secrets to
  `/security/secret/data?name=<n>&namespace=<ns>` (landed) and render
  ConfigMap/PVC/ServiceAccount/ImagePullSecret as plain text (not yet landed)
  (`related-resources-deep-link-secrets-only`).
- All three stubs are removed from `views/Stub/routes.ts`; all six routes are
  wired; the nav leaves are UNCHANGED (`stub-removed-and-routes-wired`).

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/app/services/k8s_client.py` — `self._apps` (if absent) + six
  methods (`list_stateful_sets`/`get_stateful_set`/`list_daemon_sets`/
  `get_daemon_set`/`list_replica_sets`/`get_replica_set`) (modified).
- `backend/app/api/resources.py` — six dict rows (three `_KINDS` + three
  `_GETTERS`) (modified).
- `backend/tests/services/test_k8s_client_statefulsets.py` (new).
- `backend/tests/services/test_k8s_client_daemonsets.py` (new).
- `backend/tests/services/test_k8s_client_replicasets.py` (new).
- `backend/tests/api/test_resources.py` — FakeK8s methods + 15 new tests
  (modified).
- `frontend/src/lib/types.ts` — `StatefulSetItem` + `DaemonSetItem` +
  `ReplicaSetItem` (modified).
- `frontend/src/views/Workload/StatefulSet.tsx` (new).
- `frontend/src/views/Workload/StatefulSetData.tsx` (new).
- `frontend/src/views/Workload/DaemonSet.tsx` (new).
- `frontend/src/views/Workload/DaemonSetData.tsx` (new).
- `frontend/src/views/Workload/ReplicaSet.tsx` (new).
- `frontend/src/views/Workload/ReplicaSetData.tsx` (new).
- `frontend/tests/views/statefulsets.test.tsx` (new).
- `frontend/tests/views/statefulset_data.test.tsx` (new).
- `frontend/tests/views/daemonsets.test.tsx` (new).
- `frontend/tests/views/daemonset_data.test.tsx` (new).
- `frontend/tests/views/replicasets.test.tsx` (new).
- `frontend/tests/views/replicaset_data.test.tsx` (new).
- `frontend/src/App.tsx`, `frontend/src/views/Stub/routes.ts`,
  `frontend/tests/views/Stub.test.tsx` (modified).

**Key links** (critical connections that must work together):
- The `_KINDS` row and the `_GETTERS` row are ONE behavior per kind: the same
  route branch serves list AND `?name=`. A `_GETTERS` row without a matching
  client method is a 500 at `getattr(pool.get(cluster), ...)` — both rows land
  in the same commit as the service methods (six rows + six methods total).
- **All three kinds are namespaced `apps/v1`**: the list URL and the data URL
  carry `namespace=<ns>`; SAR group = `apps`, namespace = the query value; the
  client methods use `list_namespaced_stateful_set` /
  `read_namespaced_stateful_set` / `list_namespaced_daemon_set` /
  `read_namespaced_daemon_set` / `list_namespaced_replica_set` /
  `read_namespaced_replica_set` (all on `self._apps`).
- **The `self._apps` attribute is shared with the deployments spec** — this
  spec adds it if absent; the companion `pods-deployments-views` spec adds it
  too. A WHY-comment on the attribute notes the shared ownership (so the
  deployments spec's implementer dedupes rather than re-adds). The three kinds
  are self-contained on it (they work whether the deployments spec lands
  before or after).
- **The three data pages share the `spec.template.spec` shape** — the
  Containers / Variables / Security Contexts / Related Resources tabs are
  IDENTICAL across StatefulSet / DaemonSet / ReplicaSet (the `apps/v1`
  workload template is the same). Only the first tab differs (the metadata
  row set: Replicas vs Desired vs Desired+Owner). This is a deliberate
  DRY opportunity — the three data views can share a common
  `WorkloadTemplateTabs` component (the Containers/Variables/Security/Related
  Resources tabs) parameterized by the first tab's content.
- **The `Pod` / workload types must be extended** before the views compile:
  `fe-build` runs `tsc --noEmit` over TEST files too. The three types
  (`StatefulSetItem` / `DaemonSetItem` / `ReplicaSetItem`) share the
  `spec.template.spec` shape (containers/init_containers/env/volumes/
  image_pull_secrets/service_account_name/security_context) + the
  `spec.selector.match_labels` + the kind-specific status fields
  (`status.replicas`/`current_replicas`/`ready_replicas` for StatefulSet;
  `status.desired_number_scheduled`/`current_number_scheduled`/`number_ready`
  for DaemonSet; `status.fully_labeled_replicas`/`available_replicas`/
  `ready_replicas` + `metadata.owner_references` for ReplicaSet).
- The list view's name-link href is the SOLE producer of the data page's
  `?name=&namespace=` query strings — the data page parses the params, never
  constructs one (the HPA contract; keep it).
- The data view's NOT_FOUND branch depends on the backend's 0/1-item list
  contract (`[]` on 404) — the data view must NOT treat `items: []` as an API
  error (the `NOT_FOUND`-as-throw-not-found-state pattern from
  `HorizontalPodAutoscalerData.tsx`).
- **The 4.1 data-page title bugs are fixed, the LIST titles are kept
  verbatim** — the e2e-smoke contract pins the LIST card titles (`Statefulset
  List` / `DaemonSet List` / `ReplicaSet List` — the `Statefullset` typo is
  NOT replicated, the correct casing is used). The DATA card titles + the first-
  tab labels are the 4.1 copy-paste bugs that are FIXED (`StatefulSet Data` /
  `DaemonSet Data` / `ReplicaSet Data`; tabs `StatefulSet` / `DaemonSet` /
  `ReplicaSet`). Do NOT "fix" the LIST titles beyond the `Statefullset`
  casing (the e2e-smoke contract).
- **The ReplicaSet data page is a 5.0 addition** — 4.1 had no
  `replicaset-data.html.j2`. The ReplicaSet list Name cell GAINS a link (4.1's
  was not a link). The data page follows the Deployment-tab shape (the same
  `spec.template.spec` tabs) for consistency with every other 5.0 data page.
- **The ReplicaSet owner deep-link is deferred** — the owner renders as plain
  text until the deployments view is landed (the not-yet-landed
  `pods-deployments-views` spec); the deep-link to
  `/workload/deployments/data?name=<owner>&namespace=<ns>` is added when that
  view lands (the same "deep-link to landed kinds" pattern as
  `pods-deployments-views`).
- **The Related Resources deep-links only to LANDED destinations** — Secrets →
  `/security/secret/data?name=<n>&namespace=<ns>` (landed); ConfigMap / PVC /
  ServiceAccount / ImagePullSecret → plain text (their views are not yet
  landed). Do NOT deep-link to non-landed kinds (the links would 404).

**One-way-door decisions:** None (no migration, no public-API break, no
dependency add; the kind table is additive; the shared `self._apps` attribute
is deduped, not a door).

## Global Constraints

- No new Python dependency — `AppsV1Api` is already in the kubernetes client;
  at most ONE new attribute (`self._apps`) in `K8sClient.__init__` (shared
  with the deployments spec — air-gap, ADR-0020).
- No new npm dependency (ADR-0020) — `react-syntax-highlighter` is already
  imported (the `json` grammar already registered); `CTabs`/`CTab`/
  `CTabContent` + `KubeDataTable` + CoreUI are existing.
- All three kinds are namespaced (group `apps`): the list URL and the data URL
  carry `namespace=<ns>`; SAR group = `apps`, namespace = the query value; the
  client methods use the `list_namespaced_*` / `read_namespaced_*` `apps/v1`
  methods on `self._apps`.
- The full-object blocks are `JSON.stringify(item, null, 2)` with hljs grammar
  `json`, style `anOldHope` (the truthful-classifier rule).
- Card titles EXACTLY (the e2e-smoke contracts — the LIST titles, kept
  verbatim with the `Statefullset` casing fixed): `Statefulset List`,
  `DaemonSet List`, `ReplicaSet List`. The DATA titles (the 4.1 bugs FIXED):
  `StatefulSet Data`, `DaemonSet Data`, `ReplicaSet Data`. The first-tab labels
  (the 4.1 bugs FIXED): `StatefulSet`, `DaemonSet`, `ReplicaSet`.
- Pinned copy (do not reword): `No statefulsets found`,
  `No statefulset '<name>' found`, `Error: statefulset name not provided`,
  `No daemonsets found`, `No daemonset '<name>' found`,
  `Error: daemonset name not provided`, `No replicasets found`,
  `No replicaset '<name>' found`, `Error: replicaset name not provided`,
  `No cluster selected.`, `Loading statefulsets...`, `Loading daemonsets...`,
  `Loading replicasets...`, `No labels`, `No annotations`, `No init
  containers`, `No variables`, `No security context`, `No selectors`.
- Conventional commits; spec-zone commits precede code-zone commits;
  WHY-comments on load-bearing invariants (the shared `self._apps`, the title-
  bug fixes, the ReplicaSet data-page addition).
- `fe-build` runs `tsc --noEmit` over TEST files too — type any new test
  params explicitly.

## File Structure

- `backend/app/services/k8s_client.py` (modify) — `self._apps` in `__init__`
  (if absent, next to `self._v1`, with the shared-ownership WHY-comment);
  `list_stateful_sets` / `get_stateful_set` / `list_daemon_sets` /
  `get_daemon_set` / `list_replica_sets` / `get_replica_set` (next to the HPA
  methods — the namespaced-core pattern).
- `backend/app/api/resources.py` (modify) — `_KINDS` + `_GETTERS` rows for all
  three kinds.
- `backend/tests/services/test_k8s_client_statefulsets.py` (new) — the
  `AppsV1Api` fake for `list_namespaced_stateful_set` /
  `read_namespaced_stateful_set`.
- `backend/tests/services/test_k8s_client_daemonsets.py` (new) — the
  `AppsV1Api` fake for `list_namespaced_daemon_set` /
  `read_namespaced_daemon_set`.
- `backend/tests/services/test_k8s_client_replicasets.py` (new) — the
  `AppsV1Api` fake for `list_namespaced_replica_set` /
  `read_namespaced_replica_set`.
- `backend/tests/api/test_resources.py` (modify) — FakeK8s gains the six
  methods; 15 new tests (5 per kind).
- `frontend/src/lib/types.ts` (modify) — `StatefulSetItem` + `DaemonSetItem`
  + `ReplicaSetItem` (the shared `spec.template.spec` shape + the kind-specific
  status fields; next to `DeploymentItem`).
- `frontend/src/views/Workload/StatefulSet.tsx` (new) — namespaced layout from
  the HPA list (the Name/Desired/Current/Ready/Created columns).
- `frontend/src/views/Workload/StatefulSetData.tsx` (new) — five-tab `CTabs`
  page (StatefulSet/Containers/Variables/Security Contexts/Related Resources)
  + the JSON block.
- `frontend/src/views/Workload/DaemonSet.tsx` (new) — namespaced layout from
  the HPA list (the Name/Desired/Current/Ready/Created columns).
- `frontend/src/views/Workload/DaemonSetData.tsx` (new) — five-tab `CTabs`
  page (DaemonSet/Containers/Variables/Security Contexts/Related Resources) +
  the JSON block.
- `frontend/src/views/Workload/ReplicaSet.tsx` (new) — namespaced layout from
  the HPA list (the Name/Desired/Current/Ready/Owner columns).
- `frontend/src/views/Workload/ReplicaSetData.tsx` (new) — five-tab `CTabs`
  page (ReplicaSet/Containers/Variables/Security Contexts/Related Resources) +
  the JSON block (the 5.0 addition).
- `frontend/src/views/Workload/WorkloadTemplateTabs.tsx` (new, optional DRY)
  — the shared Containers/Variables/Security Contexts/Related Resources tabs
  (the `spec.template.spec` shape, parameterized by the first tab's content).
- `frontend/tests/views/statefulsets.test.tsx` (new).
- `frontend/tests/views/statefulset_data.test.tsx` (new).
- `frontend/tests/views/daemonsets.test.tsx` (new).
- `frontend/tests/views/daemonset_data.test.tsx` (new).
- `frontend/tests/views/replicasets.test.tsx` (new).
- `frontend/tests/views/replicaset_data.test.tsx` (new).
- `frontend/src/App.tsx` (modify) — the six routes + the six imports.
- `frontend/src/views/Stub/routes.ts` (modify) — remove lines 12–14
  (`/workload/statefulsets` + `/workload/daemonsets` + `/workload/replicasets`).
- `frontend/tests/views/Stub.test.tsx` (modify) — add the three paths to the
  `viewPaths` set (the stubs are removed; the test must not expect them).

---

### Task 1: Backend — the three `apps/v1` kinds (service + `_KINDS`/`_GETTERS` + API tests)

**SATISFIES:** `statefulsets-list-200-in-namespace`, `statefulsets-sar-denied`,
`statefulset-kind-singular-rejected`, `statefulsets-get-by-name`,
`daemonsets-list-200-in-namespace`, `daemonsets-sar-denied`,
`daemonset-kind-singular-rejected`, `daemonsets-get-by-name`,
`replicasets-list-200-in-namespace`, `replicasets-sar-denied`,
`replicaset-kind-singular-rejected`, `replicasets-get-by-name`

**Files:**
- Modify: `backend/app/services/k8s_client.py`
- Modify: `backend/app/api/resources.py`
- Test: `backend/tests/services/test_k8s_client_statefulsets.py` (new)
- Test: `backend/tests/services/test_k8s_client_daemonsets.py` (new)
- Test: `backend/tests/services/test_k8s_client_replicasets.py` (new)
- Test: `backend/tests/api/test_resources.py` (extend)

**Interfaces:**
- Consumes: nothing (first code task).
- Produces: `K8sClient.list_stateful_sets(namespace)` /
  `get_stateful_set(namespace, name)` / `list_daemon_sets(namespace)` /
  `get_daemon_set(namespace, name)` / `list_replica_sets(namespace)` /
  `get_replica_set(namespace, name)` — the exact names `_KINDS`/`_GETTERS`
  reference via `getattr`.
- Seam: the existing `pool` factory (the FakeK8s injection seam is already
  proven by the HPA / VPA tests).
- Deletion test: delete the six `_KINDS`/`_GETTERS` rows → the three kinds 404
  with `RESOURCE_KIND_NOT_SUPPORTED` again; delete the service methods → the
  service tests fail.
- Adapters: 1 (in-process k8s client); no port.

- [ ] **Step 1: Write the failing service tests** — three new test files
  (mirror the HPA test pattern, an `AppsV1Api` fake):
  - `test_k8s_client_statefulsets.py`: the namespaced call
    (`list_namespaced_stateful_set` / `read_namespaced_stateful_set`), `to_dict`
    form with `status.replicas`/`current_replicas`/`ready_replicas` +
    `spec.template.spec`, list 500 → `ClusterUnreachableError`, getter 404 →
    `[]`.
  - `test_k8s_client_daemonsets.py`: the namespaced call
    (`list_namespaced_daemon_set` / `read_namespaced_daemon_set`), `to_dict`
    form with `status.desired_number_scheduled`/`current_number_scheduled`/
    `number_ready`, list 500 → `ClusterUnreachableError`, getter 404 → `[]`.
  - `test_k8s_client_replicasets.py`: the namespaced call
    (`list_namespaced_replica_set` / `read_namespaced_replica_set`), `to_dict`
    form with `status.fully_labeled_replicas`/`available_replicas`/
    `ready_replicas` + `metadata.owner_references`, list 500 →
    `ClusterUnreachableError`, getter 404 → `[]`.
- [ ] **Step 2: Run, confirm RED** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_statefulsets.py tests/services/test_k8s_client_daemonsets.py tests/services/test_k8s_client_replicasets.py -q`.
  Expected: FAIL (no methods).
- [ ] **Step 3: Add `self._apps` + the six methods** — `k8s_client.py`. Verify
  `self._apps` exists in `__init__`; if absent, add `self._apps =
  k8s_client.AppsV1Api(api_client)` next to `self._v1`:
  ```python
  # SHARED with the pods-deployments-views change (which adds list_deployments /
  # get_deployment on the same AppsV1Api). The attribute is added ONCE; the
  # companion spec dedupes rather than re-adds it (the statefulsets-daemonsets-
  # replicasets-views + pods-deployments-views changes both use self._apps).
  self._apps = k8s_client.AppsV1Api(api_client)
  ```
  Next to the HPA methods (the namespaced-core pattern):
  ```python
  def list_stateful_sets(self, namespace: str | None) -> list[dict[str, Any]]:
      """StatefulSet list in the standard kubernetes dict form (``to_dict``).
      Namespaced (apps/v1): ``list_namespaced_stateful_set``. A transport
      ApiException maps to ``ClusterUnreachableError`` (502)."""
      if not namespace:
          return []
      try:
          resp = self._apps.list_namespaced_stateful_set(namespace)
      except ApiException as e:
          self._unreachable("list_stateful_sets", e)
          raise AssertionError("unreachable") from e
      return [s.to_dict() for s in resp.items]

  def get_stateful_set(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One StatefulSet as a 0/1-item list in the standard kubernetes dict
      form (``to_dict``); ``[]`` on 404. Namespaced (apps/v1,
      ``read_namespaced_stateful_set``). Any other ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          return [self._apps.read_namespaced_stateful_set(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_stateful_set", e)
          raise AssertionError("unreachable") from e

  def list_daemon_sets(self, namespace: str | None) -> list[dict[str, Any]]:
      """DaemonSet list in the standard kubernetes dict form (``to_dict``).
      Namespaced (apps/v1): ``list_namespaced_daemon_set``. A transport
      ApiException maps to ``ClusterUnreachableError`` (502)."""
      if not namespace:
          return []
      try:
          resp = self._apps.list_namespaced_daemon_set(namespace)
      except ApiException as e:
          self._unreachable("list_daemon_sets", e)
          raise AssertionError("unreachable") from e
      return [d.to_dict() for d in resp.items]

  def get_daemon_set(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One DaemonSet as a 0/1-item list in the standard kubernetes dict form
      (``to_dict``); ``[]`` on 404. Namespaced (apps/v1,
      ``read_namespaced_daemon_set``). Any other ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          return [self._apps.read_namespaced_daemon_set(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_daemon_set", e)
          raise AssertionError("unreachable") from e

  def list_replica_sets(self, namespace: str | None) -> list[dict[str, Any]]:
      """ReplicaSet list in the standard kubernetes dict form (``to_dict``).
      Namespaced (apps/v1): ``list_namespaced_replica_set``. A transport
      ApiException maps to ``ClusterUnreachableError`` (502)."""
      if not namespace:
          return []
      try:
          resp = self._apps.list_namespaced_replica_set(namespace)
      except ApiException as e:
          self._unreachable("list_replica_sets", e)
          raise AssertionError("unreachable") from e
      return [r.to_dict() for r in resp.items]

  def get_replica_set(self, namespace: str, name: str) -> list[dict[str, Any]]:
      """One ReplicaSet as a 0/1-item list in the standard kubernetes dict
      form (``to_dict``); ``[]`` on 404. Namespaced (apps/v1,
      ``read_namespaced_replica_set``). Any other ApiException maps to
      ``ClusterUnreachableError`` (502)."""
      try:
          return [self._apps.read_namespaced_replica_set(name, namespace).to_dict()]
      except ApiException as e:
          if e.status == 404:
              return []
          self._unreachable("get_replica_set", e)
          raise AssertionError("unreachable") from e
  ```
  (match the HPA method's exact namespace handling — if
  `list_horizontal_pod_autoscalers` falls back to all-namespaces when the
  namespace is `None`, mirror that decision here; verify against the HPA
  source.)
- [ ] **Step 4: Wire the kinds + write the failing API tests** —
  `backend/app/api/resources.py`:
  ```python
  # StatefulSet (apps/v1, namespaced) — the 4.1-parity nav leaf resolved by
  # the statefulsets-daemonsets-replicasets-views change (list + data views;
  # ADR-0022 placement).
  "statefulsets": ("list_stateful_sets", "statefulsets", "apps"),
  # DaemonSet (apps/v1, namespaced) — the 4.1-parity nav leaf resolved by the
  # same change (list + data views; ADR-0022 placement).
  "daemonsets": ("list_daemon_sets", "daemonsets", "apps"),
  # ReplicaSet (apps/v1, namespaced) — the 4.1-parity nav leaf resolved by the
  # same change (list + data views; the data page is a 5.0 addition — 4.1 was
  # list-only; ADR-0022 placement).
  "replicasets": ("list_replica_sets", "replicasets", "apps"),
  ```
  in `_KINDS`, and `"statefulsets": "get_stateful_set"` +
  `"daemonsets": "get_daemon_set"` + `"replicasets": "get_replica_set"` in
  `_GETTERS`.

  Then `backend/tests/api/test_resources.py` (mirror the HPA block ×3):
  - FakeK8s gains the six methods (the StatefulSet fake returns a
    `to_dict`-shaped item with `status.replicas` + `spec.template.spec`; the
    DaemonSet fake returns `status.desired_number_scheduled` +
    `spec.template.spec`; the ReplicaSet fake returns
    `status.fully_labeled_replicas` + `metadata.owner_references` +
    `spec.template.spec`).
  - 15 new tests (5 per kind, same docstring-tag style):
    - StatefulSet: `list_200_in_namespace` (kind + to_dict form),
      `get_by_name` (hit + miss), `sar_denied` (assert `("list", "statefulsets",
      <ns>, None, "apps")` in `asked`), `binding_404`, `singular_rejected`
      (`statefulset`).
    - DaemonSet: `list_200_in_namespace`, `get_by_name`, `sar_denied` (assert
      `("list", "daemonsets", <ns>, None, "apps")`), `binding_404`,
      `singular_rejected` (`daemonset`).
    - ReplicaSet: `list_200_in_namespace`, `get_by_name`, `sar_denied` (assert
      `("list", "replicasets", <ns>, None, "apps")`), `binding_404`,
      `singular_rejected` (`replicaset`).
- [ ] **Step 5: Run, confirm GREEN** — from `backend/`:
  `uv run pytest tests/services/test_k8s_client_statefulsets.py tests/services/test_k8s_client_daemonsets.py tests/services/test_k8s_client_replicasets.py tests/api/test_resources.py -q`
  (the 3 pre-existing kind-fixture errors from the missing Docker daemon are
  the known baseline — everything else green).
- [ ] **Step 6: Commit** —
  `git add backend/app/services/k8s_client.py backend/app/api/resources.py backend/tests/services/test_k8s_client_statefulsets.py backend/tests/services/test_k8s_client_daemonsets.py backend/tests/services/test_k8s_client_replicasets.py backend/tests/api/test_resources.py`
  `git commit -m "feat(resources): statefulsets + daemonsets + replicasets kinds (apps/v1, namespaced, SAR-gated)"`

### Task 2: Frontend — StatefulSet list + data views + tests

**SATISFIES:** `statefulset-list-renders-rows`, `statefulset-list-status-fields`,
`statefulset-data-renders-detail`, `statefulset-data-title-fixed`,
`statefulset-data-replicas-plain-text`, `statefulset-data-not-found-state`,
`related-resources-deep-link-secrets-only`

**Files:**
- Modify: `frontend/src/lib/types.ts` (add `StatefulSetItem`)
- Create: `frontend/src/views/Workload/StatefulSet.tsx`
- Create: `frontend/src/views/Workload/StatefulSetData.tsx`
- Create: `frontend/src/views/Workload/WorkloadTemplateTabs.tsx` (the shared
  template tabs — the DRY component)
- Test: `frontend/tests/views/statefulsets.test.tsx` (new)
- Test: `frontend/tests/views/statefulset_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `statefulsets` list + `?name=` URLs, namespaced).
- Produces: the data-page link
  `/workload/statefulsets/data?name=<name>&namespace=<ns>` (the sole producer)
  + the `WorkloadTemplateTabs` component (reused by Tasks 3–4).
- Seam: `apiFetch` + TanStack Query + `useClusterStore.selectedCluster` + the
  selected-namespace store.
- Deletion test: deleting the views → the routes (Task 5) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `StatefulSetItem` next to `DeploymentItem`:
  ```ts
  /** A StatefulSet item (kubernetes to_dict, snake_case; namespaced apps/v1). */
  export interface StatefulSetItem {
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
      current_replicas?: number
      ready_replicas?: number
      updated_replicas?: number
      conditions?: { type?: string; reason?: string; message?: string; last_transition_time?: string }[]
    }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Build the shared template tabs** —
  `frontend/src/views/Workload/WorkloadTemplateTabs.tsx`: a component that
  renders the Containers (Init + main CTables, name+image) / Variables /
  Security Contexts / Related Resources tabs from a `spec.template.spec`
  object (the deep-links: Secrets → `/security/secret/data?name=<n>&namespace=
  <ns>`, the rest plain text). This is the DRY component the three data views
  reuse.
- [ ] **Step 3: Write the failing view tests** — clone
  `horizontal_pod_autoscalers.test.tsx` + `horizontal_pod_autoscaler_data.test.tsx`:
  list (card title `Statefulset List` — the 4.1 `Statefullset` typo NOT
  replicated; columns Name/Desired/Current/Ready/Created; Desired=`status.
  replicas`, Current=`status.current_replicas`, Ready=`status.ready_replicas`;
  name link `/workload/statefulsets/data?name=<n>&namespace=<ns>`, no-cluster,
  no-namespace, empty) + data (card title `StatefulSet Data` — the 4.1
  `Deployment Data` bug FIXED; five tabs StatefulSet/Containers/Variables/
  Security Contexts/Related Resources — the first tab labeled `StatefulSet`;
  Replicas plain text; the Related Resources tab deep-links Secrets + plain-
  texts the rest; not-found state; missing-name).
- [ ] **Step 4: Run, confirm RED.**
- [ ] **Step 5: Implement** — `StatefulSet.tsx` (namespaced layout from the
  HPA list; Desired/Current/Ready from `status.replicas`/`current_replicas`/
  `ready_replicas` ?? 0; Created = `formatTimestamp`); `StatefulSetData.tsx`
  (five-tab `CTabs` page — the StatefulSet tab CTable (Replicas plain text,
  Selectors sub-table) + the `WorkloadTemplateTabs` + the JSON block; the
  NOT_FOUND state).
- [ ] **Step 6: Run, confirm GREEN.**
- [ ] **Step 7: Commit** —
  `git commit -m "feat(frontend): statefulset list + data views (4.1 port, title bug fixed, apps/v1)"`

### Task 3: Frontend — DaemonSet list + data views + tests

**SATISFIES:** `daemonset-list-renders-rows`, `daemonset-list-status-fields`,
`daemonset-data-renders-detail`, `daemonset-data-title-fixed`,
`daemonset-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts` (add `DaemonSetItem`)
- Create: `frontend/src/views/Workload/DaemonSet.tsx`
- Create: `frontend/src/views/Workload/DaemonSetData.tsx`
- Test: `frontend/tests/views/daemonsets.test.tsx` (new)
- Test: `frontend/tests/views/daemonset_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `daemonsets` list + `?name=` URLs) + Task 2's
  `WorkloadTemplateTabs`.
- Produces: the data-page link
  `/workload/daemonsets/data?name=<name>&namespace=<ns>` (the sole producer).
- Seam: `apiFetch` + TanStack Query + the selected-namespace store.
- Deletion test: deleting the views → the routes (Task 5) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `DaemonSetItem` next to `StatefulSetItem`:
  ```ts
  /** A DaemonSet item (kubernetes to_dict, snake_case; namespaced apps/v1). */
  export interface DaemonSetItem {
    metadata?: { name?: string; namespace?: string; creation_timestamp?: string;
      labels?: Record<string, string>; annotations?: Record<string, string> }
    spec?: {
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
      desired_number_scheduled?: number
      current_number_scheduled?: number
      number_ready?: number
      number_available?: number
      number_misscheduled?: number
      updated_number_scheduled?: number
    }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone the HPA +
  `statefulsets.test.tsx` patterns: list (card title `DaemonSet List`; columns
  Name/Desired/Current/Ready/Created; Desired=`status.desired_number_scheduled`,
  Current=`status.current_number_scheduled`, Ready=`status.number_ready`; name
  link, no-cluster, no-namespace, empty) + data (card title `DaemonSet Data` —
  the 4.1 `Daemonset Data` FIXED; five tabs DaemonSet/Containers/Variables/
  Security Contexts/Related Resources — the first tab labeled `DaemonSet`;
  Desired plain text; the Related Resources tab; not-found state; missing-name).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `DaemonSet.tsx` (namespaced layout from the HPA
  list; Desired/Current/Ready from `status.desired_number_scheduled` /
  `current_number_scheduled` / `number_ready` ?? 0; Created =
  `formatTimestamp`); `DaemonSetData.tsx` (five-tab `CTabs` page — the
  DaemonSet tab CTable (Desired plain text, Selectors sub-table) + the
  `WorkloadTemplateTabs` + the JSON block; the NOT_FOUND state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): daemonset list + data views (4.1 port, title bug fixed, apps/v1)"`

### Task 4: Frontend — ReplicaSet list + data views + tests

**SATISFIES:** `replicaset-list-renders-rows`, `replicaset-list-status-fields`,
`replicaset-list-name-links-added`, `replicaset-data-renders-detail`,
`replicaset-data-not-found-state`

**Files:**
- Modify: `frontend/src/lib/types.ts` (add `ReplicaSetItem`)
- Create: `frontend/src/views/Workload/ReplicaSet.tsx`
- Create: `frontend/src/views/Workload/ReplicaSetData.tsx`
- Test: `frontend/tests/views/replicasets.test.tsx` (new)
- Test: `frontend/tests/views/replicaset_data.test.tsx` (new)

**Interfaces:**
- Consumes: Task 1's API (the `replicasets` list + `?name=` URLs) + Task 2's
  `WorkloadTemplateTabs`.
- Produces: the data-page link
  `/workload/replicasets/data?name=<name>&namespace=<ns>` (the sole producer —
  a 5.0 addition, 4.1's Name cell was not a link).
- Seam: `apiFetch` + TanStack Query + the selected-namespace store.
- Deletion test: deleting the views → the routes (Task 5) 404.
- Adapters: 1; no port.

- [ ] **Step 1: Add the type** — `ReplicaSetItem` next to `DaemonSetItem`:
  ```ts
  /** A ReplicaSet item (kubernetes to_dict, snake_case; namespaced apps/v1). */
  export interface ReplicaSetItem {
    metadata?: { name?: string; namespace?: string; creation_timestamp?: string;
      labels?: Record<string, string>; annotations?: Record<string, string>;
      owner_references?: { kind?: string; name?: string; [k: string]: unknown }[] }
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
      fully_labeled_replicas?: number
      available_replicas?: number
      ready_replicas?: number
      current_replicas?: number
      updated_replicas?: number
    }
    [key: string]: unknown
  }
  ```
- [ ] **Step 2: Write the failing view tests** — clone the HPA +
  `statefulsets.test.tsx` patterns: list (card title `ReplicaSet List`; columns
  Name/Desired/Current/Ready/Owner; Desired=`status.fully_labeled_replicas`,
  Current=`status.available_replicas`, Ready=`status.ready_replicas`; Owner =
  first `owner_references` `<kind-lowercase>s/<name>` plain text (until the
  deployments view is landed); **the Name cell IS a link** to
  `/workload/replicasets/data?name=<n>&namespace=<ns>` — a 5.0 addition; no-
  cluster, no-namespace, empty) + data (card title `ReplicaSet Data` — the 5.0
  addition; five tabs ReplicaSet/Containers/Variables/Security Contexts/
  Related Resources; Desired plain text + Owner plain text; the Related
  Resources tab; not-found state; missing-name).
- [ ] **Step 3: Run, confirm RED.**
- [ ] **Step 4: Implement** — `ReplicaSet.tsx` (namespaced layout from the HPA
  list; Desired/Current/Ready from `status.fully_labeled_replicas` /
  `available_replicas` / `ready_replicas` ?? 0; Owner = first
  `owner_references` → `${kind.toLowerCase()}s/${name}` plain text; **the Name
  cell links to the data page** — the 5.0 addition); `ReplicaSetData.tsx`
  (five-tab `CTabs` page — the ReplicaSet tab CTable (Desired plain text,
  Owner plain text, Selectors sub-table) + the `WorkloadTemplateTabs` + the
  JSON block; the NOT_FOUND state).
- [ ] **Step 5: Run, confirm GREEN.**
- [ ] **Step 6: Commit** —
  `git commit -m "feat(frontend): replicaset list + data views (data page is a 5.0 addition, apps/v1)"`

### Task 5: Routing + stub removal + full verification

**SATISFIES:** `stub-removed-and-routes-wired`

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/views/Stub/routes.ts`
- Modify: `frontend/tests/views/Stub.test.tsx`

**Interfaces:**
- Consumes: Tasks 2–4's view components.
- Produces: the resolved nav leaves (the goal).
- Seam: react-router `Route` + the stub routes + the `viewPaths` set.
- Deletion test: delete the six `Route`s → the paths 404; re-add the stubs →
  the pages stub again.
- Adapters: 0; pure wiring.

- [ ] **Step 1: Wire the routes** — `App.tsx`: add the six view imports + the
  six routes (mirroring the HPA route block — the namespaced pattern):
  ```tsx
  <Route path="/workload/statefulsets" element={<ProtectedRoute><StatefulSetView /></ProtectedRoute>} />
  <Route path="/workload/statefulsets/data" element={<ProtectedRoute><StatefulSetDataView /></ProtectedRoute>} />
  <Route path="/workload/daemonsets" element={<ProtectedRoute><DaemonSetView /></ProtectedRoute>} />
  <Route path="/workload/daemonsets/data" element={<ProtectedRoute><DaemonSetDataView /></ProtectedRoute>} />
  <Route path="/workload/replicasets" element={<ProtectedRoute><ReplicaSetView /></ProtectedRoute>} />
  <Route path="/workload/replicasets/data" element={<ProtectedRoute><ReplicaSetDataView /></ProtectedRoute>} />
  ```
- [ ] **Step 2: Remove the stubs** — `views/Stub/routes.ts`: delete lines
  12–14 (`/workload/statefulsets` + `/workload/daemonsets` +
  `/workload/replicasets`).
- [ ] **Step 3: Update Stub.test.tsx** — add the three paths to the
  `viewPaths` set in `expectedStubs()` (the stubs are removed; without the
  addition the test expects them to be stubs — RED). Re-run
  `corepack pnpm vitest run tests/views/Stub.test.tsx`.
- [ ] **Step 4: Full verification** — from the repo root:
  - `task fe-build` (tsc --noEmit + eslint + vite build).
  - `task fe-check` (air-gap — no new external refs).
  - `corepack pnpm vitest run` (frontend suite; the known pre-existing
    failures are the baseline).
  - `cd backend && uv run pytest -m "not integration" -q` (full unit suite
    green).
- [ ] **Step 5: Commit** —
  `git add frontend/src/App.tsx frontend/src/views/Stub/routes.ts frontend/tests/views/Stub.test.tsx`
  `git commit -m "feat(frontend): wire statefulsets + daemonsets + replicasets routes, remove stubs"`

---

## Verification Floor (end of change)

- `cd backend && uv run pytest tests/services/test_k8s_client_statefulsets.py tests/services/test_k8s_client_daemonsets.py tests/services/test_k8s_client_replicasets.py tests/api/test_resources.py -q` — all new tests green (3 known kind-fixture errors from missing Docker are the baseline).
- `cd frontend && corepack pnpm vitest run tests/views/statefulsets.test.tsx tests/views/statefulset_data.test.tsx tests/views/daemonsets.test.tsx tests/views/daemonset_data.test.tsx tests/views/replicasets.test.tsx tests/views/replicaset_data.test.tsx tests/views/Stub.test.tsx` — green.
- `task fe-build` + `task fe-check` — green.
- `git diff --stat` vs the change start: `frontend/src/_nav.tsx` UNCHANGED (the leaves already exist); no file outside the File Structure list touched.

## Task Dependencies

```
Task 1 (backend: all three kinds) ──► Task 2 (StatefulSet views + WorkloadTemplateTabs) ──► Task 5 (routing + stubs)
                     ├──► Task 3 (DaemonSet views) ──────────────────────────────────────┤
                     └──► Task 4 (ReplicaSet views) ─────────────────────────────────────┘
```

Tasks 3 and 4 are independent of each other (both consume Task 1 + Task 2's
`WorkloadTemplateTabs`); either can run first or in parallel. Task 2 first
after Task 1 (it builds the shared `WorkloadTemplateTabs` that Tasks 3–4
reuse). Task 5 last (it wires the routes + removes the stubs, so the views
must exist first).

## Rollback

Each task is one conventional commit and independently revertable (no schema,
no dependency, no public contract change). Reverting Task 5 re-adds the three
stubs (self-contained: routes + stubs + test in one commit). Reverting Task 1
reverts all three kinds (the three leaves 404; the shared `self._apps`
attribute reverts with it — the companion deployments spec, if it lands after
this revert, re-adds `self._apps`). Tasks 2, 3, and 4 are independent reverts
(the StatefulSet / DaemonSet / ReplicaSet views are separate commits;
`WorkloadTemplateTabs` reverts with Task 2 — Tasks 3–4 must be reverted before
Task 2, or they reference a missing component). The three kinds are self-
contained on the shared `self._apps` (the dedupe note in the attribute's WHY-
comment tracks the ownership).
