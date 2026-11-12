# StatefulSets + DaemonSets + ReplicaSets Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-29-statefulsets-daemonsets-replicasets-views`
**Date:** 2026-10-29
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

Resolve THREE nav leaves under Workloads to real, SAR-gated, read-only,
**namespaced** list + data pairs, all `apps/v1` kinds (the same `AppsV1Api` the
companion `pods-deployments-views` change uses):

1. **`/workload/statefulsets`** — a 4.1-parity port. 4.1 has real templates:
   `workload/statefulset.html.j2` (list: **Name / Desired / Current / Ready /
   Created** — card title has a 4.1 typo `Statefullset List`) and
   `workload/statefulset-data.html.j2` (data: a 5-tab page — **StatefulSet** /
   **Containers** / **Variables** / **Security Contexts** / **Related
   Resources**; 4.1's data card title is a copy-paste bug `Deployment Data` and
   the first tab is mislabeled `Deployment`). StatefulSet is a **namespaced
   core API** (`statefulsets`, group `apps`). 4.1's read is
   `k8sStatefulSetsGet` (`4.1:src/kubedash/lib/k8s/workload.py:694`):
   `AppsV1Api().list_namespaced_stateful_set(ns, _request_timeout=1)` — a
   generated core-API model, so the `to_dict` form is snake_case. Status comes
   from `status.replicas` (desired) / `status.current_replicas` (current) /
   `status.ready_replicas` (ready).

2. **`/workload/daemonsets`** — a 4.1-parity port. 4.1 has real templates:
   `workload/daemonset.html.j2` (list: **Name / Desired / Current / Ready /
   Created** — card title `DaemonSet List`) and
   `workload/daemonset-data.html.j2` (data: a 5-tab page — **DaemonSet** /
   **Containers** / **Variables** / **Security Contexts** / **Related
   Resources**; 4.1's data card title is `Daemonset Data` and the first tab is
   mislabeled `Deployment`). DaemonSet is a **namespaced core API**
   (`daemonsets`, group `apps`). 4.1's read is `k8sDaemonSetsGet`
   (`4.1:src/kubedash/lib/k8s/workload.py:19`):
   `AppsV1Api().list_namespaced_daemon_set(ns, _request_timeout=1)`. Status
   comes from `status.desired_number_scheduled` (desired) /
   `status.current_number_scheduled` (current) / `status.number_ready` (ready).

3. **`/workload/replicasets`** — a 4.1 port **extended** (ratified
   2026-10-29). 4.1 has a **list-only** template: `workload/replicaset.html.j2`
   (list: **Name / Desired / Current / Ready / Owner** — card title
   `ReplicaSet List`; the Name cell is NOT a link in 4.1 — there is NO
   `replicaset-data.html.j2`). 4.1's read is `k8sReplicaSetsGet`
   (`4.1:src/kubedash/lib/k8s/workload.py:650`):
   `AppsV1Api().list_namespaced_replica_set(ns, _request_timeout=1)`. Status
   comes from `status.fully_labeled_replicas` (desired) /
   `status.available_replicas` (current) / `status.ready_replicas` (ready); the
   owner is the first `owner_references` entry (`<kind-lowercase>s/<name>`).
   **Ratified 2026-10-29: a data page IS added** (going beyond 4.1) — the
   Deployment-tab shape (metadata + Selectors + Containers + Variables +
   Security + Related Resources) + the full-object JSON block, for consistency
   with every other 5.0 data page.

All three are **namespaced** — the `?namespace=` query param drives the read
(the header's selected-namespace store is the source, as in the HPA /
NetworkPolicies views), and `?name=` drives the data page. The data pages
follow the ratified 5.0 shape: 4.1's curated multi-tab tables + the full-object
`JSON.stringify(item, null, 2)` block with the `json` hljs grammar (the
truthful-classifier rule ratified for PriorityClassData, final review
2026-10-28).

**The `self._apps` seam (the not-yet-landed dependency):** all three kinds use
`AppsV1Api`, which requires a `self._apps` attribute in `K8sClient.__init__`.
The companion `pods-deployments-views` spec (which adds `list_deployments` /
`get_deployment`) also adds `self._apps` and has NOT landed. **This spec adds
`self._apps` if absent** (and the three kinds are self-contained on it); when
the deployments spec lands, the shared `self._apps` attribute is deduplicated
(not re-added) — the same ownership/dedupe pattern as the GatewayClass seam.

Deliver: a real list + data pair at `/workload/statefulsets`,
`/workload/daemonsets`, and `/workload/replicasets` (+ their `/data` routes),
so all three Workloads nav leaves resolve to first-class views.

## Requirements

### R1 — SAR-gated StatefulSet list + `?name=` endpoints

`GET /api/v1/clusters/<id>/resources/statefulsets?namespace=<ns>` MUST return
the StatefulSet list (`kind: "statefulsets"`, items in kubernetes `to_dict`
snake_case form, `metadata`/`spec`/`status` intact). The kind is **namespaced**
(group `apps`). The read is SAR-gated per ADR-0004: `list` on `statefulsets`,
group `apps`, the namespace from the query; on deny → 403 `RBAC_DENIED` naming
the resource, the SAR before the K8s call; unbound → 404. The plural
`statefulsets` is the kind identifier; the singular `statefulset` is rejected
with `RESOURCE_KIND_NOT_SUPPORTED`. `GET ...?namespace=<ns>&name=<name>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a hit
is the full object, a miss is `[]` (the data page renders a not-found state).
SAR-gated on `get` with the namespace. No new HTTP route — the kind is wired
through `_KINDS` + `_GETTERS` only.

### R2 — SAR-gated DaemonSet list + `?name=` endpoints

`GET /api/v1/clusters/<id>/resources/daemonsets?namespace=<ns>` MUST return
the DaemonSet list (`kind: "daemonsets"`, items in `to_dict` snake_case form).
The kind is **namespaced** (group `apps`). SAR-gated on `list` / `get` on
`daemonsets`, group `apps`; deny → 403, unbound → 404; the singular `daemonset`
is rejected with `RESOURCE_KIND_NOT_SUPPORTED`. The `?name=` lookup returns a
0/1-item list (hit = the object, miss = `[]`). No new HTTP route.

### R3 — SAR-gated ReplicaSet list + `?name=` endpoints

`GET /api/v1/clusters/<id>/resources/replicasets?namespace=<ns>` MUST return
the ReplicaSet list (`kind: "replicasets"`, items in `to_dict` snake_case
form). The kind is **namespaced** (group `apps`). SAR-gated on `list` / `get`
on `replicasets`, group `apps`; deny → 403, unbound → 404; the singular
`replicaset` is rejected with `RESOURCE_KIND_NOT_SUPPORTED`. The `?name=`
lookup returns a 0/1-item list (hit = the object, miss = `[]`). No new HTTP
route.

### R4 — The three `K8sClient` service methods + `self._apps`

This change adds three pairs of `K8sClient` methods (list + get, each
`to_dict`-form, `[]` on 404, `ClusterUnreachableError` on other failures):
`list_stateful_sets(namespace)` / `get_stateful_set(namespace, name)`
(`list_namespaced_stateful_set` / `read_namespaced_stateful_set`),
`list_daemon_sets(namespace)` / `get_daemon_set(namespace, name)`
(`list_namespaced_daemon_set` / `read_namespaced_daemon_set`),
`list_replica_sets(namespace)` / `get_replica_set(namespace, name)`
(`list_namespaced_replica_set` / `read_namespaced_replica_set`). All use
`self._apps` (`AppsV1Api`). **`self._apps` is added to `__init__` if absent**
(the companion `pods-deployments-views` spec adds it too — deduped when that
lands; a WHY-comment notes the shared ownership).

### R5 — The StatefulSet list page

`/workload/statefulsets` MUST render a `KubeDataTable` of the selected
namespace's StatefulSets with columns **Name / Desired / Current / Ready /
Created**. The card title is EXACTLY `Statefulset List` (4.1's title, kept
verbatim — the e2e-smoke contract; the 4.1 `Statefullset` typo is a 4.1
artifact, NOT replicated — 5.0 renders `Statefulset List`). The Name cell
links to `/workload/statefulsets/data?name=<name>&namespace=<ns>` — the list
view is the sole producer of those query strings.

- **Desired** = `status.replicas` (default 0).
- **Current** = `status.current_replicas` (default 0).
- **Ready** = `status.ready_replicas` (default 0).
- **Created** = `formatTimestamp` of `metadata.creation_timestamp`.

States: no cluster selected → `No cluster selected.`; no namespace selected →
the namespace selector state; loading → `Loading statefulsets...`; error → red
error line; empty list → `No statefulsets found` (first-class, not an error).

### R6 — The StatefulSet data page (the 4.1 five-tab shape, title bug fixed)

`/workload/statefulsets/data?name=<name>&namespace=<ns>` MUST fetch the object
with a **single `?name=` request**. Empty `items` is a not-found **STATE** —
pinned copy `No statefulset '<name>' found`, muted, not an error. The data
card title is `StatefulSet Data` (the 4.1 copy-paste bug `Deployment Data` is
**fixed** — ratified 2026-10-29). The page renders the 4.1 tabs via CoreUI
`CTabs` (the first tab labeled `StatefulSet`, NOT 4.1's mislabeled
`Deployment`):

- **StatefulSet** (CTable): Namespace / Name / Created / Replicas /
  Annotations (key/value sub-table, `No annotations` when empty, VERBATIM — no
  `trimAnnotations`) / Labels (key/value sub-table, `No labels` when empty) /
  Selectors (key/value sub-table from `spec.selector.match_labels`, `No
  selectors` when absent). **Replicas** = `spec.replicas` as **plain text**
  (4.1's Admin-only replica spinner is NOT replicated — mutation is out of
  scope).
- **Containers**: two CTables — **Init Containers** (Name / Image; `No init
  containers` when absent) and **Containers** (Name / Image) — from
  `spec.template.spec.containers` / `init_containers` (4.1's shape: name +
  image only, the template not a running pod).
- **Variables** (CTable: Name / Value): the env vars from
  `spec.template.spec.containers[].env` with a literal `value` (4.1's
  `environment_variables`); `No variables` when absent.
- **Security Contexts** (CTable: Context / State): the
  `spec.template.spec.security_context` fields as key/value rows (`No security
  context` when absent).
- **Related Resources** (CTable: Type / Name / Namespace): image-pull secrets,
  service account, secrets (env + volumes), configmaps (volumes), PVCs
  (volumes) — from `spec.template.spec`. **Deep-linking (the ratified pattern
  from `pods-deployments-views`):** Secrets → `/security/secret/data?name=<n>
  &namespace=<ns>` (landed); ConfigMap / PVC / ServiceAccount /
  ImagePullSecret → **plain text** (their views are not yet landed).

Below the tabs: the full object as a syntax-highlighted block:
`JSON.stringify(item, null, 2)` with the `json` hljs grammar (style
`anOldHope`). Missing `name` param → `Error: statefulset name not provided`.

### R7 — The DaemonSet list page

`/workload/daemonsets` MUST render a `KubeDataTable` of the selected
namespace's DaemonSets with columns **Name / Desired / Current / Ready /
Created**. The card title is EXACTLY `DaemonSet List` (4.1's title, verbatim —
the e2e-smoke contract). The Name cell links to
`/workload/daemonsets/data?name=<name>&namespace=<ns>`.

- **Desired** = `status.desired_number_scheduled` (default 0).
- **Current** = `status.current_number_scheduled` (default 0).
- **Ready** = `status.number_ready` (default 0).
- **Created** = `formatTimestamp` of `metadata.creation_timestamp`.

States: no cluster → `No cluster selected.`; no namespace → the selector
state; loading → `Loading daemonsets...`; error → red error line; empty →
`No daemonsets found`.

### R8 — The DaemonSet data page (the 4.1 five-tab shape, title bug fixed)

`/workload/daemonsets/data?name=<name>&namespace=<ns>` MUST fetch the object
with a **single `?name=` request**. Empty `items` is a not-found **STATE** —
pinned copy `No daemonset '<name>' found`, muted. The data card title is
`DaemonSet Data` (4.1's `Daemonset Data` is **fixed** to proper casing —
ratified 2026-10-29). The page renders the 4.1 tabs via `CTabs` (the first tab
labeled `DaemonSet`, NOT 4.1's mislabeled `Deployment`):

- **DaemonSet** (CTable): Namespace / Name / Created / Desired / Annotations /
  Labels / Selectors. **Desired** = `status.desired_number_scheduled` as
  **plain text** (4.1's Admin spinner NOT replicated — a DaemonSet has no
  `spec.replicas` to scale; the spinner in 4.1 was a copy-paste artifact).
- **Containers** / **Variables** / **Security Contexts** / **Related
  Resources**: the SAME shape as the StatefulSet data page (R6) — the template
  `spec.template.spec` is the same for both kinds.

Below the tabs: the full-object JSON block. Missing `name` param →
`Error: daemonset name not provided`.

### R9 — The ReplicaSet list page

`/workload/replicasets` MUST render a `KubeDataTable` of the selected
namespace's ReplicaSets with columns **Name / Desired / Current / Ready /
Owner**. The card title is EXACTLY `ReplicaSet List` (4.1's title, verbatim —
the e2e-smoke contract). The Name cell links to
`/workload/replicasets/data?name=<name>&namespace=<ns>` — **a 5.0 addition**
(4.1's Name cell was NOT a link, since 4.1 had no data page; ratified
2026-10-29 the data page is added, so the link is added too).

- **Desired** = `status.fully_labeled_replicas` (default 0).
- **Current** = `status.available_replicas` (default 0).
- **Ready** = `status.ready_replicas` (default 0).
- **Owner** = the first `metadata.owner_references` entry rendered as
  `<kind-lowercase>s/<name>` (4.1's shape), `—` when absent. **Deep-linking:**
  the owner's kind is almost always `deployment` → the owner links to
  `/workload/deployments/data?name=<owner>&namespace=<ns>` **when the
  deployments view is landed** (the companion `pods-deplainments-views` spec);
  until then it is **plain text** (the deep-link is added when the
  deployments view lands — the same "deep-link to landed kinds" pattern).

States: no cluster → `No cluster selected.`; no namespace → the selector
state; loading → `Loading replicasets...`; error → red error line; empty →
`No replicasets found`.

### R10 — The ReplicaSet data page (the 5.0-added shape)

`/workload/replicasets/data?name=<name>&namespace=<ns>` MUST fetch the object
with a **single `?name=` request** — a **5.0 addition** (4.1 had no
`replicaset-data.html.j2`; ratified 2026-10-29). Empty `items` is a not-found
**STATE** — pinned copy `No replicaset '<name>' found`, muted. The data card
title is `ReplicaSet Data`. The page renders the Deployment-tab shape (the
same as the StatefulSet/DaemonSet data pages, the `spec.template.spec` is the
same for all `apps/v1` workload kinds) via `CTabs`:

- **ReplicaSet** (CTable): Namespace / Name / Created / Desired / Owner /
  Annotations / Labels / Selectors. **Desired** = `status.fully_labeled_
  replicas` as **plain text**; **Owner** = the first `owner_references`
  (`<kind-lowercase>s/<name>`, the same deep-link rule as R9).
- **Containers** / **Variables** / **Security Contexts** / **Related
  Resources**: the SAME shape as the StatefulSet data page (R6).

Below the tabs: the full-object JSON block. Missing `name` param →
`Error: replicaset name not provided`.

### R11 — Routing

- `App.tsx` wires all six routes (three list + three data) as `ProtectedRoute`
  views (mirroring the HPA route block — the namespaced pattern).
- No nav change — the three leaves ALREADY exist in the Workloads group in
  `_nav.tsx` (lines 90–92). They are **promoted from stubs** (all three are in
  `views/Stub/routes.ts` lines 12–14). No stub removal is a nav change — the
  stubs are removed, the leaves stay.

## Non-goals

- No create / edit / delete / scale for StatefulSets, DaemonSets, or
  ReplicaSets (read-only, as in every other 5.0 resource view to date; 4.1's
  Admin replica spinners and `k8sDeploymentsPatchReplica` /
  `k8sStatefulSetPatchReplica` / `k8sDaemonsetPatch` are NOT replicated —
  mutation is out of scope).
- No `?labelSelector=` on any of these routes (the pods-route concern, the
  not-yet-landed service-views spec).
- No deep-linking of the ReplicaSet owner to the Deployments view in THIS
  change (the deployments view is the not-yet-landed `pods-deployments-views`
  spec — the deep-link is added when it lands; until then plain text).
- No vuln-report columns (4.1's `has_report` block is commented out; not
  ported).
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title strings `Statefulset List`, `DaemonSet List`, `ReplicaSet List` are
  the only smoke-relevant contracts.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form / POST
   / `session['ns_select']`; no list-then-filter on the data page (a single
   `?name=` request).
2. **The 4.1 data-page title bugs are FIXED** (ratified 2026-10-29) —
   StatefulSet data is `StatefulSet Data` (not 4.1's copy-paste `Deployment
   Data`); DaemonSet data is `DaemonSet Data` (not 4.1's `Daemonset Data`);
   the first-tab labels are `StatefulSet` / `DaemonSet` / `ReplicaSet` (not
   4.1's mislabeled `Deployment`). The LIST card titles are kept verbatim
   (the e2e-smoke contract) — only the 4.1 data-page title bugs are fixed.
3. **The 4.1 `Statefullset List` list-title typo is NOT replicated** — 5.0
   renders `Statefulset List` (the correct casing; the `ll` is a 4.1 artifact).
4. **ReplicaSets GAINS a data page** (ratified 2026-10-29 — 4.1 was list-only,
   no `replicaset-data.html.j2`; the data page follows the Deployment-tab shape
   + the JSON block for consistency with every other 5.0 data page). The
   ReplicaSet list Name cell GAINS a link to the data page (4.1's was not a
   link).
5. **All three data pages GAIN the full-object JSON block** (4.1's data pages
   had none — only the curated tab tables).
6. **The Replicas / Desired is plain text** (4.1's Admin-only replica spinner
   is a write path, NOT replicated — mutation is out of scope).
7. **`trimAnnotations` is NOT replicated** — annotations render verbatim
   (note: 4.1's `k8sStatefulSetsGet` has a latent bug — it calls
   `trimAnnotations(sfs.metadata.labels)` for the annotations field, passing
   the LABELS; 5.0 renders `metadata.annotations` verbatim, the truthful
   field).
8. **The Related Resources tab deep-links to LANDED kinds only** (Secrets →
   the landed Secret data view); ConfigMap / PVC / ServiceAccount /
   ImagePullSecret → **plain text** (their views are not yet landed — the same
   pattern as `pods-deployments-views`).
9. **The ReplicaSet owner deep-link is deferred** — the owner links to the
   Deployments view only when that view is landed (the not-yet-landed
   `pods-deployments-views` spec); until then it is plain text.
10. **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
    every read; 5.0's client uses the pool's configured timeout.
