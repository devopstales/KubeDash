# Pods + Deployments Views (List + Data) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-pods-deployments-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

Resolve TWO nav leaves under Workloads to real, SAR-gated, read-only,
**namespaced** list + data pairs:

1. **`/workload/pods`** — a 4.1-parity port. 4.1 has real templates:
   `workload/pod.html.j2` (list: **Status / Name / Pod IP / Owner** — the
   Report columns and the delete action are commented out in 4.1) and
   `workload/pod-data.html.j2` (data: a 5-tab page — **Pod** / **Containers**
   / **Conditions** / **Security Contexts** / **Related Resources**; 4.1 also
   has exec + logs buttons and a commented-out vuln-report block). Pods are a
   **namespaced core API** (`pods`, group `""`). The 5.0 generic route ALREADY
   wires the `pods` kind to `K8sClient.list_pods` (`_KINDS`), but has **no
   `_GETTERS` entry** (so `?name=` lookup is missing) and `list_pods` does not
   yet accept a label selector. 4.1's read is `k8sPodListGet` / `k8sPodGet`
   (`4.1:src/kubedash/lib/k8s/workload.py:317`/`349`):
   `CoreV1Api().list_namespaced_pod(ns, _request_timeout=1)` /
   `read_namespaced_pod(po, ns, _request_timeout=1)` — generated core-API
   models, so the `to_dict` form is snake_case.

   **The orphaned table is replaced in place (ratified 2026-10-28):** 5.0 has
   an unused all-namespaces `Cluster/Pods.tsx` (nothing imports it —
   `Cluster/index.tsx` says "Pods belong to Interface → Workloads → Pods, not
   this status page"). This change DELETES that orphan and builds
   `/workload/pods` as the single, namespaced, first-class pod view.

2. **`/workload/deployments`** — a 4.1-parity port. 4.1 has real templates:
   `workload/deployment.html.j2` (list: **Name / Status / Created**, Status
   rendered `desired/ready`) and `workloyment/deployment-data.html.j2` (data:
   a 6-tab page — **Deployment** / **Containers** / **Variables** /
   **Conditions** / **Security Contexts** / **Related Resources**; 4.1 has an
   Admin-only replica spinner). Deployments are a **namespaced core API**
   (`deployments`, group `apps`). The 5.0 generic route does NOT wire the
   `deployments` kind yet (no `_KINDS` row, no `list_deployments`). 4.1's read
   is `k8sDeploymentsGet` (`4.1:src/kubedash/lib/k8s/workload.py:151`):
   `AppsV1Api().list_namespaced_deployment(ns, _request_timeout=1)` — a
   generated core-API model, so the `to_dict` form is snake_case.

Both kinds are **namespaced** — the `?namespace=` query param drives the read
(the header's selected-namespace store is the source, as in the
NetworkPolicies/ResourceQuota/HPA views), and `?name=` drives the data page.
The data pages follow the ratified 5.0 shape: 4.1's curated multi-tab tables
+ the full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
grammar (the truthful-classifier rule ratified for PriorityClassData, final
review 2026-10-28).

Deliver: a real list + data pair at `/workload/pods` and
`/workload/pods/data` (the 4.1 port, replacing the orphan), and a real list +
data pair at `/workload/deployments` and `/workload/deployments/data` (the 4.1
port), so both Workloads nav leaves resolve to first-class views.

## Requirements

### R1 — A SAR-gated pods list endpoint

`GET /api/v1/clusters/<id>/resources/pods?namespace=<ns>` MUST return the
pod list for the namespace (`kind: "pods"`, items in kubernetes `to_dict`
snake_case form, `metadata`/`spec`/`status` intact). The kind is
**namespaced** — the namespace comes from the `?namespace=` query param (the
header's selected-namespace store). The read is SAR-gated per ADR-0004:
`list` on `pods`, group `""`, the namespace from the query; on deny the
response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked
BEFORE any K8s client call. An unbound user is 404 from the binding gate. The
kind identifier is the plural `pods`; the singular `pod` is rejected with
`RESOURCE_KIND_NOT_SUPPORTED`.

The `pods` kind is ALREADY wired in `_KINDS` to `list_pods`; this change adds
NO new `_KINDS` row (only the missing `_GETTERS` row — R2).

### R2 — A `?name=` lookup for pods via the existing generic route

`GET /api/v1/clusters/<id>/resources/pods?namespace=<ns>&name=<name>` MUST
return a 0/1-item list through the same generic route (`_GETTERS`): a hit is
the single full object, a miss is `[]` (not a 404 — the data page renders a
not-found state). This requires the missing `_GETTERS["pods"] = "get_pod"` row
+ a new `K8sClient.get_pod(namespace, name)` method (cluster-scoped? no —
namespaced `read_namespaced_pod`; `[]` on 404, `ClusterUnreachableError` on
other failures). SAR-gated on `get` with the namespace. No new HTTP route is
added.

### R3 — A SAR-gated deployments list endpoint

`GET /api/v1/clusters/<id>/resources/deployments?namespace=<ns>` MUST return
the deployment list for the namespace (`kind: "deployments"`, items in
kubernetes `to_dict` snake_case form, `metadata`/`spec`/`status` intact). The
kind is **namespaced**. The read is SAR-gated per ADR-0004: `list` on
`deployments`, group `apps`, the namespace from the query; on deny the
response is 403 `RBAC_DENIED` naming the resource, and the SAR is asked BEFORE
any K8s client call. An unbound user is 404 from the binding gate. The kind
identifier is the plural `deployments`; the singular `deployment` is rejected
with `RESOURCE_KIND_NOT_SUPPORTED`.

This change ADDS the `_KINDS["deployments"]` row + a new
`K8sClient.list_deployments(namespace)` method + one new `__init__` attribute
(`self._apps = k8s_client.AppsV1Api(api_client)`, if absent).

### R4 — A `?name=` lookup for deployments via the existing generic route

`GET /api/v1/clusters/<id>/resources/deployments?namespace=<ns>&name=<name>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single full object, a miss is `[]`. SAR-gated on `get` with the
namespace. This requires the missing `_GETTERS["deployments"] = "get_deployment"`
row + a new `K8sClient.get_deployment(namespace, name)` method
(`read_namespaced_deployment`; `[]` on 404). No new HTTP route is added.

### R5 — The pods list page

`/workload/pods` MUST render a `KubeDataTable` of the selected namespace's
pods with columns **Status / Name / Pod IP / Owner**. The card title is
EXACTLY `Pod List` (4.1's title, kept verbatim — the e2e-smoke contract). The
Name cell links to `/workload/pods/data?name=<name>&namespace=<ns>` — the
list view is the sole producer of those query strings.

- **Status** = the pod's effective phase badge: `Running` (green),
  `Pending` (yellow), `Succeeded` (grey), `Terminated`/`CrashLoopBackOff`
  (red), else blue — matching 4.1's badge mapping. The effective phase is
  `status.phase`, overridden to `Terminated` when `metadata.deletion_timestamp`
  is set (4.1's rule).
- **Pod IP** = `status.pod_ip` (`—` when absent).
- **Owner** = the first `metadata.owner_references` entry rendered as
  `<kind-lowercase>s/<name>` (4.1's `"%ss/%s" % (owner.kind.lower(),
  owner.name)` shape), `—` when absent. 4.1's owner cell linked to the
  owning workload's list; this spec renders it as **plain text** (the
  owning-workload views — ReplicaSet, DaemonSet, etc. — are not in scope here;
  deep-linking them is out of scope).

States: no cluster selected → `No cluster selected.`; no namespace selected →
the namespace selector / `Select a namespace` state (the namespaced-view
contract); loading → `Loading pods...`; error → red error line; empty list →
`No pods found` (first-class, not an error).

### R6 — The pod detail page (the 4.1 five-tab shape)

`/workload/pods/data?name=<name>&namespace=<ns>` MUST fetch the object with a
**single `?name=` request** (not 4.1's list-then-filter). Empty `items` is a
not-found **STATE** — pinned copy `No pod '<name>' found`, muted, not an
error. The page renders the 4.1 tabs via CoreUI `CTabs`:

- **Pod** (CTable): Namespace / Name / Status (badge) / Restarts / Created /
  Node / Owner (plain text, the `<kind>s/<name>` shape) / Priority /
  Priority Class / Runtime Class / Annotations (key/value sub-table, `No
  annotations` when empty, VERBATIM — no `trimAnnotations`) / Labels (key/value
  sub-table, `No labels` when empty). **Node** = `spec.node_name` (deep-link
  to `/cluster/node/data?name=<node>` — the landed Nodes view, cluster-scoped
  so NO namespace param; `—` when absent). **Restarts** = the sum of
  `status.container_statuses[].restart_count` (4.1 read only
  `container_statuses[0].restart_count`; 5.0 sums all containers — the
  truthful value, a ratified improvement).
- **Containers**: two CTables — **Init Containers** (State / Name / Image /
  Restarts; `No init containers` when absent) and **Containers** (State / Name
  / Image / Restarts). State is the effective container state badge (the 4.1
  mapping: `Running` green, `ImagePullBackOff`/`ErrImagePull`/`Error`/
  `CrashLoopBackOff` red, `PodInitializing` blue, `Completed`/else grey).
- **Conditions** (CTable: Condition / State): one row per
  `status.conditions[]` entry — the `type` and `status` (4.1 rendered the
  `{type: status}` dict's key/value).
- **Security Contexts** (CTable: Context / State): the
  `spec.security_context` fields rendered as key/value rows (`No security
  context` when absent) — 4.1's `security_context.items()` iteration.
- **Related Resources**: two CTables — **Refered By** (Type / Name /
  Namespace: the owner, plain text) and **Refers To** (Type / Name /
  Namespace: image-pull secrets, service account, secrets from env + volumes,
  configmaps from volumes, PVCs from volumes). **Deep-linking (ratified
  2026-10-28):** the refs that have a LANDED 5.0 destination link to it —
  **Secrets** → `/security/secret/data?name=<n>&namespace=<ns>` (the landed
  Secret view). The refs whose destination is NOT yet landed render as
  **plain text** (ConfigMap, PVC, ServiceAccount, ImagePullSecret, owner) —
  their views are their own not-yet-landed specs. This is the
  "deep-link to landed kinds" decision.

Below the tabs: the full object as a syntax-highlighted block:
`JSON.stringify(item, null, 2)` with the `json` hljs grammar (style
`anOldHope`).

Missing `name` param → `Error: pod name not provided`.

### R7 — The deployments list page

`/workload/deployments` MUST render a `KubeDataTable` of the selected
namespace's deployments with columns **Name / Status / Created**. The card
title is EXACTLY `Deployments List` (4.1's title, kept verbatim — the
e2e-smoke contract). The Name cell links to
`/workload/deployments/data?name=<name>&namespace=<ns>` — the list view is
the sole producer of those query strings.

- **Status** = `<desired>/<ready>` (4.1's format) — `status.replicas`
  (default 0) / `status.ready_replicas` (default 0).
- **Created** = `formatTimestamp` of `metadata.creation_timestamp`.

States: no cluster selected → `No cluster selected.`; no namespace selected →
the namespace selector state; loading → `Loading deployments...`; error → red
error line; empty list → `No deployments found` (first-class, not an error).

### R8 — The deployment detail page (the 4.1 six-tab shape)

`/workload/deployments/data?name=<name>&namespace=<ns>` MUST fetch the object
with a **single `?name=` request**. Empty `items` is a not-found **STATE** —
pinned copy `No deployment '<name>' found`, muted, not an error. The page
renders the 4.1 tabs via CoreUI `CTabs`:

- **Deployment** (CTable): Namespace / Name / Created / Replicas /
  Annotations (key/value sub-table, `No annotations` when empty, VERBATIM) /
  Labels (key/value sub-table, `No labels` when empty) / Selectors (key/value
  sub-table from `spec.selector.match_labels`, `No selectors` when absent).
  **Replicas** = `spec.replicas` as **plain text** (4.1's Admin-only replica
  spinner is NOT replicated — mutation is out of scope for these read-only
  views; the spinner is a write path).
- **Containers**: two CTables — **Init Containers** (Name / Image; `No init
  containers` when absent) and **Containers** (Name / Image) — from
  `spec.template.spec.containers` / `init_containers` (4.1's shape: name +
  image only, no live state — the deployment's template, not a running pod).
- **Variables** (CTable: Name / Value): the environment variables from
  `spec.template.spec.containers[].env` that have a literal `value` (4.1's
  `environment_variables` — env entries with a name + a non-null value; secret
  refs contribute to the Related Resources secrets, not here). `No variables`
  when absent.
- **Conditions** (CTable: State / Reason / Message / Time): one row per
  `status.conditions[]` entry — `type` / `reason` / `message` /
  `last_transition_time` (4.1's format).
- **Security Contexts** (CTable: Context / State): the
  `spec.template.spec.security_context` fields as key/value rows (`No
  security context` when absent).
- **Related Resources** (CTable: Type / Name / Namespace): image-pull
  secrets, service account, secrets (env + volumes), configmaps (volumes),
  PVCs (volumes) — from `spec.template.spec`. **Deep-linking (ratified
  2026-10-28):** Secrets → `/security/secret/data?name=<n>&namespace=<ns>`
  (landed); the rest (ConfigMap, PVC, ServiceAccount, ImagePullSecret) render
  as **plain text** (their views are not yet landed).

Below the tabs: the full object as a syntax-highlighted block:
`JSON.stringify(item, null, 2)` with the `json` hljs grammar (style
`anOldHope`).

Missing `name` param → `Error: deployment name not provided`.

### R9 — Routing, nav, and the orphan removal

- `App.tsx` wires both view pairs (mirroring the HPA route block — the
  namespaced pattern).
- The `/workload/pods` and `/workload/deployments` leaves ALREADY exist in the
  Workloads group in `_nav.tsx` — NO nav change. They are **promoted from
  stubs** (both are in `views/Stub/routes.ts` lines 10–11).
- The orphan `Cluster/Pods.tsx` is **DELETED** (ratified 2026-10-28 — "replace
  it in place"; nothing imports it).
- The data routes are not nav entries.

## Non-goals

- No create / edit / delete / scale for pods or deployments (read-only, as in
  every other 5.0 resource view to date; 4.1's delete action and the Admin
  replica spinner are NOT replicated — the companion `ingress-gateway-api`
  spec's Apply is the only write path, and it is out of scope here).
- **No pod exec (terminal) or pod logs** (ratified 2026-10-28 — out of scope;
  they are the ADR-0009 bidirectional-channel change, their own spec).
- No `?labelSelector=` on the pods route in THIS spec — that param is the
  not-yet-landed `service-views` spec's concern (its Service Pods tab needs it).
  This spec's pod list is the namespace's full pod set; it does NOT read or
  forward `?labelSelector=`. (The `list_pods` signature change for label
  selector lands with the service-views spec, not here.)
- No deep-linking of the owner to its workload list (the owning-workload
  views — ReplicaSet / DaemonSet / StatefulSet — are not in scope here).
- No vuln-report columns / per-container vulnerability tables (4.1's
  `has_report` block is commented out in the 4.1 template; not ported).
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title strings `Pod List` and `Deployments List` are the only
  smoke-relevant contracts.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form / POST
   / `session['ns_select']`; no list-then-filter on the data page (a single
   `?name=` request).
2. **Both data pages GAIN the full-object JSON block** (4.1's data pages had
   none — only the curated tab tables).
3. **Pod Restarts is the SUM of all container restart counts** (4.1 read only
   `container_statuses[0].restart_count` — a latent 4.1 bug for
   multi-container pods; 5.0 sums them, the truthful value).
4. **The pod Node cell deep-links to the Nodes view** (`/cluster/node`); 4.1
   used a hidden-form POST. Plain text when `spec.node_name` is absent.
5. **The Related Resources tab deep-links to LANDED kinds only** (Secrets →
   the landed Secret data view); ConfigMap / PVC / ServiceAccount /
   ImagePullSecret / owner render as **plain text** (their views are not yet
   landed — ratified 2026-10-28).
6. **The owner cell (list + data) is plain text** (the owning-workload views
   are not in scope; 4.1's owner deep-link is deferred).
7. **`trimAnnotations` is NOT replicated** — annotations render verbatim.
8. **The 4.1 "Lables" typo (pod-data + deployment-data line) is not
   replicated** — 5.0 renders `Labels`.
9. **The deployment Replicas is plain text** (4.1's Admin-only replica
   spinner is a write path, NOT replicated — mutation is out of scope).
10. **No pod exec / logs** (ratified 2026-10-28 — the ADR-0009 change).
11. **The orphan `Cluster/Pods.tsx` is deleted** (ratified 2026-10-28 — the
    namespaced `/workload/pods` view replaces it in place).
12. **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
    every pod/deployment read; 5.0's client uses the pool's configured
    timeout.
