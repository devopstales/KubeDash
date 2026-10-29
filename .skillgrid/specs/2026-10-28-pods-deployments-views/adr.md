# Pods + Deployments Views — ADR

## Decision Summary

Port 4.1's Pods views (`/workload/pods`) and Deployments views
(`/workload/deployments`) as two SAR-gated, read-only, **namespaced** list +
data pairs on the existing generic resource route. **Pods** is a namespaced
core kind (`pods`, group `""`) — the `_KINDS` row ALREADY exists
(`list_pods`); this change adds the MISSING `_GETTERS["pods"] = "get_pod"`
row + a new `K8sClient.get_pod(namespace, name)` method
(`read_namespaced_pod`, `[]` on 404). **Deployments** is a namespaced core
kind (`deployments`, group `apps`) — this change ADDS the
`_KINDS["deployments"]` row + a new `K8sClient.list_deployments(namespace)` /
`get_deployment(namespace, name)` method + ONE new `__init__` attribute
(`self._apps = AppsV1Api`, if absent). Both data pages follow the ratified 5.0
shape: 4.1's curated multi-tab tables (pods: 5 tabs; deployments: 6 tabs) +
the full-object `JSON.stringify(item, null, 2)` block with the `json` hljs
grammar (the truthful-classifier rule ratified for PriorityClassData, final
review 2026-10-28). The orphaned all-namespaces `Cluster/Pods.tsx` is
**DELETED** (ratified 2026-10-28 — "replace it in place"; nothing imports
it). The Related Resources tab **deep-links to LANDED kinds only** (Secrets →
the landed Secret data view; ConfigMap / PVC / ServiceAccount /
ImagePullSecret / owner → plain text — their views are not yet landed).

## Decision Context

- **Two namespaced core kinds, one generic route.** Both pods and deployments
  are namespaced — the `?namespace=` query param drives the read (the header's
  selected-namespace store is the source, as in the NetworkPolicies /
  ResourceQuota / HPA views), and `?name=` drives the data page. The existing
  generic resource route already serves list AND `?name=` for a kind via
  `_KINDS`/`_GETTERS`; this change adds the missing pieces (pods: the
  `_GETTERS` row + `get_pod`; deployments: the `_KINDS` row + the `_GETTERS`
  row + the two service methods + `self._apps`).
- **Pods is partially wired already.** The `_KINDS["pods"]` row exists
  (`list_pods`, used by the cluster-detail context); what's missing for the
  data page is the `?name=` getter. This change does NOT add a new `pods`
  `_KINDS` row (it would be a duplicate) and does NOT change `list_pods`'s
  signature (the `?labelSelector=` param is the not-yet-landed service-views
  spec's concern).
- **The orphan replacement.** 5.0 has an unused all-namespaces
  `Cluster/Pods.tsx` (nothing imports it — `Cluster/index.tsx` says "Pods
  belong to Interface → Workloads → Pods, not this status page"). The 4.1
  `/workload/pods` view is the namespaced, first-class pod view; the orphan is
  a redundant all-namespaces CTable. Ratified 2026-10-28: delete the orphan,
  build the namespaced view in its place. The deletion is atomic with the
  pods views (same commit).
- **The multi-tab data pages.** 4.1's pod data page is a 5-tab page (Pod /
  Containers / Conditions / Security Contexts / Related Resources); the
  deployment data page is a 6-tab page (Deployment / Containers / Variables /
  Conditions / Security Contexts / Related Resources). 5.0 renders these via
  CoreUI `CTabs` (the pattern already used by the Service view's three-tab
  data page) and ADDS the full-object JSON block to each (the truthful
  classifier rule).
- **Deep-linking to LANDED kinds only.** The Related Resources tab references
  kinds that have 5.0 views and kinds that don't. Ratified 2026-10-28: link
  ONLY to the landed destinations — Secrets (`/security/secret/data`) and
  Node (`/cluster/node/data`, cluster-scoped, from the Pod tab). The rest
  (ConfigMap, PVC, ServiceAccount, ImagePullSecret, the pod owner) render as
  plain text; their views are their own not-yet-landed specs. Deep-linking to
  a non-landed kind would 404.
- **`trimAnnotations` not replicated; the "Lables" typo not replicated.** The
  4.1 data templates' inline last-applied-configuration filter and the
  "Lables" typo (pod-data + deployment-data) are 4.1 artifacts; 5.0 renders
  annotations verbatim and the label row as "Labels".
- **Pod Restarts is the sum of all container restart counts.** 4.1 read only
  `container_statuses[0].restart_count` — a latent bug for multi-container
  pods. 5.0 sums `container_statuses[].restart_count` (the truthful value, a
  ratified improvement).
- **The deployment Replicas is plain text.** 4.1's Admin-only replica spinner
  is a WRITE path (a patch); these views are read-only, so the spinner is not
  replicated — Replicas renders as plain text.
- **No pod exec / logs (ratified 2026-10-28).** The 4.1 exec (terminal) and
  logs buttons are the ADR-0009 bidirectional-channel change, their own spec —
  out of scope here.
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  every pod/deployment read; 5.0's client uses the pool's configured timeout
  (the house rule ratified across the 4.1→5.0 ports).

## ADR Manifest

| ADR | Relevance to this change |
|---|---|
| 0004 | Per-object SAR (`list` / `get` on the kind, the namespace) gates both the pods read (group `""`) and the deployments read (group `apps`); deny → 403 `RBAC_DENIED`, the SAR before the K8s call, the client call never made on deny. |
| 0009 | SSE is the push channel — not used by these read-only views (the list/data fetches are TanStack Query polls). The pod exec/logs (the bidirectional channel) are OUT OF SCOPE (ratified 2026-10-28). |
| 0010 | Read path — the list/data fetches are per-request REST (these are the resource views; the informer-cache read path applies to the watch-driven surfaces, not this generic route). |
| 0020 | Air-gap — no new npm/Python dependency; the views reuse `KubeDataTable` + `CTabs` + CoreUI + `react-syntax-highlighter` (the `json` grammar already registered). |
| 0021 | The cluster binding gate (404 unbound) and the local-admin/cluster model the SAR reads assume. |
| 0022 | The Workloads group nav shape the two leaves already occupy (4.1 parity structure; the leaves are promoted from stubs, NOT added — no nav change). |

## Deviations (from 4.1)

1. **`?name=` + `?namespace=` query-param navigation**; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page (a
   single `?name=` request).
2. **Both data pages GAIN the full-object JSON block** (4.1's data pages had
   only the curated tab tables).
3. **Pod Restarts is the SUM of all container restart counts** (4.1 read only
   `container_statuses[0].restart_count` — a latent multi-container bug; 5.0
   sums them).
4. **The pod Node cell deep-links to the Nodes view** (`/cluster/node/data?name=
   <node>`, cluster-scoped); 4.1 used a hidden-form POST. Plain text when
   `spec.node_name` is absent.
5. **The Related Resources tab deep-links to LANDED kinds only** (Secrets →
   the landed Secret data view; Node → the landed Nodes data view); ConfigMap
   / PVC / ServiceAccount / ImagePullSecret / owner render as **plain text**
   (their views are not yet landed — ratified 2026-10-28).
6. **The owner cell (list + data) is plain text** (the owning-workload views
   are not in scope; 4.1's owner deep-link is deferred).
7. **`trimAnnotations` is NOT replicated** — annotations render verbatim.
8. **The 4.1 "Lables" typo (pod-data + deployment-data) is not replicated** —
   5.0 renders "Labels".
9. **The deployment Replicas is plain text** (4.1's Admin-only replica
   spinner is a write path, NOT replicated — mutation is out of scope).
10. **No pod exec / logs** (ratified 2026-10-28 — the ADR-0009 change).
11. **The orphan `Cluster/Pods.tsx` is deleted** (ratified 2026-10-28 — the
    namespaced `/workload/pods` view replaces it in place).
12. **No per-request `_request_timeout=1`.** 5.0's client uses the pool's
    configured timeout.

## Out of Scope

- Create / edit / delete / scale for pods or deployments (read-only; 4.1's
  delete action and the Admin replica spinner are NOT replicated).
- **Pod exec (terminal) and pod logs** (the ADR-0009 bidirectional-channel
  change, its own spec).
- `?labelSelector=` on the pods route (the not-yet-landed service-views
  spec's concern — its Service Pods tab needs it; this spec's pod list is the
  namespace's full set).
- Deep-linking of the owner to its workload list (the owning-workload views —
  ReplicaSet / DaemonSet / StatefulSet — are not in scope).
- The vuln-report columns / per-container vulnerability tables (4.1's
  `has_report` block is commented out in the 4.1 template; not ported).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
