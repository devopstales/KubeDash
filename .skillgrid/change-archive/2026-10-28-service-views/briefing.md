# Service Views (List + Data + Pods tab) — Briefing (the *what*)

> **Role:** this is the *what* — requirements & intent. The companion
> `blueprint.md` is the *how*. The filename pair is load-bearing for
> `brainstorming`/`resume`. Do not rename.

**Topic:** `2026-10-28-service-views`
**Date:** 2026-10-28
**Backlog:** TBD (created with the spec commit)
**ADR:** none — this change follows the existing locked ADR set (see `adr.md`);
no new decision, no new assumption.

## Intent

The 5.0 nav carries a `Services` leaf
(`/network/service`, `_nav.tsx:95`) that currently renders the placeholder
stub (`views/Stub/routes.ts:15`). **4.1 has real templates for this kind**:
`network/service.html.j2` (list: **Name / Type / Cluster IP / External IP**)
and `network/service-data.html.j2` (data: a **three-tab** page — Service /
Ports / Pods). Unlike the ConfigMap kind, **Service is a core API**
(`services`, core group, **namespaced**); the 4.1 read is
`k8sServiceListGet` (`4.1:src/kubedash/lib/k8s/network.py:111`):
`CoreV1Api().list_namespaced_service(ns, _request_timeout=1)` — a generated
core-API model, so the `to_dict` form is snake_case. The data page's Pods tab
is fed by a SECOND read, `k8sPodSelectorListGet`
(`4.1:src/kubedash/lib/k8s/network.py:147`):
`CoreV1Api().list_namespaced_pod(ns, label_selector=<spec.selector>)` — the
pods matching the Service's `spec.selector`, projected to
`status`/`name`/`pod_ip`/`node_name`/`owner`.

Port the 4.1 shape to 5.0 with the ratified deltas:

- **Navigation:** `?name=` + `?namespace=` query params — no 4.1 hidden forms
  / POST / `session['ns_select']` (the Namespaces/Nodes/CRDs/ResourceQuota
  decision). The namespace comes from the header's selected-namespace store.
- **Detail rendering:** the data page keeps 4.1's three-tab structure
  (Service / Ports / Pods) — implemented as stacked sections with a CoreUI
  tab switcher (the `CTabs`/`CTab` pattern, not 4.1's Bootstrap JS tabs) —
  and ADDS the full-object `JSON.stringify(item, null, 2)` block with the
  `json` hljs grammar to the Service tab (the truthful-classifier rule
  ratified for PriorityClassData, final review 2026-10-28).
- **Pods tab (ratified 2026-10-28):** the list's `?name=&namespace=` fetch
  returns the Service (with `spec.selector`); the Pods tab fires a SECOND
  parallel fetch on the existing pods route with a **new optional
  `?labelSelector=` param** (server-side filter, 4.1's real behavior) — the
  pods matching the selector, projected to Status/Name/IP/Node/Owner. A
  Service with no `spec.selector` (e.g. an ExternalName or headless Service
  with an empty selector) renders the Pods tab as an empty state (`No pods
  match this service's selector`), NOT an error.
- **Gating:** SAR per ADR-0004 on the existing generic `/resources` route —
  `list`/`get` on `services`, core group (`""`), namespace from the query
  (or `None` for the all-namespaces read); the Pods tab's pods read is
  SAR-gated on `list pods` (the same gate the existing pods route uses).
- **Rendering stack:** CoreUI + `KubeDataTable` + TanStack Query + MSW (the
  5.0 view stack), 4.1's DataTables-JS + Jinja + Bootstrap-JS tabs dropped.

Deliver: a real list page and a real three-tab detail page at
`/network/service` and `/network/service/data`, plus the `?labelSelector=`
param on the pods route, removing the stub, so the nav leaf resolves to
first-class views.

## Requirements

### R1 — A SAR-gated Service list endpoint

`GET /api/v1/clusters/<id>/resources/services?namespace=<ns>` MUST return the
Service list for that namespace (`kind: "services"`, items in kubernetes
`to_dict` snake_case form, `metadata`/`spec`/`status` intact). With a
`namespace` param the read is `list_namespaced_service`; without one the list
spans all namespaces (`list_service_for_all_namespaces` — the `list_secrets`
branch). **No field stripping**: a Service's `spec` (type, cluster_ip,
ports, selector) and `status` (load_balancer) are public, so the full
`to_dict` goes to the view. The read is SAR-gated per ADR-0004: `list` on
`services`, core group (`""`), namespace = the query namespace or `None`; on
deny the response is 403 `RBAC_DENIED` naming the resource, and the SAR is
asked BEFORE any K8s client call. An unbound user is 404 from the binding
gate. The kind identifier is the plural `services`; the singular `service`
is rejected with `RESOURCE_KIND_NOT_SUPPORTED`.

### R2 — A `?name=&namespace=` lookup via the existing generic route

`GET /api/v1/clusters/<id>/resources/services?name=<name>&namespace=<ns>`
MUST return a 0/1-item list through the same generic route (`_GETTERS`): a
hit is the single object, a miss is `[]` (not a 404 — the data page renders
a not-found state). SAR-gated on `get` with the same namespace semantics. The
namespace param is REQUIRED for the lookup: without it the route falls back
to `namespace = "default"` (the generic route's existing `name` branch
behavior) — the data page ALWAYS sends the namespace it was linked with. No
new HTTP route is added: the kind is wired through `_KINDS` + `_GETTERS`
only.

### R3 — A `?labelSelector=` param on the existing pods route

`GET /api/v1/clusters/<id>/resources/pods?namespace=<ns>&labelSelector=<expr>`
MUST apply an OPTIONAL server-side label filter to the existing pods list:
when `labelSelector` is present, the read is
`list_namespaced_pod(namespace, label_selector=<expr>)` (the kubernetes
client's `label_selector` kwarg — a comma-separated `key=value` equality
expression, the same format 4.1's `k8sPodSelectorListGet` builds from a
selector dict); when absent, the existing behavior is UNCHANGED (all pods in
the namespace, or all namespaces). The `labelSelector` param is a plain
string passed through to the client — the route does NOT parse or validate
it (the kubernetes API server is the authority on selector syntax; a
malformed selector is a 400 from the API, which the existing
`ClusterUnreachableError` mapping turns into a 502). The param is namespaced-
only: it applies to the `namespace` branch, NOT the all-namespaces branch
(a `labelSelector` without a `namespace` is ignored — the Pods tab always
sends both). SAR is UNCHANGED: `list` on `pods`, core group, the query
namespace (or `None`). No new kind, no new `_KINDS` row — this is a param
addition to the existing `pods` route's `list_pods` method.

### R4 — The list page

`/network/service` MUST render a `KubeDataTable` in the header-selected
namespace (`useClusterStore.selectedNamespace ?? 'default'`) with columns
**Name / Type / Cluster IP / External IP**. The card title is EXACTLY
`Service List` (4.1's title, kept verbatim — the e2e-smoke contract). The
Name cell links to
`/network/service/data?name=<name>&namespace=<ns>` — the list view is the
sole producer of those query strings.

- **Type** = `spec.type` (`—` when absent).
- **Cluster IP** = `spec.cluster_ip` (`—` when absent — a `None`-type or
  headless Service may have no cluster IP; 4.1 rendered the raw value which
  was empty).
- **External IP** = `status.load_balancer.ingress[0].ip` for a
  `spec.type == "LoadBalancer"` Service (`—` when the type is not
  LoadBalancer, when `load_balancer.ingress` is absent or empty, or when
  `ip` is absent — 4.1's `service.status.load_balancer.ingress[0].ip`
  deep-index 500s on a LoadBalancer with no ingress yet; 5.0 renders `—`).

States: no cluster selected → `No cluster selected.`; loading → `Loading
services...`; error → red error line; empty list → `No services found`
(first-class, not an error).

### R5 — The detail page (three tabs)

`/network/service/data?name=<name>&namespace=<ns>` MUST fetch the Service
with a **single `?name=&namespace=` request** (not 4.1's list-then-filter).
Empty `items` is a not-found **STATE** — pinned copy `No Service '<name>'
found`, muted, not an error. The page renders three tabs (a CoreUI
`CTabs`/`CTab` switcher — the 4.1 Bootstrap-JS tabs re-implemented as React
tabs):

- **Service tab** (default active): a CTable (Name / Type / Created /
  Annotations / Labels / Cluster IP / External IP) — the 4.1 Service tab's
  row set — PLUS the full-object `JSON.stringify(item, null, 2)` block with
  the `json` hljs grammar (style `anOldHope`).
  - **Type** = `spec.type` (`—` when absent).
  - **Annotations** = key/value sub-table (`No annotations` when empty),
    rendered VERBATIM (no `trimAnnotations` — the 4.1 data template's
    inline `last-applied-configuration` filter is NOT replicated; the JSON
    block has the full object).
  - **Labels** = key/value sub-table (`No labels` when empty).
  - **Cluster IP** = `spec.cluster_ip` (`—` when absent).
  - **External IP** = the R4 External IP expression (`—` when not a
    LoadBalancer or no ingress).
  - **Created** = `formatTimestamp` of `metadata.creation_timestamp`.
- **Ports tab**: a CTable (Name / Port / Protocol / Target / Node Port) —
  one row per `spec.ports` entry, `No ports` when `spec.ports` is absent or
  empty.
  - **Name** = `port.name` (`—` when absent).
  - **Port** = `port.port` (the service port, an integer).
  - **Protocol** = `port.protocol` (`—` when absent; k8s defaults to TCP but
    4.1 rendered the raw value, so 5.0 does too — `—` only when the field is
    genuinely absent from the `to_dict`).
  - **Target** = `port.target_port` (`—` when absent — it may be a name or a
    number, 4.1 rendered it raw).
  - **Node Port** = `port.node_port` (`—` when absent — only present on
    NodePort/LoadBalancer types).
- **Pods tab**: a CTable (Status / Name / IP / Node / Owner) — the pods
  matching the Service's `spec.selector`, fetched via the R3
  `?labelSelector=` param.
  - The labelSelector string is built from `spec.selector` as a
    comma-separated `key=value` expression (4.1's `k8sPodSelectorListGet`
    format) — sent ONLY when `spec.selector` is non-empty.
  - **Status** = `status.phase` rendered as a badge (4.1's four-tier badge
    pair — `Running` → success, `Pending` → warning, `Succeeded` →
    secondary, else → info; `—` when absent).
  - **Name** = `metadata.name` (plain text — the 4.1 pod-data link is NOT
    replicated; 5.0 has no `/workload/pod/data` destination yet).
  - **IP** = `status.pod_ip` (`—` when absent).
  - **Node** = `spec.node_name` (`—` when absent — a not-yet-scheduled pod
    has no node).
  - **Owner** = the first `metadata.owner_references` entry, rendered
    `kind.name` lowercase (4.1's `"%ss/%s" % (owner.kind.lower(),
    owner.name)` — the `/` is NOT in 4.1's format string, it's a typo; 5.0
    renders `kind.name` with a slash: `kind.lower() + "/" + name`, the
    conventional form) (`—` when there are no owner references).
  - **Empty state**: when `spec.selector` is absent or empty (no pods can
    match), OR the pods fetch returns `items: []`, the Pods tab renders
    `No pods match this service's selector` (muted, first-class — NOT an
    error, NOT a fetch at all when the selector is empty).

Missing `name` param → `Error: service name not provided`. Missing
`namespace` param → the page falls back to the header-selected namespace
(it only renders when a cluster is selected, so the store value is always
available); it still sends the resolved namespace in the request.

### R6 — Routing and stub removal

`App.tsx` wires both views (mirroring the secret route block).
`/network/service` is removed from `views/Stub/routes.ts`. The `_nav.tsx`
leaf is UNCHANGED (path and label). The data route is not a nav entry (same
as secret/data, network-policy/data).

## Non-goals

- No create/edit/delete for Services (read-only, as in 4.1 and as in every
  other 5.0 resource view to date).
- No `sessionAffinity` / `externalTrafficPolicy` / `loadBalancerIPs`
  first-class display — 4.1's data page did not surface them; the raw object
  is in the JSON block.
- No pod → pod-data deep-link in the Pods tab — 4.1 linked each pod's name
  to `/workload/pod/data` via a hidden form; 5.0 has no pod-data page
  destination yet (the `Pods` view is an embedded dashboard table, not a
  routed data page), so pod names render as plain text.
- No node → node-data deep-link in the Pods tab — 4.1 linked each pod's node
  to `/cluster/node/data`; 5.0 HAS that route (`/cluster/node/data?name=
  <node>`), but the link is a non-goal for this change (the Pods tab is a
  read-only projection; the node link is a candidate for a follow-up).
- No Ingresses tab — 4.1's data page had an Ingresses tab that was
  **commented out** (lines 36-40); it never rendered, so 5.0 does not add
  it.
- No all-namespaces LIST mode on the page: the page always shows the
  header-selected namespace; the all-namespaces list branch exists for the
  API (R1) and future consumers only.
- No e2e smoke addition beyond the existing UI smoke conventions; the card
  title string `Service List` is the only smoke-relevant contract.

## Ratified deviations from 4.1 (recorded; see `adr.md` → Deviations)

1. `?name=` + `?namespace=` query-param navigation; no 4.1 hidden form /
   POST / `session['ns_select']`; no list-then-filter on the data page.
2. The three-tab data page is re-implemented as CoreUI `CTabs`/`CTab`
   (React tabs), NOT 4.1's Bootstrap-JS `data-bs-toggle="tab"` tabs.
3. The Service tab GAINS the full-object `JSON.stringify` block (4.1's data
   page had no full-object block — only the metadata table + the ports/pods
   tabs); the `json` hljs grammar is the truthful classifier (ratified
   2026-10-28).
4. **The Pods tab's pods read uses the existing pods route with a new
   `?labelSelector=` param** (ratified 2026-10-28), NOT a new
   `k8sPodSelectorListGet`-style endpoint. 4.1's read projected the pods to
   `status`/`name`/`pod_ip`/`node_name`/`owner`; 5.0's read is the full
   `to_dict` pod (the existing `list_pods` shape) and the VIEW projects it
   to the same five columns (the backend does no projection — the view uses
   optional-chaining reads, the certainty rule).
5. **The `labelSelector` is a plain string pass-through** — the route does
   NOT parse or validate it (the kubernetes API server is the authority on
   selector syntax). 4.1 built the selector string in Python
   (`f"{key}={value},"`); 5.0 builds it in the view (the view has the
   `spec.selector` dict, the route just forwards the string).
6. **The External IP deep-index 500 is fixed.** 4.1's
   `service.status.load_balancer.ingress[0].ip` raises `IndexError`/
   `AttributeError` (→ 500) on a LoadBalancer with no `ingress` yet (the
   common "pending" state); 5.0 renders `—` for absent `ingress`/`ip`
   (certainty rule: never crash the row).
7. **The pod `owner` format is fixed.** 4.1's
   `"%ss/%s" % (owner.kind.lower(), owner.name)` produces
   `deploymentss/web-abc` (a stray `s` — a 4.1 typo); 5.0 renders
   `deployment/web-abc` (the conventional `kind.name` form).
8. **`trimAnnotations` is NOT replicated** — annotations render verbatim
   (the 4.1 data template's inline `last-applied-configuration` filter and
   the list read's `trimAnnotations` are both dropped; the JSON block has
   the full object, and 5.0 has no trim helper).
9. **The pod and node cells are plain text, not 4.1's hidden-form links.**
   4.1's Pods tab linked pod names to `/workload/pod/data` and node names to
   `/cluster/node/data` via hidden forms; 5.0 has no pod-data destination
   (the `Pods` view is an embedded table, not a routed data page) and the
   node link is a non-goal for this change, so both render as plain text.
10. **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout
    to `list_namespaced_service` and `list_namespaced_pod`; 5.0's client
    uses the pool's configured timeout (a 1 s list read on a large namespace
    is a spurious-failure source, and the 5.0 client's contract is the pool
    timeout, not a per-call override).
