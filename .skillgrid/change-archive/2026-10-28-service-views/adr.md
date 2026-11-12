# Service Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `services`, core group (`""`), namespace = the query namespace or `None` (all-namespaces branch); the SAR is asked BEFORE the client call; 403 names the denied resource. The Pods tab's pods read is SAR-gated on `list pods` (the same gate the existing pods route uses) — the `?labelSelector=` param does NOT change the gate. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/resourcequotas/networkpolicies for a namespaced core kind; the Pods tab's pods read goes through the existing `list_pods` pool method (now with the optional `label_selector` param); no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CoreV1Api` as the existing `self._v1` attribute (NO new `__init__` attribute needed); the frontend reuses `KubeDataTable`, CoreUI (`CTabs`/`CTab`/`CTabContent` already in the vendored `@coreui/react`), and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by `SecretData.tsx`). |
| ADR-0022 (other-resources placement) | The view lives under Network (the 4.1 `network` blueprint grouping) — the ratified nav-placement deviation. The nav leaf already exists at this path, and 4.1's own templates lived in `network/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind via the existing generic route. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (SAR gating,
placement, air-gap, read path) and follows an established, ratified in-repo
pattern (the namespaced core-kind family — secrets/resourcequotas/
networkpolicies — same `_KINDS` + `_GETTERS` wiring, same list+data view
pair). The ONE fork — the Pods tab's pods read via a `?labelSelector=` param
on the existing pods route rather than a new selector endpoint — was
ratified with the user on 2026-10-28 (briefing R3): the param is a plain
string pass-through to `list_namespaced_pod`'s `label_selector` kwarg
(4.1's `k8sPodSelectorListGet` behavior, re-implemented as a param), keeping
the pods route's existing SAR gate and avoiding a new endpoint.

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row
  (`service_name`) and the data page re-listed the whole namespace then
  filtered in Python (`for service in services: if service["name"] ==
  service_name`). 5.0 reaches the data page by query param and does a single
  `?name=&namespace=` read.
- **The three-tab data page is CoreUI `CTabs`, NOT Bootstrap-JS tabs.** 4.1's
  data page used `data-bs-toggle="tab"` Bootstrap-JS tabs; 5.0 re-implements
  the same three-tab structure (Service / Ports / Pods) as a CoreUI
  `CTabs`/`CTab`/`CTabContent` React switcher (the 5.0 view stack — no
  Bootstrap-JS dependency).
- **The Service tab GAINS the full-object `JSON.stringify` block.** 4.1's
  data page had NO full-object block (only the metadata table + the
  ports/pods tabs); 5.0 adds it with the `json` hljs grammar (the
  truthful-classifier rule, ratified PriorityClassData final review
  2026-10-28).
- **The Pods tab's pods read uses the existing pods route with a new
  `?labelSelector=` param, NOT a new endpoint.** 4.1's
  `k8sPodSelectorListGet` was a separate function that called
  `list_namespaced_pod(ns, label_selector=...)`; 5.0 adds the optional
  `label_selector` param to the existing `list_pods` method and the
  `?labelSelector=` query param to the existing pods route — the same SAR
  gate (`list pods`), no new endpoint, no new `_KINDS` row. The param is a
  PLAIN STRING pass-through (the route does NOT parse or validate it — the
  kubernetes API server is the authority on selector syntax).
- **The view builds the selector string, the route forwards it.** 4.1 built
  the `key=value,` string in Python (in `k8sPodSelectorListGet`); 5.0's view
  builds it from `spec.selector` (the view has the dict) and the route just
  forwards the string (the backend does no projection or parsing).
- **The External IP deep-index 500 is fixed.** 4.1's
  `service.status.load_balancer.ingress[0].ip` raises `IndexError`/
  `AttributeError` (→ 500) on a LoadBalancer with no `ingress` yet (the
  common "pending" state); 5.0 renders `—` for absent `ingress`/`ip`
  (certainty rule: never crash the row).
- **The pod `owner` format is fixed.** 4.1's
  `"%ss/%s" % (owner.kind.lower(), owner.name)` produces
  `deploymentss/web-abc` (a stray `s` — a 4.1 typo); 5.0 renders
  `deployment/web-abc` (the conventional `kind.name` form).
- **`trimAnnotations` is NOT replicated.** 4.1's list read used
  `trimAnnotations` and the data template had an inline
  `last-applied-configuration` filter; 5.0 renders annotations verbatim
  (the kubectl noise is in the JSON block either way, and 5.0 has no trim
  helper).
- **The pod and node cells are plain text, not 4.1's hidden-form links.**
  4.1's Pods tab linked pod names to `/workload/pod/data` and node names to
  `/cluster/node/data` via hidden forms; 5.0 has no pod-data destination
  (the `Pods` view is an embedded dashboard table, not a routed data page)
  and the node link is a non-goal for this change, so both render as plain
  text.
- **The Ingresses tab is not added.** 4.1's data page had an Ingresses tab
  that was COMMENTED OUT (lines 36-40) — it never rendered, so 5.0 does not
  add it.
- **No per-request `_request_timeout=1`.** 4.1 passed a 1-second timeout to
  `list_namespaced_service` and `list_namespaced_pod`; 5.0's client uses the
  pool's configured timeout (a 1 s list read on a large namespace is a
  spurious-failure source, and the 5.0 client's contract is the pool
  timeout, not a per-call override).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
