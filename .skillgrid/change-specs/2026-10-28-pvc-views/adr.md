# PVC Views — ADR Review Manifest

> In-force set from the `## LOCKED` index in `.skillgrid/ASSUMPTIONS.md`. ADR
> bodies 0001–0013 have index entries but no bodies on disk (per AGENTS.md);
> the index is the fallback authority.

## In-force ADRs this change follows

| ADR | How this change follows it |
|-----|---------------------------|
| ADR-0003 (observability query-only) | The new `metrics/pvcs` route is a query-only observed tier: unavailable kubelet stats (404/5xx/timeout per node) degrade to 200 `metrics_available: false` + empty `items`, never 500; the SAR deny on the stats tier degrades to `metrics_denied: true`, never 403 — the two-tier pattern already in `backend/app/api/metrics.py`'s summary/node_metrics routes, applied to the kubelet stats source. |
| ADR-0004 (RBAC via SAR) | The new kind is SAR-gated like every other resource: `list`/`get` on `persistentvolumeclaims`, core group (`""`), namespace = the query namespace or `None` (all-namespaces branch); the SAR is asked BEFORE the client call; 403 names the denied resource. The usage route is gated on `get nodes` (the stats proxy goes through the node API), asked before any stats call. No change to the `can()` mechanism. |
| ADR-0009/0010 (read path) | Reads go through the client pool on request (the `_KINDS` table pattern) — same as secrets/resourcequotas/networkpolicies for a namespaced core kind; no informer-cache change. |
| ADR-0020 (air gap) | No new dependency: the kubernetes Python client already ships `CoreV1Api` as the existing `self._v1` attribute (NO new `__init__` attribute needed); `json` is stdlib (4.1's `eval` is replaced); the frontend reuses `KubeDataTable`, CoreUI, and the already-vendored `react-syntax-highlighter` (`json` grammar already registered by the resourcequota data view). |
| ADR-0022 (other-resources placement) | The view lives under Storage (the 4.1 `storage` blueprint grouping) — the ratified nav-placement deviation. The nav leaf already exists at this path, and 4.1's own templates lived in `storage/`. |
| ADR-0021 (local admin auth) | Unchanged — the binding gate (`_cluster_for`) and the auth hook apply to the new kind and route via the existing generic route / metrics blueprint. |

## Decision created by this change

None. No new ADR: the change consumes locked decisions (query-only
observability, SAR gating, placement, air-gap, read path) and follows an
established, ratified in-repo pattern (the namespaced core-kind family —
secrets/resourcequotas/networkpolicies — same `_KINDS` + `_GETTERS` wiring,
same list+data view pair; the usage route mirrors the existing two-tier
metrics routes). The ONE fork — porting 4.1's Usage column as a second
REST fetch rather than a server-side join — was ratified with the user on
2026-10-28 (briefing R3).

## Recorded deviations from 4.1

- **`?name=` + `?namespace=` navigation, not 4.1's hidden form +
  `session['ns_select']`.** 4.1's list page POSTed a hidden form per row
  (`selected`) and the data page re-listed the whole namespace then filtered
  in Python (`for pvc in pvc_list: if pvc["name"] == selected`). 5.0 reaches
  the data page by query param and does a single `?name=&namespace=` read.
- **Usage is a second REST fetch, not a server-side join.** 4.1's `pvc()`
  route called `k8sPVCMetric(session['ns_select'])` and joined in the
  template (`{% if metric.name == pvc.name %}`). 5.0 exposes the usage as
  `GET /metrics/pvcs?namespace=<ns>` (the ADR-0003 two-tier pattern): the
  list page fires a second parallel query and joins client-side by PVC name;
  the list renders even when kubelet stats are absent, and the SAR deny on
  the stats tier degrades the column to `—` instead of a 500.
- **The usage read is SAR-gated on the ACTING user, not the `Admin` token.**
  4.1's `k8sPVCMetric` re-fetched the `Admin` kubeconfig
  (`k8sClientConfigGet('Admin', None)`) — the usage was ALWAYS readable
  regardless of the logged-in user's grants. 5.0 asks the acting user's
  `get nodes` grant and reports `metrics_denied: true` (200, empty items)
  on deny — the metrics.k8s.io two-tier rule applied to the kubelet stats
  source.
- **`eval` is replaced with `json.loads`.** 4.1 `eval(data)`d the kubelet
  stats body (Python-literal eval on a wire string, `_request_timeout=1`);
  5.0 `json.loads` the body (the kubelet Summary API is JSON), keeps a
  per-node timeout, and skips (not raises on) a failing node.
- **The division-by-zero in 4.1's `percentageUsed` is guarded.** 4.1 computed
  `usedBytes / capacityBytes * 100` with no zero guard (kubelet capacity is
  never zero in practice, so it never fired); 5.0 reports `0.0` when
  `capacity_bytes` is zero.
- **Full-object block is JSON, highlighted as `json`.** The 5.0 data page
  renders `JSON.stringify` of the `to_dict` item — JSON is a YAML subset,
  and the `json` grammar is the truthful classifier for the exact text
  rendered (ratified rule, PriorityClassData final review 2026-10-28).
- **The data page's "Lables" typo is not replicated** — 5.0 renders
  `Labels`.
- **The StorageClass / Volume cells are plain text, not 4.1's hidden-form
  links.** 4.1's list linked those cells to `/storage/storage-class` and
  `/storage/pv` via hidden forms; 5.0 has no PV page destination and the
  StorageClass page lands separately in this batch, so both cells render as
  plain text — the full `spec` is in the JSON block.
- **`trimAnnotations` is not replicated.** 4.1 dropped
  `kubectl.kubernetes.io/last-applied-configuration` from the annotations
  table; 5.0 renders annotations verbatim (the kubectl noise is in the JSON
  block either way, and 5.0 has no trim helper).
  **OVERRIDE 2026-11-05 (user decision):** the trim is now replicated — the
  two machine-managed keys are dropped from the annotations table (the
  2026-11-04 HPA override shape, 46929a10; 2026-11-05-pv-views companion
  fix).

## Navigation Superseded (2026-10-29)

The query-param navigation clause in this ADR (Deviations; Decision Context) is **SUPERSEDED (2026-10-29)** by `2026-10-29-session-object-navigation` (ADR-0040, proposed): object identity lives in tab-private `sessionStorage`; list rows open the detail via `setObjectRef(...)` or a same-origin form POST; no `/data` route suffix; no object identity in the URL. See `NAVIGATION-SUPERSEDED.md` in this folder. The backend REST `?name=`/`?namespace=` filtering params are unchanged.
