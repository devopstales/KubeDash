# Cluster Dashboard — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files to touch, code,
> tests, and verification. The product *why* lives in `briefing.md` + the prototype
> `../../prototypes/002-cluster-dashboard/dashboard-c-41-donut.html`. This blueprint is
> pure-technical and cites them rather than restating.

**Status:** PROPOSED

**Tier:** T2

**Build shape:** Tracer thread (the allocation rollup → endpoint → view is a thin end-to-end path;
the charts + events thicken it. Integration risk with the K8s API + Metrics API is the unknown, so
connect it first.)

**Goal:** Build the Option C cluster dashboard — two rows (CPU/Memory/Pods concentric donuts with an
overcommit signal, then a live events table) — backed by a new cluster-allocation rollup, a metrics
query, and an events source, all query-only through the existing K8s seam.

**Architecture:** Backend adds a **cluster allocation rollup** (sum node capacity + pod
requests/limits + Metrics API usage, query-only ADR-0003) exposed as `GET /clusters/<id>/metrics/summary`,
plus an **events** read through `K8sClient.list_events` (the same pool seam as `list_pods`; ADR-0010's
informer cache interposes here *later* — it is not built yet). Frontend adds a `Cluster/Dashboard`
view: `@coreui/react-chartjs` concentric donuts (3 datasets/rings, dark tones, center % plugin), a
red overflow bar per resource, and a `KubeDataTable` events table — both theme-aware.

**Tech Stack:** Flask 3 + Smorest (backend); `kubernetes` python client (v1 Core + Metrics API);
marshmallow; React 18 + CoreUI + TanStack Query + `KubeDataTable` + **`@coreui/react-chartjs`**
(Chart.js, already vendored — no new dependency).

**Spec:** `briefing.md` (requirements R1–R5).
**Findings:** `findings.md` (prototype 002 verdicts + constraints + the 3-dataset doughnut gotcha).
**Visual reference:** `../../prototypes/002-cluster-dashboard/dashboard-c-41-donut.html`.

**In-force ADRs:** ADR-0003 (query-only observability), ADR-0004 (SAR cache key carries every
attribute — a derived rollup must be gated on the right verb/resource), ADR-0005 (CoreUI),
ADR-0010 (informer cache read path), ADR-0020 (air gap), ADR-0023 (DataTables).

**Critic:** T2 → dispatch a critic subagent before the user-decide loop (recorded outcome in header
after the loop).

**Decision note (metrics source):** the metrics *usage* source is the **Kubernetes Metrics API**
(`metrics.k8s.io/v1beta1`), query-only — ratified in `../2026-10-21-cluster-node/adr.md` for the
sibling node change. This change reuses that decision (no new ADR). Declared **requests/limits** come
from pod specs (not the metrics API).

**Critic:** T2 critic subagent ran (2026-10-22). Verdict: NEEDS FIXES → all accepted findings applied
to this blueprint (informer-cache citation removed; events read path specified as `list_events`;
metrics RBAC gate added; overcommit-gate semantics stated; `MetricsV1beta1Api` import check +
`call_api` fallback added; baseline refresh + centerText-as-closure + `used=null` bar rule + shared
404 handler added). Critic issue #5 (camelCase wire format) was **rejected** — verified the OpenAPI
contract is snake_case (`total_pages`, `display_name`, `api_server`), so the blueprint's snake_case
schemas/types are correct.

## Terms

Pointers only (canonical in `.skillgrid/artifacts/01-business-terms.md` / `02-technical-terms.md`):
- **Api**, **View**, **Informer cache**, **SSE stream** — see `02-technical-terms.md` (unchanged).
- **Allocation rollup** (new, this change): the cluster-wide aggregate of node capacity, summed pod
  requests/limits, and Metrics API usage, computed query-only. It is the data source for the
  dashboard's overcommit signal.
- **Overcommit** (new, this change): Σ declared requests ÷ capacity. Above 100% = overbooked.
  Distinct from limits-over-capacity (burst headroom).

## Must-Haves (goal-backward verification)

**Truths:**
- `GET /api/v1/clusters/<id>/metrics/summary` returns `{cluster, metrics_available, cpu:{capacity_millicores, used_millicores, requests_millicores, limits_millicores}, memory:{capacity_bytes, used_bytes, requests_bytes, limits_bytes}, pods:{capacity, running, pending, completed}}`. *backstop* (needs live cluster).
- `used` comes from the Metrics API; **when the Metrics API 404s/5xxes, `metrics_available` is `false` and `used` fields are `null`** — the endpoint does **not** 500 and does **not** return `0`. *backstop*.
- `requests`/`limits` are summed from pod `spec.containers[].resources` and are **independent of metrics availability** (declared state is always present).
- **Overcommit is derivable client-side**: `over = max(0, requests − capacity)/capacity`. The endpoint returns raw sums; it does not precompute a boolean (the UI renders the red bar).
- `GET /api/v1/clusters/<id>/events` returns recent events newest-first with `type`, `reason`, `involved_object`, `message`, `count`, `last_timestamp` (snake_case, per the OpenAPI contract). *backstop*.
- Per-user RBAC holds for the **derived** rollup: a user without cluster-wide `list pods` **and** `list nodes` is denied (403 RBAC_DENIED) on the whole summary — a count never leaks for a user who cannot see the underlying resources. *backstop* (operational lens: in-cluster shared).
- **Metrics (used) is separately gated:** the `used_*` fields require `get nodes` on `metrics.k8s.io`. A user who can list pods/nodes but *cannot* read metrics gets `metrics_available:false` + `used:*:null` (declared requests/limits still visible) — used is never leaked from a source the user can't read.
- The view renders **unknown** (not `0`, not a healthy tone) for a metric whose source is absent (metrics unavailable → used unknown; no storage source → storage unknown).
- A value over 100% of capacity renders a **red overflow bar** sized to the over-capacity amount; a value at/under 100% renders none.

**Artifacts:**
- `backend/app/services/cluster_allocation.py` — **new**, pure (no Flask): the rollup logic (sum capacity/requests/limits, compute overcommit) over injected dicts.
- `backend/app/services/k8s_client.py` — `list_nodes`, `node_usage` (metrics via `api_client.call_api`), `list_pods` (exists) extended to carry requests/limits.
- `backend/app/api/metrics.py` — `GET /v1/clusters/<id>/metrics/summary` implemented (no longer 501 for this route).
- `backend/app/api/events.py` — **new** `GET /v1/clusters/<id>/events`.
- `backend/app/schemas/metrics.py` — `MetricsSummaryOut` (new).
- `backend/app/schemas/events.py` — `EventOut` (new).
- `frontend/src/views/Cluster/Dashboard.tsx` — **new**, the Option C view.
- `frontend/src/components/ConcentricDonut.tsx` — **new**, the reusable 3-ring donut (3-dataset doughnut + center % + optional overflow bar).
- `frontend/src/lib/types.ts` — `MetricsSummary`, `ClusterEvent` types.
- `frontend/src/App.tsx` — wire `/dashboard/cluster-metric` to the new view.
- `frontend/src/_nav.tsx` — retarget the **Cluster Metrics** sidebar leaf from `/clusters` to
  `/dashboard/cluster-metric` (Kubernetes Cluster keeps `/clusters` — decision, paladm, 2026-10-22;
  supersedes the ADR-0022 "share the cluster list" pairing for this entry).
- `frontend/tests/nav.test.tsx` — the `cluster-metrics-and-kubernetes-cluster-share-cluster-list`
  test now expects `Cluster Metrics` → `/dashboard/cluster-metric` and Kubernetes Cluster →
  `/clusters` (rename accordingly).
- Tests: `backend/tests/services/test_cluster_allocation.py`, `backend/tests/api/test_metrics_summary.py`, `backend/tests/api/test_events.py`, `frontend/tests/views/dashboard.test.tsx`, `frontend/tests/components/ConcentricDonut.test.tsx`.

**Key links:**
- `MetricsApi.summary` calls `pool.get(cluster).list_nodes()` + `list_pods()` + `node_usage()`, then the **pure** `cluster_allocation.compute_summary(nodes, pods, usage)` — the rollup is testable without a cluster.
- The view fetches `/metrics/summary` (one call) and renders the donuts + overflow bars; it does **not** recompute overcommit in multiple places (single source: the `ConcentricDonut` prop).
- `ConcentricDonut` takes `{used, requests, limits, capacity, hue, label}` and renders rings + the red overflow bar — the overcommit logic lives in one component.
- Events view reads `/events`; "Live · SSE" is wired only if an SSE events channel exists (else the badge is omitted — do not fake it).

**One-way-door decisions:**
- **New public API surface** (`/metrics/summary`, `/events`) — additive, but it grows the public contract. Tagged on the tasks that add each route.
- **Metrics API as the usage source** — if a different source (Prometheus) is later required, `node_usage` + the rollup's usage input rework. Tagged on the metrics task (ratified in the sibling ADR; confirmed here).

## Global Constraints

- **Certainty in data display (AGENTS.md § Rules):** a value KubeDash cannot read is never `0`, `none`,
  or a healthy tone — mark it unknown/partial and say why. Declared (requests/limits) vs observed
  (used) get distinct labels.
- **Never import Flask in `app/services/`** — `cluster_allocation.py` is pure (dicts in, dict out);
  `k8s_client.py` stays kubernetes+httpx only.
- **All K8s reads go through `K8sClientPool`** (the documented seam where ADR-0010's informer cache
  will *interpose later* — the cache is not built yet). No new per-request ad-hoc K8s calls outside the
  pool: events use `pool.get(cluster).list_events()`, metrics use `pool.get(cluster).node_usage()`.
- **Air gap (ADR-0020):** no CDN. Charts via `@coreui/react-chartjs` (bundled). No webfont.
- **CoreUI tokens only (ADR-0005):** the red overflow bar uses `--cui-danger`; ring hues are the two
  resource colors (blue/amber) — no new accent.
- **Conventional commits, no AI attribution.** Spec-zone commits precede code-zone.

## File Structure

- `backend/app/services/cluster_allocation.py` — **new**, pure rollup (capacity/requests/limits sums, overcommit).
- `backend/app/services/k8s_client.py` — add `list_nodes`, `node_usage` (metrics via `api_client.call_api`, no new client object), extend pod list to expose requests/limits.
- `backend/app/api/metrics.py` — implement `GET /v1/clusters/<id>/metrics/summary`.
- `backend/app/api/events.py` — **new** `GET /v1/clusters/<id>/events`.
- `backend/app/schemas/metrics.py` — **new** `MetricsSummaryOut`.
- `backend/app/schemas/events.py` — **new** `EventOut`.
- `backend/app/api/__init__.py` — register `EventsApi` (mirror `MetricsApi` registration).
- `frontend/src/components/ConcentricDonut.tsx` — **new** reusable 3-ring donut + overflow bar.
- `frontend/src/views/Cluster/Dashboard.tsx` — **new** Option C view.
- `frontend/src/lib/types.ts` — add `MetricsSummary`, `ClusterEvent`.
- `frontend/src/App.tsx` — route `/dashboard/cluster-metric` to the new view.
- `frontend/src/_nav.tsx` — Cluster Metrics leaf → `/dashboard/cluster-metric`.
- `frontend/tests/nav.test.tsx` — update the Cluster Metrics expectation.
- Tests (listed under Artifacts).

---

### Task 1: pure cluster-allocation rollup

**Files:**
- Create: `backend/app/services/cluster_allocation.py`
- Test: `backend/tests/services/test_cluster_allocation.py`

**Interfaces:**
- Consumes: nothing (pure). Inputs are plain dicts (node `to_dict`, pod `to_dict`, a usage dict) — the K8s layer produces them.
- Produces: `compute_summary(nodes: list[dict], pods: list[dict], usage: dict[str, dict] | None) -> dict` returning the `MetricsSummaryOut`-shaped dict (see Must-Haves). `usage` maps node-name → `{cpu_millicores, memory_bytes}`; **`None` ⇒ metrics unavailable** (used fields become `None`).
- Seam: `cluster_allocation.py` (the rollup). Deletion test: the summary endpoint re-implements summing + overcommit inline (and loses pure testability). Adapters: prod (K8s dicts) + test (hand-built dicts) — 2, seam justified.

**SATISFIES:** summary-computes-overcommit; summary-metrics-unavailable-not-zero

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/services/test_cluster_allocation.py
def test_compute_summary_overcommit():
    nodes = [node_dict(name="n1", cpu="4000m", mem="8Gi")]
    pods = [pod_dict(cpu_req="1000m", mem_req="2Gi"), pod_dict(cpu_req="1000m", mem_req="2Gi")]
    usage = {"n1": {"cpu_millicores": 800, "memory_bytes": 4 * 2**30}}
    s = cluster_allocation.compute_summary(nodes, pods, usage)
    assert s["cpu"]["capacity_millicores"] == 4000
    assert s["cpu"]["requests_millicores"] == 2000          # 2 pods x 1000m
    assert s["cpu"]["limits_millicores"] == 0                # no limits declared
    assert s["cpu"]["used_millicores"] == 800
    assert s["memory"]["requests_bytes"] == 4 * 2**30

def test_compute_summary_metrics_unavailable():
    s = cluster_allocation.compute_summary([node_dict("n1", "4000m", "8Gi")], [pod_dict("1000m", "2Gi")], usage=None)
    assert s["cpu"]["used_millicores"] is None
    assert s["cpu"]["requests_millicores"] == 1000          # declared state still present
```

- [ ] **Step 2: Run test to verify it fails** — `uv run pytest backend/tests/services/test_cluster_allocation.py -v` → FAIL (module not found).
- [ ] **Step 3: Write minimal implementation** — parse K8s quantities (`_parse_cpu`/`_parse_bytes` helpers for `m`/`Ki`/`Mi`/`Gi`), sum capacity across nodes, sum requests/limits across `pod.spec.containers[]` (a pod with no request contributes 0), set used from `usage` or `None` when unavailable. Pure — no imports beyond `typing`.
- [ ] **Step 4: Run test to verify it passes** — same command → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(api): pure cluster allocation rollup"`.

### Task 2: K8s client — nodes + metrics usage

> ⚠ one-way: introduces the **Metrics API** (`metrics.k8s.io`) as the usage source (ratified in
> `../2026-10-21-cluster-node/adr.md`; confirmed here).

**Files:**
- Modify: `backend/app/services/k8s_client.py` (add `list_nodes`, `node_usage`; metrics read uses the existing `self._api_client.call_api` — no new client object)
- Test: `backend/tests/services/test_k8s_client_metrics.py` (new)

**Interfaces:**
- Consumes: `K8sClient._v1` (CoreV1Api) for `list_nodes`; `K8sClient._api_client` (the shared `ApiClient`, line 170) `.call_api` for the metrics read (kubernetes 37.0.1 has no `MetricsV1beta1Api` — see Step 0).
- Produces: `list_nodes(self, _namespace=None) -> list[dict]` (cluster-scoped, mirrors `list_namespaces`); `node_usage(self) -> tuple[bool, dict[str, dict]]` returning `(available, {name: {cpu_millicores, memory_bytes}})` — `(False, {})` on Metrics API 404/5xx (query-only, never raise to the handler for a missing source).
- Seam: `k8s_client.py`. Deletion test: the summary endpoint loses its data source. Adapters: prod + `FakeK8s` double (the pool's `factory` seam) — 2.

**SATISFIES:** client-node-usage-available; client-node-usage-unavailable

- [ ] **Step 0: Verify the metrics API seam (door check).** The vendored client is **kubernetes 37.0.1**, whose generated client has **no `MetricsV1beta1Api`** (verified: `from kubernetes.client import MetricsV1beta1Api` raises ImportError; `kubernetes.utils.metrics` is the client's own Prometheus instrumentation, unrelated). So the metrics read uses `api_client.call_api` directly against `metrics.k8s.io`. Confirm:
  ```bash
  cd backend && .venv/bin/python -c "import kubernetes.client as c; print(hasattr(c, 'MetricsV1beta1Api'))"
  # expect: False  -> use call_api; if True, use self._metrics.read_node_metrics()
  ```
- [ ] **Step 1: Write the failing test** (available: `node_usage` returns `(True, {"n1": {...}})`; unavailable: the metrics HTTP call returns 404 → `(False, {})`).
- [ ] **Step 2: Run test to verify it fails** — `uv run pytest backend/tests/services/test_k8s_client_metrics.py -v` → FAIL.
- [ ] **Step 3: Implement** — `list_nodes` via `self._v1.list_node()`; `node_usage` via `self._api_client.call_api(['/apis/metrics.k8s.io/v1beta1/nodes'], 'GET', response_type='V1NodeMetricsList', _return_http_data_only=True)` (the shared `ApiClient` from line 170), parsing `usage.cpu` (millicores) / `usage.memory` (bytes) per node. 404/5xx → `(False, {})` (query-only, missing metrics-server is expected, not an error); other ApiExceptions → `_unreachable`. The test double stubs the `call_api` response.
- [ ] **Step 4: Run test to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(api): k8s client nodes + metrics usage (query-only)"`.

### Task 3: `GET /metrics/summary` endpoint

> ⚠ one-way: new public API route (additive).

**Files:**
- Create: `backend/app/schemas/metrics.py` (`MetricsSummaryOut`)
- Modify: `backend/app/api/metrics.py` (add the route; keep `query_range` 501)
- Test: `backend/tests/api/test_metrics_summary.py` (new)

**Interfaces:**
- Consumes: `pool.get(cluster).list_nodes/list_pods/node_usage` (Tasks 2), `cluster_allocation.compute_summary` (Task 1), `bound_cluster_or_404`, `rbac.can`.
- Produces: `GET /api/v1/clusters/<id>/metrics/summary` → `MetricsSummaryOut`.
- Seam: the `MetricsApi` handler + the pure rollup. Adapters: the handler + the injected rollup.

**SATISFIES:** summary-endpoint-ok; summary-endpoint-rbac-denied; summary-endpoint-metrics-unavailable

- [ ] **Step 1: Write the failing test** (ok → 200 with sums; RBAC: `rbac.can` False on cluster-wide `list pods` **or** `list nodes` → 403 RBAC_DENIED; metrics-denied: `rbac.can` True on pods/nodes but False on `get nodes`/`metrics.k8s.io` → 200 with `metrics_available:false`, `used:*` null, requests/limits still present; metrics 404 → 200, `metrics_available:false`, **not** 500).
- [ ] **Step 2: Run test to verify it fails** → FAIL.
- [ ] **Step 3: Implement** the schema (`MetricsSummaryOut` with nested `cpu`/`memory`/`pods` sub-schemas, snake_case, `used` fields nullable) + the route: `_cluster_for` (same as `resources.py`), then the **two-tier RBAC gate** (the rollup is a derived count, ADR-0004):
  - **Tier 1 (whole summary):** `rbac.can(user, cluster, "list", "pods", None, None, "")` **and** `list nodes` — cluster-wide (namespace=None), matching the cluster-wide data fetch. A per-namespace-only user is 403 (a designed, tested consequence, not an accident).
  - **Tier 2 (used only):** `rbac.can(user, cluster, "get", "nodes", None, None, "metrics.k8s.io")` — if denied, set `metrics_available:false` + `used:*:null` but still return declared requests/limits/capacity.
  Gather `nodes` (cluster-wide), `pods` (cluster-wide, namespace=None to match Tier 1), `usage` (only if Tier 2 passes), call `compute_summary`, set `metrics_available`.
- [ ] **Step 4: Run test to verify it passes** → PASS.
- [ ] **Step 5: Refresh the path baseline** — the new route changes `tests/api/apidocs_paths_baseline.json`; re-dump and commit it (`pnpm --dir frontend exec openapi-typescript` is the frontend side; the backend baseline regenerates via the apidocs dump test — run the backend apidocs snapshot test with the update flag and commit the diff).
- [ ] **Step 6: Commit** — `git commit -m "feat(api): cluster metrics summary endpoint"`.

### Task 4: `GET /events` endpoint

> ⚠ one-way: new public API route (additive).

**Files:**
- Create: `backend/app/api/events.py` (`EventsApi`)
- Create: `backend/app/schemas/events.py` (`EventOut`)
- Modify: `backend/app/api/__init__.py` (register `EventsApi`)
- Test: `backend/tests/api/test_events.py` (new)

**Interfaces:**
- Consumes: `pool.get(cluster)` (the informer-cache read path, ADR-0010) + `rbac.can` on `list events`.
- Produces: `GET /api/v1/clusters/<id>/events` → `EventOut` list, newest-first, with `type` (Normal/Warning), `reason`, `involved_object` (kind/name/namespace), `message`, `count`, `last_timestamp` (snake_case).
- Seam: `EventsApi` + `K8sClient.list_events`. Adapters: the handler + `FakeK8s` double.

**SATISFIES:** events-endpoint-lists; events-endpoint-rbac-denied

- [ ] **Step 0: Add `K8sClient.list_events`** (Task 4 owns this seam, not the handler): `list_events(self, _namespace=None) -> list[dict]` via `self._v1.list_event_for_all_namespaces()` (cluster-wide, to match the cluster-wide `list events` SAR gate). The informer cache interposes here later (ADR-0010); for now it is a live read through the pool — identical in shape to `list_pods`.
- [ ] **Step 1: Write the failing test** (lists events newest-first; RBAC denied on `list events` → 403).
- [ ] **Step 2: Run test to verify it fails** → FAIL.
- [ ] **Step 3: Implement** — `EventsApi` mirroring `resources.py`'s auth gate (`_cluster_for` + `rbac.can(user, cluster, "list", "events", None, None, "")`), call `pool.get(cluster).list_events()`, map to `EventOut`, sort by `last_timestamp` desc, default limit 100. The endpoint's order is authoritative; the frontend table renders it pre-sorted.
- [ ] **Step 4: Run test to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(api): cluster events endpoint"`.

### Task 5: `ConcentricDonut` component (reusable)

**Files:**
- Create: `frontend/src/components/ConcentricDonut.tsx`
- Test: `frontend/tests/components/ConcentricDonut.test.tsx`

**Interfaces:**
- Consumes: `@coreui/react-chartjs` (`CChart`) + the Chart.js doughnut config from the prototype (3 datasets = 3 rings; `centerText` plugin for the center %).
- Produces: `<ConcentricDonut used={number|null} requests={number} limits={number} capacity={number} hue={[r,g,b]} ariaLabel={string} />` — renders the 3 rings (darker tones alpha 1.0/0.7/0.45 of `hue`), the center used % (**"unknown"** when `used` is null), and a **red overflow bar** (CoreUI danger) sized to `max(0, max(requests,limits) − capacity)/capacity`. When `used` is null, the bar uses **only requests/limits** (the used term is skipped, not `NaN`).
- Seam: the component. Deletion test: the dashboard inlines the 3-dataset config + overcommit math (loses reuse + the single overcommit source). Adapters: the dashboard (prod) + the component test — 2.

**SATISFIES:** donut-renders-rings; donut-overcommit-red-bar; donut-unknown-used

- [ ] **Step 1: Write the failing test** (renders 3 rings; `requests=120`/`capacity=100` → red overflow bar width ~20%; `used=null` → center "unknown" **and** the bar uses only requests/limits).
- [ ] **Step 2: Run test to verify it fails** — `pnpm --dir frontend test -- ConcentricDonut` → FAIL.
- [ ] **Step 3: Implement** via `@coreui/react-chartjs` `CChart` (type `doughnut`, **3 datasets** = 3 rings, `cutout ~40%`). The `centerText` plugin is a **closure factory** `makeCenterText({pct, sub})` receiving the label values as props (the React wrapper owns the Chart lifecycle — do NOT store `$pct` on the instance as the vanilla prototype did). The plugin must be idempotent (React StrictMode double-mounts). Theme-aware: compute grid/tick/legend colors **as a function of the current `data-coreui-theme`** in render and let `CChart` `update()` — do not imperatively `destroy()`/redraw as the prototype's script tag did.
- [ ] **Step 4: Run test to verify it passes** → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(fe): concentric donut component with overcommit bar"`.

### Task 6: `Cluster/Dashboard` view

**Files:**
- Create: `frontend/src/views/Cluster/Dashboard.tsx`
- Modify: `frontend/src/lib/types.ts` (add `MetricsSummary`, `ClusterEvent`)
- Modify: `frontend/src/App.tsx` (route `/dashboard/cluster-metric` → `Dashboard`)
- Modify: `frontend/src/_nav.tsx` (Cluster Metrics leaf → `/dashboard/cluster-metric`)
- Modify: `frontend/tests/nav.test.tsx` (Cluster Metrics expectation)
- Test: `frontend/tests/views/dashboard.test.tsx`

**Interfaces:**
- Consumes: `apiFetch`, `ConcentricDonut` (Task 5), `KubeDataTable`, `TopMenu`, `useClusterStore`.
- Produces: `DashboardView` — fetches `/metrics/summary` + `/events` (two `useQuery`s), renders two rows (charts / events), CPU=blue, Memory=amber, Pods donut, events table.
- Seam: the view. Deletion test: the dashboard route reverts to the stub. Adapters: MSW for both endpoints.

**SATISFIES:** dashboard-renders-rows; dashboard-unknown-used; dashboard-no-cluster; dashboard-metrics-404-unknown

- [ ] **Step 1: Write the failing test** (MSW: summary + events → two rows render, CPU/Memory donuts, events table; summary `metrics_available:false` → used unknown; metrics endpoint 404 → unknown, **no red error** (version-skew, AGENTS.md known-gotcha); no cluster → "No cluster selected.").
- [ ] **Step 2: Run test to verify it fails** → FAIL.
- [ ] **Step 3: Implement** — the Option C layout from the prototype: `TopMenu` breadcrumb (Dashboard), row 1 = three cards (CPU `ConcentricDonut` blue, Memory amber, Pods donut), row 2 = events `KubeDataTable`. Overcommit is delegated to `ConcentricDonut` (single source). **"Live · SSE" badge only if an SSE events channel exists** — do not fake it (omit the badge when absent). **Version-skew (shared handler):** a 404 from *either* `/metrics/summary` or `/events` (old backend) maps to `{status:'unknown'}` — render unknown, **not** a red error (with `retry:false` a 404 throws → query `error` state, so the view must explicitly catch 404 per query). The events table renders the endpoint's newest-first order; **drop the prototype's "N newest of M" footer** (the endpoint returns a flat list with no total count) or add `total` to `EventOut` if the footer is wanted — pick one and note it.
- [ ] **Step 4: Run test to verify it passes** → PASS.
- [ ] **Step 5: Wire the route** in `App.tsx` at `/dashboard/cluster-metric` (lazy import, `ProtectedRoute`, matching the other cluster views), and retarget the **Cluster Metrics** leaf in `_nav.tsx` to that path; update the `cluster-metrics-and-kubernetes-cluster-share-cluster-list` test in `nav.test.tsx` (rename it — e.g. `cluster-metrics-opens-dashboard`) to expect `Cluster Metrics` → `/dashboard/cluster-metric` while Kubernetes Cluster keeps `/clusters`.
- [ ] **Step 6: Commit** — `git commit -m "feat(fe): cluster dashboard view (concentric donuts + events) at /dashboard/cluster-metric"`.

### Task 7: acceptance + quality gate

**Files:**
- Create: `.skillgrid/specs/2026-10-21-cluster-dashboard/acceptance.feature` (Cucumber BDD — spec folder, not `tests/features/`; matches the sibling changes' convention)
- Run: `qlty fmt`, `qlty check --fix --level=low --trigger agent`, `jscpd .`, full suites.

**SATISFIES:** all scenarios above.

- [ ] **Step 1: Author the `.feature`** — scenarios: summary overcommit, summary metrics-unavailable-not-zero, events list, RBAC denied, view renders rows, unknown used, no cluster, metrics-404-unknown, light+dark, cluster-metrics-nav-opens-dashboard.
- [ ] **Step 2: Run the gate** — `uv run pytest -m "not integration"` (backend), `task fe-check` (air-gap), `qlty check --fix --level=low --trigger agent`.
- [ ] **Step 3: Integration smoke (kind-gated, optional)** — against a kind cluster with a metrics-server, confirm real numbers + a red bar when overbooked; without a metrics-server, used = unknown. *backstop*.
- [ ] **Step 4: Commit** — `git commit -m "test: cluster dashboard acceptance + quality gate"`.

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Routing | Applicable | `/metrics/summary` + `/events` behind `apply_auth` + `bound_cluster_or_404` + `rbac.can`. | `test_metrics_summary_rbac_denied`; `test_events_rbac_denied`. |
| Per-user RBAC on derived data | Applicable (operational lens: in-cluster shared) | The rollup is a **derived count** — gated on `list pods` + `list nodes`, so a count never leaks for a user who can't see the resources (ADR-0004 cache key carries every attribute). | `test_metrics_summary_rbac_denied` (403). |
| Certainty in data display | Applicable | Missing metrics source → `metrics_available:false` + `used:null`; view renders **unknown**, never `0`. | `test_metrics_summary_metrics_unavailable` + `dashboard.test` unknown-assertion. |
| Version skew (frontend vs backend) | Applicable (AGENTS.md known-gotcha) | The view treats a 404 on `/metrics/summary` or `/events` as "unavailable → unknown", not a red error. | `dashboard.test` case: endpoint 404 → unknown, no red error. |
| Shell commands / subprocess | N/A | No shell/subprocess in this change. | — |

## Hypothesis

**Claim:** A pure cluster-allocation rollup (capacity + Σ pod requests/limits + Metrics API usage) can back the Option C dashboard (concentric donuts + overcommit + events) with honest unknown states.
**Right condition:** `GET /metrics/summary` returns real sums (or `metrics_available:false` with null used) without a 500, and the view renders the donuts + red overflow bar + events with unknown where a source is absent.
**Wrong condition:** the Metrics API requires auth/deployment KubeDash doesn't have in the target cluster, or the rollup can't be computed from the existing seam without a new data source.
**Thinnest MVP:** `compute_summary` (pure) + `/metrics/summary` + a CPU-only donut (no events).
**Door check:** Task 1 + Task 2 — if `node_usage` cannot read the Metrics API through the existing `K8sClient`/pool seam (auth/deployment gap), stop and reassess the usage source before building the view.

## Self-Review

- **Spec coverage:** R1 (metrics) → Tasks 1–3; R2 (overcommit) → Tasks 1 (rollup) + 5 (donut red bar) + 6 (view); R3 (events) → Task 4 + 6; R4 (layout/shell) → Task 6 (view + `/dashboard/cluster-metric` route + nav retarget); R5 (themes) → Tasks 5–6 (theme-aware charts). ✔
- **Route decision:** the view is routed at `/dashboard/cluster-metric` (user decision, 2026-10-22); the sidebar's Cluster Metrics entry is retargeted to it (ADR-0022 pairing superseded for this entry; nav test updated in Task 6). ✔
- **Must-haves coverage:** every truth/artifact/key-link maps to a task. The "unknown not zero" rule is covered in Tasks 1, 3, 6 + the threat matrix. ✔
- **One-way doors:** new API routes (Tasks 3, 4) and the metrics source (Task 2) are listed in Must-Haves and tagged. ✔
- **Owed decision:** metrics source → decided (metrics.k8s.io, ratified in the sibling ADR; recorded in the Decision note). Events source → named (informer cache per ADR-0010, fallback to CoreV1Api through the pool). No other owed decisions — every displayed value has a named source (Metrics API for used, pod specs for requests/limits, node status for capacity, informer cache for events, "unknown" where absent). ✔
- **Placeholder scan:** no TBD/"implement later". The `_parse_cpu`/`_parse_bytes` helpers are named with the quantity formats they must handle. ✔
- **Type consistency:** `compute_summary`, `list_nodes`, `node_usage`, `MetricsSummaryOut`, `EventOut`, `ConcentricDonut`, `MetricsSummary`, `ClusterEvent` are consistent across tasks. ✔
