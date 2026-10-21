# Cluster Node View — Implementation Blueprint (steps, files, verification)

> **Role:** this is the *how* — the implementation plan: concrete steps, files to touch, code,
> tests, and verification. The product *why* (operator wants an honest cluster-node view) lives
> in the decision recorded in `../2026-10-21-dashboard-options/findings.md` and the prototype at
> `../../prototypes/001-dashboard-options/dashboard-1-41.html`. This blueprint is pure-technical
> and cites them rather than restating.

**Status:** ASSUMED — owes ratification (run `skillgrid:writing-blueprints` with this blueprint
as the topic to ratify)

**Tier:** T2

**Build shape:** Tracer thread (the node table is the thinnest end-to-end path UI→API→K8s; it
works first, then the metric tiles thicken it with the metrics source — integration risk with
the K8s API is the unknown, so connect it first)

**Goal:** Replace the `/cluster/node` stub with a real view — a `KubeDataTable` node list
(declared vs observed state, pod counts) above four cluster metric tiles, all backed by the
existing resource-listing seam and a new metrics query endpoint.

**Architecture:** Add a `nodes` row to the `resources.py` `_KINDS` table + a `K8sClient.list_nodes`
method (cluster-scoped, mirrors `list_namespaces`). Implement `K8sClient.node_metrics` using the
Kubernetes **Metrics API** (`metrics.k8s.io/v1beta1`) for per-node CPU/memory, wrapped in a
query-only `MetricsApi` per ADR-0003. The frontend `Cluster/Nodes` view (Option 1 layout) renders
the tiles first, then the node table, with per-metric `unknown` states where the source is absent.

**Tech Stack:** Flask 3 + Smorest (backend), `kubernetes` python client (v1 Core + Metrics API),
marshmallow schemas, React 18 + CoreUI + TanStack Query + `KubeDataTable` (frontend).

**Spec:** `../2026-10-21-dashboard-options/findings.md` (decision) + `../../prototypes/001-dashboard-options/dashboard-1-41.html` (visual reference). In-force ADRs: ADR-0003 (observability query-only), ADR-0004 (SAR cache key carries every attribute), ADR-0005 (CoreUI), ADR-0010 (informer cache read path), ADR-0020 (air gap), ADR-0023 (DataTables).

**Findings:** `../2026-10-21-dashboard-options/findings.md`

**Critic:** skipped (single-topic T2 feature; the self-review + plan-review gates still run) — *recorded, may change at review*

## Terms

Pointers only (canonical terms in `.skillgrid/artifacts/01-business-terms.md` / `02-technical-terms.md`):
- **Api**, **View**, **Informer cache**, **SSE stream** — see `02-technical-terms.md` (unchanged).
- **Metrics API** (newly used here): the `metrics.k8s.io/v1beta1` K8s API served by the in-cluster
  metrics-server; provides per-node/pod CPU+memory *usage*. KubeDash reads it query-only (ADR-0003)
  and never writes to it.

**Status: ASSUMED** — owes ratification (run `skillgrid:writing-blueprints` with this blueprint
as the topic to ratify)

| | |
|---|---|
| Owed decision | The **metrics data source** for the four tiles. `metrics.py` is a 501 stub and ADR-0003 has no body on disk, so the source is undecided. The blueprint assumes the **Kubernetes Metrics API** (`metrics.k8s.io/v1beta1`, via the python client). |
| Assumption built on | CPU/Memory per node come from `metrics.k8s.io/v1beta1` (`NodeMetrics`), queried live (query-only, ADR-0003), through the registry credentials. If the endpoint is absent (404) or a node has no sample, that tile/metric renders `unknown` — never `0`. Storage and the "Pods total/limit" tiles have **no** source in metrics.k8s.io; they render `unknown` until a source is named. |
| Code area | `backend/app/services/k8s_client.py` (`list_nodes`, `node_metrics`), `backend/app/api/metrics.py` + `backend/app/schemas/metrics.py` (new), `frontend/src/views/Cluster/Nodes.tsx` (new), `frontend/src/lib/types.ts`. |
| Authorized by | paladm, at the blueprint gate (2026-10-21) — scope "Table + real tiles, needs metrics work". |

## Must-Haves (goal-backward verification)

**Truths:**
- `GET /api/v1/clusters/<id>/resources/nodes` returns `{"items": [<node dict>...], "kind": "nodes", "cluster": <name>}` where each item is the cluster-native node `to_dict` form. *backstop* (needs a live kind cluster).
- The node table shows **declared** state (capacity, labels) and **observed** state (Ready condition, last-heartbeat) under *distinct labels* — per AGENTS.md § Certainty in data display.
- `GET /api/v1/clusters/<id>/metrics/nodes` returns per-node `{name, cpu_used_millicores, cpu_capacity_millicores, memory_used_bytes, memory_capacity_bytes, source: "metrics.k8s.io"}` plus a `metrics_available: true|false` flag.
- When metrics.k8s.io is unreachable (404/5xx), the metrics endpoint returns `metrics_available: false` with an empty/`null` series — it does **not** 500 and does **not** return zeros. *backstop*.
- The `/cluster/node` view renders four metric tiles + the node table; any metric whose source is absent renders the word **unknown** (or `—`), never `0`, never a healthy-tone number.
- Per-user RBAC holds for the metrics rollup: a user without `get nodes` is denied (403 RBAC_DENIED) on the node list; a user without access to metrics.k8s.io sees `unknown` tiles, not a 500. *backstop* (operational lens: in-cluster shared).

**Artifacts:**
- `backend/app/services/k8s_client.py` — `list_nodes` + `node_metrics` (real, not stub).
- `backend/app/api/resources.py` — `nodes` row in `_KINDS` (real).
- `backend/app/api/metrics.py` — `GET /v1/clusters/<id>/metrics/nodes` implemented (no longer 501 for this route).
- `backend/app/schemas/metrics.py` — `NodeMetricsOut` (new).
- `frontend/src/views/Cluster/Nodes.tsx` — the Option-1 view (tiles + node table), replacing the stub.
- `frontend/src/lib/types.ts` — `K8sNode`, `NodeMetrics` types.
- `tests/` — `backend/tests/services/test_k8s_client_nodes.py`, `backend/tests/api/test_resources_nodes.py`, `backend/tests/api/test_metrics_nodes.py`, `frontend/src/views/Cluster/Nodes.test.tsx`.

**Key links:**
- `ResourcesApi.list_resources` routes `kind == "nodes"` to `K8sClient.list_nodes` via the existing `_KINDS` row (no new endpoint).
- The `Nodes` view fetches **both** the node list and the metrics endpoint and joins them by node name; a node present in the list but absent from metrics gets `unknown` per-metric values.
- `MetricsApi` reuses the same `bound_cluster_or_404` + `rbac.can` gates as `resources.py` (single auth seam, per ADR-0004).

**One-way-door decisions:**
- **Adding the `nodes` kind to the public resource API** — new route surface; low risk (additive, one `_KINDS` row), but it changes the API contract. Tagged on Task 2.
- **Choosing metrics.k8s.io as the metrics source** — if a different source is later required (e.g. Prometheus per a future ADR), `node_metrics` + the tile wiring rework. This is the ASSUMED decision; ratified before or during the build. Tagged on Task 3.

## Global Constraints

- **Certainty in data display (AGENTS.md § Rules):** a value KubeDash cannot read is never rendered as `0`, `none`, or a healthy tone — mark it unknown/partial and say why. Declared (spec) vs observed (status) state get distinct labels.
- **Never import Flask in `app/services/`** — `k8s_client.py` stays pure (kubernetes client + dataclasses/dicts only).
- **Read path through the informer cache where it exists (ADR-0010)** — nodes are cluster-scoped and the cache is per-cluster; the node list may hit the API directly through the existing seam (consistent with `list_pods`), but must not add a per-request ad-hoc call pattern that bypasses the pool.
- **Air gap (ADR-0020):** no CDN in the frontend; the metrics API is an in-cluster endpoint (no external dependency).
- **CoreUI only (ADR-0005):** no Tailwind, no second accent, no webfont. Tiles are plain divs + `progress` inside the card body (per the prototype).
- **Conventional commits, no AI attribution** (per `commits.md`). Spec-zone commits precede code-zone.

## File Structure

- `backend/app/services/k8s_client.py` — add `list_nodes`, `node_metrics` (methods on `K8sClient`).
- `backend/app/api/resources.py` — add `"nodes": ("list_nodes", "nodes", "")` to `_KINDS`.
- `backend/app/api/metrics.py` — replace the 501 `query` body (keep `query_range` 501) with a `GET /clusters/<id>/metrics/nodes` route.
- `backend/app/schemas/metrics.py` — **new**: `NodeMetricsOut` marshmallow schema.
- `frontend/src/lib/types.ts` — add `K8sNode`, `NodeMetrics` types.
- `frontend/src/views/Cluster/Nodes.tsx` — **new**: the Option-1 view.
- `frontend/src/App.tsx` — wire `/cluster/node` to `Nodes` (replacing the stub route).
- Tests: `backend/tests/services/test_k8s_client_nodes.py`, `backend/tests/api/test_resources_nodes.py`, `backend/tests/api/test_metrics_nodes.py`, `frontend/src/views/Cluster/Nodes.test.tsx`.

---

### Task 1: `K8sClient.list_nodes`

**Files:**
- Modify: `backend/app/services/k8s_client.py` (add `list_nodes` near `list_namespaces`, ~line 194)
- Test: `backend/tests/services/test_k8s_client_nodes.py` (new)

**Interfaces:**
- Consumes: `K8sClient._v1` (`CoreV1Api`), existing `_unreachable` helper, `to_dict` form (all present).
- Produces: `list_nodes(self, _namespace: str | None) -> list[dict[str, Any]]` — cluster-scoped; the `_namespace` arg is accepted and ignored (mirrors `list_namespaces`).
- Seam: `k8s_client.py` (the resource list seam). Deletion test: the `resources.py` `nodes` route loses its data source. Adapters: prod `K8sClient` + a test double (mock `_v1.list_node`).

**SATISFIES:** node-list-returns-nodes

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/services/test_k8s_client_nodes.py
def test_list_nodes_returns_cluster_scoped_to_dict(client, mock_v1):
    fake = [type("N", (), {"to_dict": lambda self: {"metadata": {"name": "node-1"}}})()
    mock_v1.list_node.return_value = type("R", (), {"items": fake})()
    rows = client.list_nodes(None)
    assert rows == [{"metadata": {"name": "node-1"}}]
    mock_v1.list_node.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails** — `uv run pytest backend/tests/services/test_k8s_client_nodes.py -v` → FAIL (`list_nodes` not defined).
- [ ] **Step 3: Write minimal implementation**

```python
def list_nodes(self, _namespace: str | None) -> list[dict[str, Any]]:
    """Cluster-scoped node list (``to_dict``). The `_namespace` arg is accepted
    and ignored because nodes are cluster-scoped, mirroring ``list_namespaces``."""
    return [n.to_dict() for n in self._v1.list_node().items]
```

- [ ] **Step 4: Run test to verify it passes** — same command → PASS.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(api): add K8sClient.list_nodes"`.

### Task 2: route `nodes` through `resources.py`

> ⚠ one-way: adds the `nodes` kind to the public resource API (new route surface). Additive/low-risk, but confirm before the API contract grows.

**Files:**
- Modify: `backend/app/api/resources.py:46-55` (add a `_KINDS` row)
- Test: `backend/tests/api/test_resources_nodes.py` (new)

**Interfaces:**
- Consumes: `K8sClient.list_nodes` (Task 1), the existing `list_resources` handler, `rbac.can`.
- Produces: `GET /api/v1/clusters/<id>/resources/nodes` → `ResourceListOut` (no new handler).
- Seam: the `_KINDS` table (the documented seam "adding a kind is one table row"). Adapters: the existing handler + `rbac.can` gate.

**SATISFIES:** node-endpoint-returns-list; node-endpoint-rbac-denied

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/api/test_resources_nodes.py
def test_list_nodes_endpoint(client, authed, mock_pool):
    mock_pool.get.return_value.list_nodes.return_value = [{"metadata": {"name": "node-1"}}]
    r = client.get("/api/v1/clusters/1/resources/nodes")
    assert r.status_code == 200
    body = r.get_json()
    assert body["kind"] == "nodes"
    assert body["items"] == [{"metadata": {"name": "node-1"}}]

def test_list_nodes_rbac_denied(client, authed, mock_pool, mock_rbac):
    mock_rbac.can.return_value = False
    r = client.get("/api/v1/clusters/1/resources/nodes")
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "RBAC_DENIED"
```

- [ ] **Step 2: Run test to verify it fails** — `uv run pytest backend/tests/api/test_resources_nodes.py -v` → FAIL (404 `RESOURCE_KIND_NOT_SUPPORTED`).
- [ ] **Step 3: Add the table row**

```python
_KINDS: dict[str, tuple[str, str, str]] = {
    "pods": ("list_pods", "pods", ""),
    "namespaces": ("list_namespaces", "namespaces", ""),
    "nodes": ("list_nodes", "nodes", ""),   # cluster-scoped; no group
    "serviceaccounts": ("list_serviceaccounts", "serviceaccounts", ""),
    # ... existing rows unchanged
}
```

- [ ] **Step 4: Run test to verify it passes** — same command → PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat(api): list cluster nodes via resources endpoint"`.

### Task 3: `K8sClient.node_metrics` + `MetricsApi` route

> ⚠ one-way: chooses metrics.k8s.io as the metrics source (the ASSUMED decision). If a different source is later required, `node_metrics` and the tile wiring rework — ratify before/at this task.

**Files:**
- Modify: `backend/app/services/k8s_client.py` (add `node_metrics` + a lazily-built metrics client)
- Create: `backend/app/schemas/metrics.py` (`NodeMetricsOut`)
- Modify: `backend/app/api/metrics.py` (implement the route; keep `query_range` 501)
- Test: `backend/tests/api/test_metrics_nodes.py` (new) + `backend/tests/services/test_k8s_client_node_metrics.py` (new)

**Interfaces:**
- Consumes: `K8sClient._v1` (for capacity) + a new `MetricsV1beta1Api` on the same `ApiClient`; `bound_cluster_or_404`, `rbac.can`.
- Produces: `node_metrics(self) -> tuple[bool, list[dict[str, Any]]]` — returns `(metrics_available, series)` where each series item is `{name, cpu_used_millicores, cpu_capacity_millicores, memory_used_bytes, memory_capacity_bytes}`. `metrics_available` is `False` when the metrics API 404s/5xxes (query-only; never raise to the handler for a missing source).
- Seam: `k8s_client.py`. Deletion test: the metrics endpoint loses its data source. Adapters: prod `K8sClient` + test double.

**SATISFIES:** metrics-endpoint-available; metrics-endpoint-unavailable-no-zero

- [ ] **Step 1: Write the failing test** (service — available)

```python
def test_node_metrics_available(client, mock_v1, mock_metrics):
    # mock_metrics.read_node_metrics() -> items with usage; mock_v1.list_node() -> capacity
    avail, series = client.node_metrics()
    assert avail is True
    assert series[0]["name"] == "node-1"
    assert series[0]["cpu_used_millicores"] == 1234
    assert series[0]["cpu_capacity_millicores"] == 8000  # from list_node capacity
```

- [ ] **Step 2: Run test to verify it fails** → FAIL (`node_metrics` not defined).
- [ ] **Step 3: Write the implementation**

```python
def node_metrics(self) -> tuple[bool, list[dict[str, Any]]]:
    """Per-node CPU/memory from metrics.k8s.io + capacity from core v1 (query-only,
    ADR-0003). Returns (available, series). A missing metrics API 404/5xx returns
    (False, []) — the UI renders unknown, never zero."""
    try:
        resp = self._metrics.read_node_metrics()
    except ApiException as e:
        if e.status in (404, 500, 502, 503):
            return False, []
        self._unreachable("node_metrics", e)
        raise AssertionError("unreachable") from e
    capacities = {n["metadata"]["name"]: (n.get("status", {}).get("capacity") or {})
                  for n in self.list_nodes(None)}
    out = []
    for m in resp.items:
        md = m.to_dict()
        usage = md.get("usage", {})
        name = md["metadata"]["name"]
        cap = capacities.get(name, {})
        out.append({
            "name": name,
            "cpu_used_millicores": int(usage.get("cpu", "0").lstrip("m") or 0) if str(usage.get("cpu", "")).endswith("m") else int(float(usage["cpu"]) * 1000),
            "cpu_capacity_millicores": int(cap.get("cpu", "0").lstrip("m") or 0),
            "memory_used_bytes": int(usage.get("memory", "0").lstrip("Ki").lstrip("Mi").lstrip("Gi").lstrip("k") or 0),
            "memory_capacity_bytes": int(cap.get("memory", "0").replace("Ki", "000") or 0),
        })
    return True, out
```

> **Note for the implementer:** quantity parsing (millicores, Ki/Mi/Gi) is the fiddly part. Extract a `_parse_quantity(q: str) -> tuple[int, str]` helper and unit-test it in `test_k8s_client_node_metrics.py` with `1234m`, `1`, `1Gi`, `512Mi` — do not inline the string math above verbatim. (The sketch above is the shape, not the final parser.)

- [ ] **Step 4: Write the schema + route**

```python
# backend/app/schemas/metrics.py
from marshmallow import Schema
from marshmallow.fields import Boolean, List, Nested, Number, String
class NodeMetric(Schema):
    name = String()
    cpu_used_millicores = Number()
    cpu_capacity_millicores = Number()
    memory_used_bytes = Number()
    memory_capacity_bytes = Number()
class NodeMetricsOut(Schema):
    cluster = String()
    metrics_available = Boolean()
    source = String(default="metrics.k8s.io")
    items = List(Nested(NodeMetric))
```

```python
# backend/app/api/metrics.py — the new route (query_range stays 501)
@blp.route("/clusters/<int:cluster_id>/metrics/nodes", methods=["GET"])
@blp.response(200, NodeMetricsOut)
def node_metrics(self, cluster_id: int) -> dict:
    cluster = _cluster_for(g.current_user, cluster_id)   # bound_cluster_or_404, same seam
    if not rbac.can(g.current_user, cluster, "get", "nodes", None, None, ""):
        raise RbacDeniedError("get on nodes")
    available, items = pool.get(cluster).node_metrics()
    return {"cluster": cluster.name, "metrics_available": available,
            "source": "metrics.k8s.io", "items": items}
```

- [ ] **Step 5: Write the endpoint tests** (available → 200 with items; metrics 404 → 200 with `metrics_available: false`, `items: []`, **not** 500, **not** zeros; RBAC denied → 403).
- [ ] **Step 6: Run all metrics tests** — `uv run pytest backend/tests/api/test_metrics_nodes.py backend/tests/services/test_k8s_client_node_metrics.py -v` → PASS.
- [ ] **Step 7: Commit** — `git commit -m "feat(api): implement node metrics query endpoint (ADR-0003)"`.

### Task 4: frontend `Cluster/Nodes` view (Option 1)

**Files:**
- Create: `frontend/src/views/Cluster/Nodes.tsx`
- Modify: `frontend/src/lib/types.ts` (add `K8sNode`, `NodeMetrics`)
- Modify: `frontend/src/App.tsx` (route `/cluster/node` → `Nodes`)
- Test: `frontend/src/views/Cluster/Nodes.test.tsx` (new)

**Interfaces:**
- Consumes: `apiFetch`, `KubeDataTable`, `TopMenu`, `useClusterStore` (all present, see `Namespaces.tsx`).
- Produces: a `NodesView` that fetches `/resources/nodes` and `/metrics/nodes` (two `useQuery`s), joins by node name, and renders four tiles + the table.
- Seam: the view (React). Deletion test: `/cluster/node` reverts to the stub. Adapters: MSW for the two endpoints in tests.

**SATISFIES:** node-view-renders-tiles-and-table; node-view-unknown-metric; node-view-no-cluster

- [ ] **Step 1: Write the failing test** (MSW mocks both endpoints; assert tiles render, a node without a metric shows "unknown", and a not-ready node shows a secondary badge).

```tsx
// frontend/src/views/Cluster/Nodes.test.tsx (Vitest + RTL + MSW)
it('renders metric tiles and marks a node unknown when metrics are absent', async () => {
  server.use(
    http.get('*/clusters/1/resources/nodes', () => HttpResponse.json({ kind: 'nodes', cluster: 'prod1', items: [node('node-1', 'Ready'), node('node-2', 'NotReady')] })),
    http.get('*/clusters/1/metrics/nodes', () => HttpResponse.json({ cluster: 'prod1', metrics_available: true, source: 'metrics.k8s.io', items: [metric('node-1')] })),
  )
  render(<NodesView />)   // cluster id 1 selected in the store
  expect(await screen.findByText('CPU usage')).toBeInTheDocument()
  expect(screen.getByText('unknown')).toBeInTheDocument()   // node-2 has no metric
  expect(screen.getByText('NotReady')).toBeInTheDocument()
})
```

- [ ] **Step 2: Run test to verify it fails** — `pnpm --dir frontend test -- Nodes.test` → FAIL (no view).
- [ ] **Step 3: Implement the view** — Option 1 layout from `../../prototypes/001-dashboard-options/dashboard-1-41.html`:
  - `TopMenu` breadcrumb `Cluster > Nodes`, **no** header create icon (nodes aren't created here).
  - One `CCard shadow mb-4`, title `Cluster Metrics` (or `Node Metrics`) `m-0 fw-bold text-primary fs-6`.
  - Four tiles (`row row-cols-2 row-cols-lg-4 g-3`): **CPU usage**, **Memory usage**, **Pods**, **Storage**. Each tile: label (`text-muted text-uppercase`), value, a thin `progress` bar. CPU/Memory values come from the metrics endpoint (rollup = sum usage / sum capacity across nodes). **Pods** = ready/total from the node list. **Storage** has no source → render the word **unknown** (or `—`) + `text-muted` "no storage metrics source".
  - Certainty rule: if `metrics_available` is `false`, CPU/Memory tiles show **unknown** (not 0%). A node row present in the list but absent from metrics shows per-row **unknown**.
  - Node `KubeDataTable` columns (order per STYLEGUIDE: status, name, resource fields, created, action): **Status** (badge: `Ready`→success, else secondary — *observed*), **Name** (plain, no object page yet), **CPU** (used/cap, or unknown), **Memory** (used/cap, or unknown), **Pods** (ready/total), **Age/Created**. No row actions (read-only).
  - Loading/empty/error states inside the card body per STYLEGUIDE.
- [ ] **Step 4: Run test to verify it passes** → PASS.
- [ ] **Step 5: Wire the route** in `App.tsx` (replace the stub entry for `/cluster/node`).
- [ ] **Step 6: Commit** — `git commit -m "feat(fe): add cluster node view (metrics tiles + node table)"`.

### Task 5: acceptance + quality gate

**Files:**
- Create: `tests/features/cluster-node.acceptance.feature` (Cucumber BDD, per AGENTS.md § Quality gate)
- Run: `qlty fmt`, `qlty check --fix --level=low --trigger agent`, `jscpd .`, full backend + frontend suites.

**Interfaces:** none (verification).
**SATISFIES:** all scenarios above.

- [ ] **Step 1: Author the `.feature`** with scenarios mirroring the SATISFIES names (node list, RBAC denied, metrics available, metrics unavailable → unknown not zero, view renders, no cluster selected).
- [ ] **Step 2: Run the gate** — `uv run pytest -m "not integration"` (backend), `task fe-check` (air-gap), `qlty check --fix --level=low --trigger agent`.
- [ ] **Step 3: Integration smoke (kind-gated, optional here)** — against a kind cluster with a metrics-server, confirm the tiles show real numbers and a node without metrics shows unknown. *backstop*.
- [ ] **Step 4: Commit** — `git commit -m "test: cluster node acceptance + quality gate"`.

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| Routing | Applicable | `nodes` added via the `_KINDS` seam; metrics via a new `MetricsApi` route, both behind the existing `apply_auth` + `bound_cluster_or_404` + `rbac.can` gates. | `test_list_nodes_rbac_denied` (403); `test_list_nodes_endpoint` (200). |
| Per-user RBAC on derived data | Applicable (operational lens: in-cluster shared) | The metrics rollup is a *derived* count — gated on `get nodes` so a count never leaks for a user who cannot see nodes. | `test_node_metrics_rbac_denied` (403 on `/metrics/nodes`). |
| Certainty in data display | Applicable | Missing metrics source → `metrics_available:false` + `unknown` tiles; never `0`/healthy tone. | `test_node_metrics_unavailable_not_zero` + `Nodes.test` unknown-assertion. |
| Shell commands / subprocess | N/A | No shell/subprocess in this change. | — |
| Version skew (frontend vs backend) | Applicable (AGENTS.md known-gotcha) | The view calls `/metrics/nodes`; if the backend predates it the call 404s. The view treats a 404 on the metrics call as "metrics unavailable → unknown", not a red error. | `Nodes.test` case: metrics endpoint 404 → tiles show unknown, no red error. |

## Hypothesis

**Claim:** The existing `_KINDS` resource seam + a query-only metrics endpoint can back the Option-1 node view (tiles + table) with honest per-metric unknown states.
**Right condition:** `GET /resources/nodes` returns real node dicts and `GET /metrics/nodes` returns usage+capacity (or `metrics_available:false`) without a 500; the view renders tiles + table with unknown where the source is absent.
**Wrong condition:** the `_KINDS` seam cannot carry a cluster-scoped kind, or metrics.k8s.io requires a source/auth KubeDash does not have, forcing a rework of the metrics seam.
**Thinnest MVP:** `list_nodes` + the `nodes` `_KINDS` row + a node table (no tiles).
**Door check:** Task 1 + Task 2 — if `list_nodes` does not flow through `resources.py` as a clean cluster-scoped kind, stop and reassess the seam before building tiles.

## Self-Review

- **Spec coverage:** the decision (Option 1 → `/cluster/node`, table + real tiles) is fully covered by Tasks 1–5. ✔
- **Must-haves coverage:** every truth/artifact/key-link maps to a task. The "unknown not zero" rule is covered in Task 3 (endpoint) + Task 4 (view) + the threat matrix. ✔
- **One-way doors:** `nodes` API (Task 2) and metrics source (Task 3) are listed in Must-Haves and tagged. ✔
- **Owed decision:** metrics source → carried in the `ASSUMED` block (ratify before/at Task 3). ✔
- **Placeholder scan:** Task 3 Step 3's quantity parser is flagged "shape, not the final parser" with an explicit instruction to extract + unit-test `_parse_quantity` — not a silent TBD. All other steps are concrete. ✔
- **Type consistency:** `list_nodes`, `node_metrics`, `NodeMetricsOut`, `K8sNode`, `NodeMetrics` names are consistent across tasks. ✔
