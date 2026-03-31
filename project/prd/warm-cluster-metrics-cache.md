### PRD: Warm Cluster Metrics Cache

**OpenSpec change**: `openspec/changes/warm-cluster-metrics-cache/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

Cluster metrics dashboards in KubeDash can be slow or feel “cold” after restarts or long idle periods:

- Initial metrics scrapes can be expensive, especially on large clusters.
- Without a warm cache, users may see long load times or timeouts when opening metrics views.

We need to **keep cluster metrics warm and responsive** by pre‑populating and refreshing cached metrics on a schedule.

#### Goals

- Ensure the **Cluster Metrics** and related dashboards render quickly and consistently.
- Avoid repeated full‑cluster scrapes triggered by many users at once.
- Provide tunable refresh intervals that work across small and large clusters.

#### Functional Requirements

- Introduce a **metrics warmup ticker** that:
  - Runs periodically (configurable interval).
  - Scrapes cluster metrics (nodes, pods, etc.) via existing `lib/k8s/metrics` logic.
  - Persists metrics into the existing metrics tables (e.g. `metrics_nodes`, `metrics_pods`) used by dashboards.
- On startup:
  - Perform an initial metrics warmup pass once the app is ready and Kubernetes connectivity is confirmed.
  - Fail gracefully (log + metrics) if the first warmup fails, but do not block the app from starting.
- Metrics views in the UI should:
  - Prefer cached metrics from the DB.
  - Only fall back to on‑demand scrapes when necessary (e.g. cache expired or disabled).

#### Non‑Functional Requirements

- **Performance**
  - Warmup jobs must be efficient and not overload the Kubernetes API server.
  - Support configuration for batch sizes, namespaces, or filters for very large clusters.
- **Observability**
  - Expose Prometheus metrics for warmup job duration, success/failure counts, and last‑run timestamps.
  - Log failures with enough context to debug (e.g. cluster unreachable, auth errors).

---

### Implementation Tasks (from OpenSpec)

#### 1. Configuration

- [x] 1.1 Add config options for cluster‑metrics warming: enable flag (e.g. `cluster_metrics_warm_enabled`) and interval in seconds (e.g. `cluster_metrics_warm_interval_sec`), with defaults (enabled true, interval e.g. 300) and support from ini and/or env.
- [x] 1.2 Document the new options in `kubedash.ini.example` (or equivalent) and ensure disable (e.g. interval 0 or enabled false) prevents starting the ticker.

#### 2. Ticker Implementation

- [x] 2.1 Implement a ticker callback that runs inside Flask app context and calls `k8sGetClusterMetric()`; handle exceptions (log, do not crash the thread).
- [x] 2.2 Create an initializer function (e.g. `initialize_cluster_metrics_warmup(app)`) that, when warming is enabled and interval > 0, starts a `ThreadedTicker` with the configured interval and the callback from 2.1.
- [x] 2.3 Register the initializer at app startup (e.g. in `kubedash.py`) alongside existing tickers (workload cache, metrics scraper).

#### 3. Verification

- [x] 3.1 Verify that with the ticker enabled, the cluster‑metrics cache is populated after one interval and that `GET /api/v1/cluster/metrics` (or dashboard load) returns quickly from cache.
- [x] 3.2 Verify that with the ticker disabled (config), no cluster‑metrics warming ticker runs and cluster‑metrics behavior is unchanged (request‑driven only).

