### PRD: Direct Prometheus Metrics Integration (Optional)

**Status**: Optional proposal (behind config flag; does not replace existing pipeline by default)  

#### Problem / Why

Today KubeDash scrapes cluster metrics via the Kubernetes API and **persists them into a relational database** (warm cache, historical metrics, dashboards). This works, but:

- It **duplicates** metrics storage that already exists in Prometheus.
- For large clusters, scraping and storing high‑cardinality metrics in the app DB can be **expensive** (CPU, I/O, storage).
- Operators who already run Prometheus would rather **reuse their existing metrics stack** (retention, alerting, federation) than maintain a second metrics store.

We want an **optional path** where KubeDash can read metrics **directly from Prometheus** instead of (or in parallel with) the internal scraping + DB pipeline, reducing operational overhead for Prometheus‑first environments.

#### Goals

- **Optional, non‑breaking change**: existing metrics scraping and DB‑backed dashboards remain the default and continue to work unchanged.
- Allow operators to **opt into Prometheus as the metrics backend** for relevant dashboards via configuration.
- Reduce duplication of metrics storage and scraping work when Prometheus is available.
- Preserve (or improve) dashboard performance and UX when using Prometheus directly.

#### Out of Scope

- Replacing the internal metrics pipeline entirely in this iteration.  
- Implementing a full query builder UI for arbitrary PromQL.  
- Changing alerting; alerts continue to be defined and handled in Prometheus or existing tooling.

#### Functional Requirements

- **Configurable backend selection**
  - Introduce a configuration option (e.g. `metrics_backend`) that can be:
    - `"internal"` (default): current behavior, scrape via Kubernetes API and store in DB.
    - `"prometheus"`: read metrics from Prometheus only (no new metrics writes to DB).
    - `"hybrid"` (optional): use Prometheus for live/near‑real‑time views while still persisting a curated subset of metrics in DB for specific features that require it.
  - Configuration must be available via `kubedash.ini` and environment variables, and clearly documented.

- **Prometheus connection configuration**
  - Add config for Prometheus endpoint (e.g. `prometheus_base_url`), authentication (if needed), and TLS options.
  - Support both in‑cluster Prometheus (service DNS) and external Prometheus endpoints.

- **Metrics query abstraction**
  - Introduce a thin **metrics repository/adapter** that hides whether metrics come from:
    - the existing DB schema; or
    - Prometheus HTTP API (e.g. `/api/v1/query`, `/api/v1/query_range`).
  - Existing dashboards (cluster metrics, node health, workload metrics) should consume this abstraction instead of directly querying the DB or Prometheus.

- **Initial dashboard coverage**
  - At minimum, support direct Prometheus integration for:
    - Cluster‑level CPU / memory / pod count panels.
    - Node‑level CPU / memory / disk / network basics.
    - Namespace/workload summary metrics used on the main overview dashboards.
  - When `metrics_backend=prometheus`, these views should run PromQL queries instead of DB queries, but preserve the same or very similar visualizations.

- **Failure behavior**
  - If Prometheus is configured but unreachable:
    - The UI must surface a clear, non‑leaky error (e.g. “Prometheus unavailable; check configuration or network”).
    - The backend should log detailed error context for operators.
  - If both Prometheus and internal metrics are available and `metrics_backend=hybrid`, define a clear precedence for each view (e.g. prefer Prometheus for live graphs, fall back to DB only for specific features).

#### Non‑Functional Requirements

- **Security**
  - Do not expose Prometheus credentials or URLs in the UI or logs.
  - Support TLS and, where feasible, basic auth / bearer token for Prometheus endpoints.

- **Performance**
  - PromQL queries for dashboards should be bounded (time ranges, step) to avoid overloading Prometheus.
  - Avoid issuing redundant queries when multiple panels can share a common query or range.

- **Observability**
  - Emit internal metrics for:
    - Prometheus query latency and error rates.
    - Backend selection (counts of requests served via DB vs Prometheus).

#### Migration / Rollout Strategy

- Ship as **opt‑in**: default remains the existing internal scraping + DB storage pipeline.
- Provide clear documentation and examples for:
  - Enabling Prometheus integration.
  - Recommended Prometheus metrics and retention settings for KubeDash dashboards.
- Later iterations can:
  - Gradually move more features to Prometheus.
  - Optionally deprecate parts of the internal metrics pipeline in environments where Prometheus is mandatory.

