## Context

- **Current state**: Cluster metrics are served by `k8sGetClusterMetric()` in `lib/k8s/metrics.py`, which checks cache key `k8sGetClusterMetric` and, on miss, runs three sequential K8s API calls (list nodes, list pods for all namespaces, list metrics.k8s.io nodes), then caches the result for `long_cache_time` (900s). The dashboard and `/api/v1/cluster/metrics` call this function. No background task currently warms this cache; it is only filled when a request runs the function. Existing ThreadedTickers live in `lib/initializers/workload_cache.py` (workload lists) and `lib/metrics.py` (metrics scraper to DB); app startup wires them in `kubedash.py` and/or initializers.
- **Constraints**: Reuse existing `ThreadedTicker` and `k8sGetClusterMetric()`; do not change cache key or TTL semantics. Cluster-metrics API and dashboard contract stay the same.

## Goals / Non-Goals

**Goals:**

- Run a background ThreadedTicker that periodically calls `k8sGetClusterMetric()` so the cluster-metrics cache is warmed proactively.
- Make the ticker interval configurable (e.g. ini or env) and optional (e.g. disable for installs that want to avoid the extra K8s load).
- Start the ticker at app startup alongside other tickers.

**Non-Goals:**

- Changing how `k8sGetClusterMetric()` works, or adding parallel K8s calls; that is a separate change. Optimizing the cluster-metrics request path or adding stale-while-revalidate is out of scope.

## Decisions

1. **Where to run the ticker**
   - **Decision**: Call `k8sGetClusterMetric()` from a ThreadedTicker started in the same place other tickers are started (e.g. next to `initialize_workloadcachers` or `initialize_metrics_scraper` in `kubedash.py`, or in a small initializer module for “cluster metrics warm-up”). The ticker callback runs inside Flask app context so that `k8sGetClusterMetric()` and the cache backend have access to the app.
   - **Rationale**: Matches existing pattern (workload_cache, metrics scraper). No new process or service.

2. **Interval and alignment with cache TTL**
   - **Decision**: Default interval slightly shorter than cache TTL (e.g. 300s or 600s) so the cache is refreshed before expiry. Make interval configurable (e.g. `cluster_metrics_warm_interval_sec` in ini, or env `KUBEDASH_CLUSTER_METRICS_WARM_INTERVAL`) so operators can tune. If interval is 0 or the feature is disabled, do not start the ticker.
   - **Rationale**: Avoids thundering herd when cache expires; keeps cache warm without unnecessary API load.

3. **Enable/disable**
   - **Decision**: Support an explicit disable (e.g. `cluster_metrics_warm_enabled = false` or `KUBEDASH_CLUSTER_METRICS_WARM_ENABLED=false`) so deployments that already use `skip_cluster_metrics` or want to minimize K8s API calls can leave the ticker off.
   - **Rationale**: Aligns with existing `skip_cluster_metrics`-style options and gives operators control.

4. **Error handling in the ticker**
   - **Decision**: The ticker callback invokes `k8sGetClusterMetric()` and does not need to interpret the return value for “bad” metrics; the function already returns a fallback structure on error and does not cache it. Log exceptions so failures are visible; do not crash the ticker thread.
   - **Rationale**: Keeps cache logic inside `k8sGetClusterMetric()`; ticker is a simple periodic trigger.

## Risks / Trade-offs

- **[Extra K8s load]** The ticker adds periodic list_node + list_pod_for_all_namespaces + metrics API calls. **Mitigation**: Configurable interval and disable flag; default interval no more frequent than cache refresh needs (e.g. every 5–10 minutes).
- **[Stale dashboard]** Users may see data up to one interval old. **Mitigation**: Same as today when cache is hit; document that cluster metrics are refreshed on the ticker schedule when the ticker is enabled.
- **[App context]** Ticker runs in a background thread; must ensure Flask app context is available when calling `k8sGetClusterMetric()` and cache. **Mitigation**: Use the same pattern as workload_cache (e.g. `with app.app_context():` in the callback or pass `app` into a closure).

## Migration Plan

- No data migration. Deploy: add config options, start the ticker at startup when enabled. Rollback: disable the ticker or revert the change; cluster-metrics will again be request-driven only.

## Open Questions

- None.
