## Why

The cluster-metrics dashboard and `/api/v1/cluster/metrics` endpoint are slow on cache miss because `k8sGetClusterMetric()` runs three sequential Kubernetes API calls (nodes, all pods, metrics-server). The cache is only populated when a request hits the endpoint, so the first user after startup or after the 15-minute TTL always waits for the full fetch. We already use ThreadedTickers elsewhere to warm caches (e.g. workload lists). Adding a ThreadedTicker that periodically calls `k8sGetClusterMetric()` keeps the cluster-metrics cache warm so users get fast responses without changing the API or UI.

## What Changes

- Add a background ThreadedTicker that, at a configurable interval (e.g. every 60–300 seconds), calls `k8sGetClusterMetric()` so the result is written to the existing cache (key `k8sGetClusterMetric`).
- Register this ticker at app startup alongside existing tickers (workload cache, metrics scraper).
- No change to `k8sGetClusterMetric()` itself, cache key, or TTL; no change to the cluster-metrics API or dashboard contract. The ticker simply pre-populates the same cache that the request path already reads from.

## Capabilities

### New Capabilities

- **cluster-metrics-ticker**: A background task (ThreadedTicker) runs at a configurable interval and invokes the cluster-metrics fetch logic so the cluster-metrics cache is warmed proactively. Dashboard and API behavior remain unchanged; they continue to read from cache when available.

### Modified Capabilities

- None. Observable behavior of the cluster-metrics endpoint and dashboard is unchanged; only the likelihood of a cache hit is improved.

## Impact

- **Affected code**: App initialization (e.g. `kubedash.py` or an initializer module) to start the new ticker; optional config (e.g. `kubedash.ini` or env) for interval and enable/disable. `lib/k8s/metrics.py` may be called from a new call site (the ticker) in addition to the request path.
- **APIs**: No API contract changes.
- **Dependencies**: Uses existing `ThreadedTicker` and existing `k8sGetClusterMetric()`; no new dependencies.
- **Operational**: One additional background thread; interval should be chosen so that cache stays warm without overloading the Kubernetes API (e.g. align with or slightly shorter than cache TTL).
