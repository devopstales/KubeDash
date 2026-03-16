## ADDED Requirements

### Requirement: Cluster-metrics cache is warmed by a background ticker

The system SHALL run a background task (ThreadedTicker) that periodically invokes the cluster-metrics fetch logic so that the cluster-metrics cache is populated proactively. The ticker SHALL use the same cache key and storage as the request path (`k8sGetClusterMetric`). The ticker interval SHALL be configurable. The ticker MAY be disabled by configuration so that no background warming occurs.

#### Scenario: Ticker runs when enabled

- **WHEN** the application starts and cluster-metrics warming is enabled with a positive interval
- **THEN** a ThreadedTicker is started that, at the configured interval, calls the same logic that populates the cluster-metrics cache (e.g. `k8sGetClusterMetric()`), so that subsequent requests to the cluster-metrics API or dashboard may be served from cache

#### Scenario: Ticker is disabled

- **WHEN** the application starts and cluster-metrics warming is disabled (e.g. via config or interval set to 0)
- **THEN** no cluster-metrics warming ticker is started, and cluster-metrics cache is only populated when a request triggers the fetch (current behavior)

#### Scenario: Request path unchanged

- **WHEN** a client requests cluster metrics (dashboard or GET /api/v1/cluster/metrics)
- **THEN** the system SHALL continue to read from the same cache key as today; if the ticker has populated the cache, the response is fast; if not, the existing fetch-and-cache behavior applies
