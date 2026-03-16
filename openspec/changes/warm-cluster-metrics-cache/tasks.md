## 1. Configuration

- [x] 1.1 Add config options for cluster-metrics warming: enable flag (e.g. `cluster_metrics_warm_enabled`) and interval in seconds (e.g. `cluster_metrics_warm_interval_sec`), with defaults (enabled true, interval e.g. 300) and support from ini and/or env
- [x] 1.2 Document the new options in kubedash.ini.example (or equivalent) and ensure disable (e.g. interval 0 or enabled false) prevents starting the ticker

## 2. Ticker implementation

- [x] 2.1 Implement a ticker callback that runs inside Flask app context and calls `k8sGetClusterMetric()`; handle exceptions (log, do not crash the thread)
- [x] 2.2 Create an initializer function (e.g. `initialize_cluster_metrics_warmup(app)`) that, when warming is enabled and interval > 0, starts a ThreadedTicker with the configured interval and the callback from 2.1
- [x] 2.3 Register the initializer at app startup (e.g. in kubedash.py) alongside existing tickers (workload cache, metrics scraper)

## 3. Verification

- [x] 3.1 Verify that with the ticker enabled, the cluster-metrics cache is populated after one interval and that GET /api/v1/cluster/metrics (or dashboard load) returns quickly from cache
- [x] 3.2 Verify that with the ticker disabled (config), no cluster-metrics warming ticker runs and cluster-metrics behavior is unchanged (request-driven only)
