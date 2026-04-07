# Graceful Shutdown: Troubleshooting & Monitoring

## Monitoring During Shutdown

### Key Metrics

```python
# src/kubedash/lib/metrics.py

from prometheus_client import Counter, Histogram, Gauge
from datetime import datetime

# Counters
startup_total = Counter(
    'kubedash_startup_total',
    'Total number of startups',
    ['reason']  # 'initial', 'restart', 'upgrade'
)

shutdown_initiated_total = Counter(
    'kubedash_shutdown_initiated_total',
    'Total graceful shutdowns initiated',
    ['reason', 'pod']  # reason: 'sigterm', 'api', 'error'
)

shutdown_successful_total = Counter(
    'kubedash_shutdown_successful_total',
    'Total successful graceful shutdowns'
)

shutdown_failed_total = Counter(
    'kubedash_shutdown_failed_total',
    'Total failed graceful shutdowns',
    ['error_type']
)

# Histograms
shutdown_duration_seconds = Histogram(
    'kubedash_shutdown_duration_seconds',
    'Time taken for graceful shutdown (all phases)',
    buckets=(1, 5, 10, 15, 20, 30)
)

shutdown_phase_duration_seconds = Histogram(
    'kubedash_shutdown_phase_duration_seconds',
    'Time taken for individual shutdown phase',
    ['phase'],  # phase: 'leadership', 'requests', 'drain', 'scheduler', 'handlers', 'database'
    buckets=(0.1, 0.5, 1, 2, 5, 10)
)

request_drain_time_seconds = Histogram(
    'kubedash_request_drain_time_seconds',
    'Time to drain in-flight requests',
    buckets=(1, 5, 10, 15, 20)
)

leadership_release_time_seconds = Histogram(
    'kubedash_leadership_release_time_seconds',
    'Time to release Kubernetes Lease',
    buckets=(0.1, 0.5, 1, 2, 5)
)

# Gauges
in_flight_requests = Gauge(
    'kubedash_in_flight_requests',
    'Current number of in-flight HTTP requests'
)

pod_shutdown_grace_remaining_seconds = Gauge(
    'kubedash_shutdown_grace_remaining_seconds',
    'Seconds remaining in terminationGracePeriodSeconds'
)

shutdown_phase_active = Gauge(
    'kubedash_shutdown_phase_active',
    'Which shutdown phase is currently active',
    ['phase']
)
```

### Prometheus Queries

```promql
# Current leaders still running during rollout
count(kubedash_is_leader{job="kubedash"} == 1)

# Average shutdown duration
histogram_quantile(0.99, rate(kubedash_shutdown_duration_seconds_bucket[5m]))

# Requests stuck during shutdown
kubedash_in_flight_requests{job="kubedash"} > 5

# Leadership release failures
rate(kubedash_shutdown_failed_total{error_type="leadership"}[5m])

# Drain timeout exceeded
rate(kubedash_request_drain_duration_seconds_bucket{le="+Inf"}[5m]) - 
rate(kubedash_request_drain_duration_seconds_bucket{le="20"}[5m])
```

### Grafana Dashboard

```json
{
  "dashboard": {
    "title": "KubeDash Graceful Shutdown",
    "timezone": "utc",
    "panels": [
      {
        "title": "Current In-Flight Requests",
        "targets": [
          {
            "expr": "kubedash_in_flight_requests"
          }
        ]
      },
      {
        "title": "Shutdown Duration (p99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(kubedash_shutdown_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Shutdown Failures (rate)",
        "targets": [
          {
            "expr": "rate(kubedash_shutdown_failed_total[5m])"
          }
        ]
      },
      {
        "title": "Request Drain Time (p95)",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(kubedash_request_drain_time_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "Leadership Release Time",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, rate(kubedash_leadership_release_time_seconds_bucket[5m]))"
          }
        ]
      }
    ]
  }
}
```

---

## Troubleshooting Guide

### Problem 1: Pod Stuck in "Terminating" State

**Symptoms:**
```
$ kubectl get pods
NAME           READY   STATUS        RESTARTS   AGE
kubedash-0     1/1     Terminating   0          5m
kubedash-1     1/1     Running       0          2m
```

**Diagnosis:**
```bash
# Check pod details
kubectl describe pod kubedash-0

# Check logs
kubectl logs kubedash-0 | tail -50

# Force delete (last resort only!)
kubectl delete pod kubedash-0 --grace-period=0 --force
```

**Root Causes & Fixes:**

1. **Shutdown endpoint not reachable**
   ```bash
   # Check if app is responding
   kubectl exec kubedash-0 -- curl -v http://localhost:8000/api/health/live
   
   # Fix: Ensure Flask app is running
   kubectl logs kubedash-0 | grep -E "ERROR|Traceback"
   ```

2. **Long-running requests not completing**
   ```bash
   # Check for stuck requests
   kubectl logs kubedash-0 | grep "in-flight"
   
   # Fix: Increase terminationGracePeriodSeconds
   # Or optimize slow queries
   ```

3. **Database connection not closing**
   ```bash
   # Check database connections
   kubectl exec postgres-0 -- psql -c \
     "SELECT count(*) FROM pg_stat_activity WHERE datname='kubedash';"
   
   # Fix: Ensure db.engine.dispose() is called
   ```

4. **Scheduler not stopping**
   ```bash
   # Check APScheduler status
   kubectl logs kubedash-0 | grep -i "scheduler\|apscheduler"
   
   # Fix: Add wait=True to scheduler.shutdown()
   ```

---

### Problem 2: Leadership Not Released to New Pod

**Symptoms:**
```
kubedash-0: ✅ Leadership released
kubedash-0 deleted...

kubedash-1: Still waiting for leadership
kubedash-2: Waiting for leadership...
```

**Diagnosis:**
```bash
# Check Kubernetes Lease
kubectl get leases -l app=kubedash

# Check leader election logs
kubectl logs kubedash-1 | grep -i "leader\|lease"

# Check RBAC permissions
kubectl auth can-i get leases --as=system:serviceaccount:default:kubedash-sa
```

**Root Causes & Fixes:**

1. **Leadership release not called**
   ```python
   # Check: GracefulShutdown._release_leadership() is called
   logger.info("Releasing leadership...")
   self.leader_elector.stop()  # Must be called
   ```

2. **preStop hook not executing**
   ```bash
   # Verify preStop hook in deployment
   kubectl get deployment kubedash -o yaml | grep -A 10 "preStop"
   
   # Test: Create dummy preStop
   command: ['sh', '-c', 'echo "preStop executed" && sleep 1']
   ```

3. **RBAC permissions missing**
   ```yaml
   # Verify ServiceAccount has lease permissions
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: kubedash-leader
   rules:
   - apiGroups: [""]
     resources: ["leases"]
     verbs: ["get", "delete"]
   ```

---

### Problem 3: Requests Timing Out During Shutdown

**Symptoms:**
```
kubedash-0: WARNING Shutdown timeout reached. 10 requests still in-flight.
Client: Connection reset by peer
```

**Diagnosis:**
```bash
# Check request duration
kubectl logs kubedash-0 | grep "X-Response-Time"

# Monitor database load
kubectl exec postgres-0 -- psql -c \
  "SELECT client_addr, query, now()-backend_start as duration FROM pg_stat_activity;"

# Check slow queries
kubectl exec postgres-0 -- psql -c \
  "SELECT query, calls, mean_exec_time FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"
```

**Root Causes & Fixes:**

1. **Requests are actually slow**
   ```bash
   # Optimize the slow query
   EXPLAIN (ANALYZE, BUFFERS) SELECT * FROM large_table WHERE status='pending';
   
   # Add indexes if needed
   CREATE INDEX idx_large_table_status ON large_table(status);
   ```

2. **Timeout too short**
   ```yaml
   # Increase terminationGracePeriodSeconds
   spec:
     terminationGracePeriodSeconds: 60  # was 30
   ```

3. **Requests not draining properly**
   ```bash
   # Check graceful shutdown logs
   kubectl logs kubedash-0 | grep "in-flight"
   
   # Should see: "0 requests in-flight" eventually
   # Or: "Timeout reached"
   ```

**Solution:**
```python
# Add request timeout
@app.route('/api/v1/cluster/info')
def get_cluster_info():
    """Get cluster info with query timeout"""
    try:
        # Set query timeout to 5 seconds
        db.session.execute(text("SET LOCAL statement_timeout = 5000"))
        
        result = expensive_query()
        return result
    
    except Exception:
        # Timeout: fall back to cached result
        return get_cached_cluster_info()
```

---

### Problem 4: Zero In-Flight Requests but Pod Still Terminating

**Symptoms:**
```
kubedash-0: ✅ In-flight requests drained
kubedash-0: Waiting...
kubedash-0: (pod still terminating after 10 more seconds)
```

**Diagnosis:**
```bash
# Check if process is still running
kubectl exec kubedash-0 -- ps aux | grep python

# Check for zombie processes
kubectl exec kubedash-0 -- ps aux | grep defunct

# Check for open pipes/sockets
kubectl exec kubedash-0 -- lsof -p $(pgrep -f "python app.py")
```

**Root Causes & Fixes:**

1. **Background threads not stopping**
   ```python
   # Fix: Mark threads as daemon or join before exit
   cleanup_thread = threading.Thread(target=cleanup, daemon=True)
   cleanup_thread.start()
   cleanup_thread.join(timeout=5)  # Wait up to 5 seconds
   ```

2. **Child processes not terminating**
   ```bash
   # Check child processes
   kubectl exec kubedash-0 -- ps auxf | head -20
   
   # Kill child processes before exit
   pkill -P $$ || true
   ```

3. **File descriptors not closed**
   ```python
   # Fix: Explicitly close all resources
   try:
     pass  # ... cleanup code ...
   finally:
     sys.exit(0)  # Force exit after cleanup
   ```

---

### Problem 5: APScheduler Jobs Still Running During Shutdown

**Symptoms:**
```
kubedash-0: Stopping APScheduler...
kubedash-0: ✅ Scheduler stopped
kubedash-0: (scheduled job still running in background)
```

**Diagnosis:**
```bash
# Check if scheduler.shutdown() is blocking
kubectl logs kubedash-0 | grep -A 5 "Stopping APScheduler"

# Check for job errors
kubectl logs kubedash-0 | grep "Exception in scheduler"
```

**Root Causes & Fixes:**

1. **Scheduler.shutdown(wait=False)**
   ```python
   # Fix: Use wait=True to wait for jobs to complete
   scheduler.shutdown(wait=True)  # Default is False!
   ```

2. **Job execution error preventing completion**
   ```python
   # Add error handling in job
   @scheduler.scheduled_job('interval', seconds=60, id='my_job')
   def my_job():
       try:
           # ... job code ...
       except Exception:
           logger.error("Job error", exc_info=True)
           # Don't re-raise, let scheduler continue
   ```

3. **Job takes too long to complete**
   ```python
   # Add job timeout
   max_instances = 1
   job_defaults = {
       'coalesce': True,
       'max_instances': 1,
   }
   scheduler.configure(job_defaults=job_defaults)
   ```

---

## Verification Checklist

### Before Deploying to Production

- [ ] **Graceful Shutdown Library Installed**
  ```bash
  python -c "from lib.shutdown import GracefulShutdown; print('✅ OK')"
  ```

- [ ] **Shutdown Endpoint Responds**
  ```bash
  curl -X POST http://localhost:8000/api/shutdown -v
  # Should return 200 immediately
  ```

- [ ] **Health Probes Configured**
  ```bash
  curl http://localhost:8000/api/health/ready
  # Should return 200 when ready
  # Should return 503 during shutdown
  ```

- [ ] **preStop Hook Configured**
  ```bash
  kubectl get deployment kubedash -o yaml | grep -A 10 "preStop"
  # Should have curl command or similar
  ```

- [ ] **RBAC Permissions**
  ```bash
  kubectl auth can-i get leases --as=system:serviceaccount:default:kubedash-sa
  # Should return: yes
  ```

- [ ] **terminationGracePeriodSeconds Set**
  ```bash
  kubectl get deployment kubedash -o yaml | grep "terminationGracePeriodSeconds"
  # Should be >= 30
  ```

### During Deployment Test

- [ ] **Pod removes from load balancer**
  - Check readiness probe returns 503 immediately
  - Service removes endpoint from pool within 5 seconds

- [ ] **Leadership released quickly**
  - `kubectl logs | grep -i "leadership"` shows < 1 second

- [ ] **Requests drain without errors**
  - Load test generates requests during deletion
  - No HTTP 503 errors or connection resets

- [ ] **Pod terminates gracefully**
  - `kubectl describe pod | grep STATE` shows Terminated
  - Not showing `Failed` or `OOMKilled`

- [ ] **No errors in logs**
  - `kubectl logs | grep ERROR` returns nothing
  - All phases show ✅ success

### Monitoring in Production

- [ ] **Shutdown Metrics**
  ```promql
  # Dashboard shows shutdown duration trend
  histogram_quantile(0.99, rate(kubedash_shutdown_duration_seconds_bucket[5m]))
  # Should be < 10 seconds normally
  ```

- [ ] **Failure Alerts**
  ```yaml
  # Alert on shutdown failures
  - alert: KubeDashShutdownFailing
    expr: rate(kubedash_shutdown_failed_total[5m]) > 0
    annotations:
      summary: "KubeDash shutdown failing"
  ```

- [ ] **Stuck Request Alerts**
  ```yaml
  # Alert on requests stuck during shutdown
  - alert: KubeDashRequestsDrainTimeout
    expr: kubedash_in_flight_requests{job="kubedash"} > 10
    for: 25s
  ```

---

## Performance Targets

| Phase | Target | Alert Threshold |
|-------|--------|-----------------|
| Leadership Release | < 1s | > 2s |
| Stop Accepting Requests | < 0.5s | > 1s |
| Request Drain | < 15s | > 20s |
| Stop Scheduler | < 1s | > 2s |
| Run Handlers | < 2s | > 5s |
| Close Database | < 1s | > 2s |
| **Total** | **< 20s** | **> 28s** |

---

## Common Log Patterns

### Healthy Shutdown
```
INFO 🛑 Graceful shutdown initiated (timeout: 30s)
INFO → Phase: release_leadership...
INFO   ✅ release_leadership complete (0.12s)
INFO → Phase: stop_requests...
INFO   ✅ stop_requests complete (0.01s)
INFO → Phase: drain_requests...
DEBUG  4 requests in-flight (25.0s remaining)
DEBUG  2 requests in-flight (24.5s remaining)
DEBUG  0 requests in-flight (24.0s remaining)
INFO   ✅ drain_requests complete (1.02s)
INFO → Phase: stop_scheduler...
INFO   ✅ stop_scheduler complete (0.08s)
INFO → Phase: run_handlers...
INFO   ✅ run_handlers complete (0.15s)
INFO → Phase: close_database...
INFO   ✅ close_database complete (0.34s)
INFO ✅ Graceful shutdown completed in 1.72s
```

### Unhealthy Shutdown
```
WARNING Received signal 15. Starting graceful shutdown...
INFO → Phase: release_leadership...
ERROR   ❌ Error in release_leadership: Connection refused
WARNING ⏱️  Timeout reached during release_leadership phase
INFO → Phase: stop_requests...
INFO   ✅ stop_requests complete
INFO → Phase: drain_requests...
WARNING Shutdown timeout reached. 5 requests still in-flight.
ERROR   ❌ Error in drain_requests: Timeout
```

---

## Debug Mode

Enable debug logging to troubleshoot:

```bash
# Set log level
export LOG_LEVEL=DEBUG

# Start app with debug
python app.py --log-level=DEBUG

# In Kubernetes
kubectl set env deployment/kubedash LOG_LEVEL=DEBUG

# Watch logs
kubectl logs -f kubedash-0 | grep -E "shutdown|in-flight|leadership"
```

---

## Emergency Procedures

### Force Delete Pod (Last Resort)

```bash
# Do NOT do this normally
# Only if pod is stuck > 60 seconds

kubectl delete pod kubedash-0 --grace-period=0 --force

# Check what happened
kubectl logs kubedash-0 --tail=50
```

### Restart Leader Election

```bash
# If locked on same leader
kubectl delete lease kubedash-leader

# New leader will be elected immediately
kubectl logs -f kubedash-1 | grep -i leader
```

### Verify Clean Shutdown

```bash
# Get exit code of last shutdown
kubectl describe pod kubedash-0 | grep -A 5 "Last State"

# Exit code 0 = clean shutdown ✅
# Exit code 137 = SIGKILL ❌
# Exit code 1 = error ❌
```
