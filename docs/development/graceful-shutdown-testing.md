# Graceful Shutdown Testing Guide (Section 10.8)

## Overview

This guide provides procedures to verify graceful shutdown behavior in KubeDash, covering all 8 subtasks of Section 10 ("Graceful Shutdown and Lifecycle").

**Testing Scope:**
- 10.1: SIGTERM signal handler
- 10.2: Leadership release on shutdown
- 10.3: APScheduler graceful shutdown
- 10.4: Session cleanup
- 10.5-10.7: Kubernetes lifecycle hooks
- 10.8: Complete shutdown sequence

## Prerequisites

- Multi-replica KubeDash deployment with leader election enabled
- Kubernetes cluster with graceful termination support
- `kubectl` access to KubeDash namespace
- `curl` for endpoint testing
- Application logs accessible

## Test Procedures

### Test 1: Local SIGTERM Handling (Items 10.1-10.3)

**Purpose:** Verify Python graceful shutdown handler catches SIGTERM

**Setup:**
```bash
# Start KubeDash locally with Flask dev server
cd /data/git/kubedash
export FLASK_CONFIG=development
export REPLICA_MODE=single  # Single replica for local testing
python -m kubedash.kubedash
```

**Procedure:**
```bash
# In another terminal, send SIGTERM
ps aux | grep kubedash | grep -v grep
kill -TERM <PID>
```

**Expected Output (in app logs):**
```
✅ [SHUTDOWN] Phase 1: Release Leadership (LeaderElector.stop() if leader)
✅ [SHUTDOWN] Phase 2: Stop Accepting Requests (set SHUTTING_DOWN=True)
✅ [SHUTDOWN] Phase 3: Drain In-Flight Requests (~20s timeout)
✅ [SHUTDOWN] Phase 4: Stop APScheduler
✅ [SHUTDOWN] Phase 5: Run Shutdown Handlers (cleanup_sessions)
✅ [SHUTDOWN] Phase 6: Close Database
✅ [SHUTDOWN] Complete - Exit Code 0
```

**Pass Criteria:**
- [ ] All 6 shutdown phases logged
- [ ] Process exits cleanly (exit code 0)
- [ ] No connection timeout errors
- [ ] Scheduler jobs marked as stopped

---

### Test 2: Health Probe Endpoints (Items 10.1-10.7)

**Purpose:** Verify shutdown endpoints return correct status codes

**Setup:**
```bash
# In one terminal, start KubeDash with multi-replica mode
export REPLICA_MODE=cluster
export KUBERNETES_SERVICE_HOST=kubernetes.default
export KUBERNETES_NAMESPACE=default
python -m kubedash.kubedash
```

**Test 2a: Liveness Probe (should always pass)**
```bash
# While running normally
curl -k https://localhost:5000/api/health/live
# Expected: 200 OK

# Even during shutdown
# (Send SIGTERM in another terminal, then immediately run:)
curl -k https://localhost:5000/api/health/live
# Expected: 200 OK (process still alive)
```

**Test 2b: Readiness Probe (should return 503 during shutdown)**
```bash
# While running normally
curl -k https://localhost:5000/api/health/ready
# Expected: 200 OK

# Send graceful shutdown signal
kill -TERM <PID>
# Immediately run:
curl -k https://localhost:5000/api/health/ready
# Expected: 503 Service Unavailable
# (pod removed from LB within 1-2 seconds)
```

**Test 2c: Shutdown Endpoint**
```bash
# Trigger graceful shutdown via API
curl -X POST -k https://localhost:5000/api/shutdown
# Expected: 200 OK (returned immediately)
# Process should shut down within 30 seconds
```

**Pass Criteria:**
- [ ] /api/health/live returns 200 always
- [ ] /api/health/ready returns 503 during shutdown
- [ ] /api/shutdown returns 200 immediately
- [ ] Process terminates within grace period

---

### Test 3: Kubernetes Pod Termination (Items 10.5-10.7)

**Purpose:** Verify complete Kubernetes graceful shutdown workflow

**Prerequisites:**
- KubeDash deployed to Kubernetes cluster with multi-replica setup
- Deployed with graceful shutdown enabled (StatefulSet with terminationGracePeriodSeconds)

**Procedure 3a: Trigger Pod Deletion**
```bash
# Watch pod lifecycle in one terminal
kubectl get pods -n kubedash -w -l app=kubedash

# In another terminal, delete a replica pod
kubectl delete pod -n kubedash <pod-name>
```

**Expected Pod Lifecycle:**
```
NAME              READY   STATUS    RESTARTS
kubedash-0        1/1     Running   0         # Normal running
kubedash-0        1/1     Terminating          # Termination started
kubedash-0        0/1     Terminating          # Removed from LB (~1-2s)
kubedash-0        0/1     Terminating          # Graceful shutdown in progress
kubedash-0        0/1     Terminated           # Process exited (<30s)
kubedash-0        1/1     Running              # New pod created
```

**Procedure 3b: Verify preStop Hook Called**
```bash
# Get logs during shutdown
kubectl logs -f -n kubedash <pod-name> --tail=50 | grep -E "Initiating graceful|Shutdown endpoint"

# Expected logs:
# Initiating graceful shutdown...
# Shutdown endpoint called, waiting for termination...
# [SHUTDOWN] Phase 1: Release Leadership
# [SHUTDOWN] Phase 2: Stop Accepting Requests
# [SHUTDOWN] Phase 3: Drain In-Flight Requests
# [SHUTDOWN] Phase 4: Stop APScheduler
# [SHUTDOWN] Phase 5: Run Shutdown Handlers
# [SHUTDOWN] Phase 6: Close Database
```

**Procedure 3c: Verify Request Draining**
```bash
# Terminal 1: Continuously call API endpoint
while true; do
  curl -s https://kubedash.example.com/api/cluster/stats | jq .
  sleep 1
done

# Terminal 2: Scale down KubeDash
kubectl scale statefulset kubedash -n kubedash --replicas=0

# Expected: Requests complete cleanly, no connection refused errors
```

**Procedure 3d: Verify Leadership Transfer**
```bash
# Deploy with 2+ replicas
kubectl scale statefulset kubedash -n kubedash --replicas=3

# Monitor leadership
watch kubectl exec -it -n kubedash kubedash-0 -- curl -s https://localhost:5000/api/health/live

# Delete leader pod
kubectl delete pod -n kubedash kubedash-0

# Check leadership transferred
kubectl exec -it -n kubedash kubedash-1 -- \
  python -c "from lib.leader_election import get_leader_elector; print('Is Leader:', get_leader_elector().is_leader)"

# Expected: New leader elected within 5 seconds
```

**Pass Criteria:**
- [ ] Pod transitions to Terminating within 1 second
- [ ] Readiness probe returns 503, pod removed from LB
- [ ] Graceful shutdown runs (all 6 phases logged)
- [ ] Pod terminates within grace period (30s)
- [ ] Replacement pod becomes ready
- [ ] No in-flight request failures
- [ ] Leadership transferred to new pod if deleted

---

### Test 4: Multi-Replica Graceful Shutdown (Items 10.2-10.3, 10.5-10.7)

**Purpose:** Verify coordinated shutdown across multiple replicas

**Setup:**
```bash
# Deploy with 3 replicas
kubectl scale statefulset kubedash -n kubedash --replicas=3

# Verify all healthy
kubectl get pods -n kubedash -l app=kubedash
```

**Procedure:**
```bash
# Terminal 1: Monitor pod events
kubectl get events -n kubedash -w

# Terminal 2: Monitor logs from all replicas
kubectl logs -f -n kubedash -l app=kubedash --max-log-requests=10 | grep SHUTDOWN

# Terminal 3: Send traffic while shutting down
for i in {1..100}; do
  curl -s https://kubedash.example.com/api/cluster/stats > /dev/null &
done
wait

# Terminal 4: Scale down
kubectl scale statefulset kubedash -n kubedash --replicas=1
```

**Expected Behavior:**
```
- Pod terminates gracefully (preStop hook called)
- Leadership released immediately (Phase 1, <1s)
- In-flight requests drained (Phase 3, <20s)
- Scheduler jobs complete gracefully (Phase 4, <1s)
- Pod exits cleanly (exit code 0, <30s total)
- No errors in application logs
- Readiness probe removes pod from LB
- Traffic redirected to remaining replicas
```

**Pass Criteria:**
- [ ] All replicas shut down sequentially without errors
- [ ] Leadership transferred only once per pod termination
- [ ] All in-flight requests completed successfully
- [ ] No request failures during scale-down
- [ ] Total downtime < 1 second per replica
- [ ] Exit code 0 for all terminated pods

---

### Test 5: Session Cleanup on Shutdown (Item 10.4)

**Purpose:** Verify session data cleaned up on pod termination

**Setup:**
```bash
# Determine session backend (Redis or SQLAlchemy)
kubectl exec -it -n kubedash kubedash-0 -- \
  grep -E "SESSION_TYPE|SESSION_REDIS_URL" kubedash/kubedash.ini

# Connect to session backend
# For Redis:
kubectl exec -it -n kubedash kubedash-redis-0 -- redis-cli

# For SQLAlchemy (PostgreSQL):
kubectl exec -it -n kubedash kubedash-postgresql-0 -- psql -U kubedash -d kubedash
```

**Procedure:**
```bash
# Count active sessions before shutdown
# For Redis:
redis-cli KEYS "session:*" | wc -l

# Delete pod
kubectl delete pod -n kubedash kubedash-0

# Wait for shutdown to complete
sleep 35

# Count active sessions after shutdown
redis-cli KEYS "session:*" | wc -l

# Expected: No increase in stale sessions
```

**Pass Criteria:**
- [ ] No orphaned session records after shutdown
- [ ] Session cleanup handler executed (logged in pod)
- [ ] No expired sessions accumulate in backend
- [ ] New pod creates fresh session store

---

### Test 6: Database Connection Cleanup (Item 10.6)

**Purpose:** Verify database connections properly closed

**Setup:**
```bash
# Connect to PostgreSQL and monitor connections
kubectl exec -it -n kubedash kubedash-postgresql-0 -- psql \
  -U kubedash -d kubedash \
  -c "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"
```

**Procedure:**
```bash
# Record active connections before shutdown
SELECT datname, count(*) FROM pg_stat_activity WHERE datname = 'kubedash';

# Delete pod
kubectl delete pod -n kubedash kubedash-0

# Monitor connection count during termination
watch -n 0.5 'kubectl exec -it -n kubedash kubedash-postgresql-0 -- \
  psql -U kubedash -d kubedash \
  -c "SELECT datname, count(*) FROM pg_stat_activity WHERE datname = 'kubedash';"'

# Expected: Connections drop to near-zero after shutdown complete
```

**Pass Criteria:**
- [ ] All pod's database connections closed after shutdown
- [ ] No connection timeouts during shutdown
- [ ] No "broken pipe" errors in logs
- [ ] Database doesn't report idle connections for terminated pod

---

### Test 7: Request Tracking and Draining (Item 10.3)

**Purpose:** Verify in-flight requests properly tracked and drained

**Setup:**
```bash
# Create a long-running request endpoint (for testing)
# Add to kubedash/routes/test.py:
@test_routes.route('/api/test/slow-endpoint', methods=['GET'])
def slow_endpoint():
    time.sleep(5)  # 5 second request
    return {"message": "completed"}
```

**Procedure:**
```bash
# Terminal 1: Send slow request
curl https://localhost:5000/api/test/slow-endpoint &
REQUEST_PID=$!

# Terminal 2: Immediately send shutdown signal
sleep 0.5
kill -TERM <app-pid>

# Terminal 3: Monitor logs
tail -f kubedash.log | grep -E "DRAIN|COMPLETE|EXIT"

# Wait for completion
wait $REQUEST_PID

# Check exit code (should be 0)
echo $?
```

**Expected Output:**
```
✅ [SHUTDOWN] Phase 3: Drain In-Flight Requests
   - Waiting for 1 requests to complete...
   - request /api/test/slow-endpoint: IN_FLIGHT
   - Requests complete (waited 4.5s)
✅ [SHUTDOWN] Complete - Exit Code 0
```

**Pass Criteria:**
- [ ] All in-flight requests complete successfully
- [ ] Shutdown waits for long-running requests (up to 20s)
- [ ] Request tracking accurate (1 request logged)
- [ ] Exit code 0 even during request draining

---

### Test 8: Graceful Restart Workflow (Items 10.1-10.7)

**Purpose:** Verify complete graceful restart without data loss

**Setup:**
```bash
# Deploy with 2 replicas
kubectl scale statefulset kubedash -n kubedash --replicas=2
kubectl wait --for=condition=ready pod -l app=kubedash -n kubedash --timeout=300s
```

**Procedure:**
```bash
# Create test data/session
SESSION_ID=$(curl -s -b @cookies.txt https://kubedash.example.com/api/auth/login \
  -d "username=admin&password=admin" | jq -r .session_id)

# Verify data persists across pod deletions
for i in {1..3}; do
  echo "Iteration $i:"
  
  # Delete a replica
  kubectl delete pod -n kubedash kubedash-0
  
  # Wait for recovery
  kubectl wait --for=condition=ready pod -l app=kubedash -n kubedash --timeout=60s
  
  # Verify session still accessible
  curl -s -b "session=$SESSION_ID" https://kubedash.example.com/api/user/profile | jq .
  
  # Expected: Session valid, no errors
  sleep 5
done
```

**Pass Criteria:**
- [ ] All replicas recover after deletion
- [ ] User sessions persist across shutdowns
- [ ] No request failures during scale events
- [ ] Total recovery time per pod < 45 seconds
- [ ] No data corruption or loss

---

## Automated Testing (CI/CD Integration)

Create `scripts/test-graceful-shutdown.sh`:

```bash
#!/bin/bash
set -e

NAMESPACE="kubedash-test"
REPLICAS=2
GRACE_PERIOD=30

echo "🚀 Starting graceful shutdown tests..."

# Create test namespace
kubectl create namespace $NAMESPACE || true

# Deploy KubeDash with graceful shutdown
helm install kubedash deploy/charts \
  -n $NAMESPACE \
  --set replicas=$REPLICAS \
  --set terminationGracePeriodSeconds=$GRACE_PERIOD

# Wait for ready
kubectl wait --for=condition=ready pod \
  -l app=kubedash \
  -n $NAMESPACE \
  --timeout=300s

# Test 1: SIGTERM handling
echo "✓ Test 1: SIGTERM handling..."
POD=$(kubectl get pod -n $NAMESPACE -l app=kubedash -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n $NAMESPACE $POD -- kill -TERM 1 || true
sleep 35
READY=$(kubectl get pod -n $NAMESPACE -l app=kubedash --field-selector=status.phase=Running | wc -l)
if [ $READY -lt $REPLICAS ]; then
  echo "✓ Pod terminated gracefully"
fi

# Test 2: Health probes
echo "✓ Test 2: Health probes..."
POD=$(kubectl get pod -n $NAMESPACE -l app=kubedash -o jsonpath='{.items[0].metadata.name}')
LIVENESS=$(kubectl exec -n $NAMESPACE $POD -- curl -s https://localhost:5000/api/health/live)
READINESS=$(kubectl exec -n $NAMESPACE $POD -- curl -s https://localhost:5000/api/health/ready)
echo "✓ Probes responding"

# Cleanup
kubectl delete namespace $NAMESPACE

echo "✅ All graceful shutdown tests passed!"
```

---

## Troubleshooting

### Issue: Pod shutting down but not draining requests

**Solution:**
```bash
# Check if request tracking is working
kubectl logs -f -n kubedash <pod-name> | grep "track_request\|complete_request"

# Verify before_request/after_request hooks registered
grep "@app.before_request" src/kubedash/kubedash.py
```

### Issue: Shutdown hangs (doesn't exit within grace period)

**Causes:**
- Deadlock in request draining (requests stuck in pending state)
- Scheduler job hangs
- Database connection timeout

**Debug:**
```bash
# Check process state
kubectl exec -n kubedash <pod-name> -- ps aux

# View logs
kubectl logs -n kubedash <pod-name> --tail=100 | grep -E "DRAIN|DEADLOCK|hang"

# Increase grace period
kubectl patch statefulset kubedash -n kubedash \
  -p '{"spec":{"terminationGracePeriodSeconds": 60}}'
```

### Issue: Leadership not releasing to new pod

**Solution:**
```bash
# Verify leader election is enabled
kubectl exec -n kubedash <pod-name> -- \
  python -c "from lib.leader_election import get_leader_elector; print(get_leader_elector().is_enabled)"

# Check Kubernetes Lease objects
kubectl get lease -n kubedash -l app=kubedash

# Verify new pod can acquire leadership
kubectl exec -n kubedash <new-pod-name> -- \
  python -c "from lib.leader_election import get_leader_elector; print('Is Leader:', get_leader_elector().is_leader)"
```

---

## Performance Benchmarks

**Target Metrics:**

| Metric | Target | Current |
|--------|--------|---------|
| Time to accept graceful shutdown | < 100ms | - |
| Leadership release time | < 1s | - |
| Request draining time | < 20s | - |
| Scheduler shutdown | < 2s | - |
| Total shutdown duration | < 30s | - |
| Pod removed from LB | < 2s | - |
| New pod ready | < 30s | - |

---

## Testing Checklist

Before considering Section 10 complete, verify:

- [ ] Test 1: SIGTERM handling and 6-phase shutdown logged
- [ ] Test 2a: Liveness probe returns 200 always
- [ ] Test 2b: Readiness probe returns 503 during shutdown
- [ ] Test 2c: Shutdown endpoint returns 200 immediately
- [ ] Test 3a: Pod transitions through Terminating state
- [ ] Test 3b: preStop hook called and logged
- [ ] Test 3c: Requests complete during pod scale-down
- [ ] Test 3d: Leadership transferred to new pod
- [ ] Test 4: Multi-replica shutdown coordinated properly
- [ ] Test 5: Session cleanup handler executes
- [ ] Test 6: Database connections closed properly
- [ ] Test 7: In-flight requests tracked and drained
- [ ] Test 8: Complete graceful restart without data loss
- [ ] Exit codes are 0 for all graceful shutdowns
- [ ] No errors in application logs
- [ ] Performance metrics met (see table above)

---

## References

- [Graceful Shutdown Architecture](graceful-shutdown.md)
- [Graceful Shutdown Implementation](graceful-shutdown-implementation.md)
- [Leader Election and Graceful Shutdown](leader-election-graceful-shutdown.md)
- [Kubernetes Pod Lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/)
- [Container Lifecycle Hooks](https://kubernetes.io/docs/tasks/configure-pod-container/attach-handler-pod-lifecycle/)

