# Graceful Shutdown Deployment Checklist & Guide

## Pre-Implementation Checklist

### Analysis Phase
- [ ] Review current shutdown behavior
- [ ] Identify critical in-flight requests
- [ ] Measure average request duration
- [ ] Check database connection pool size
- [ ] Review APScheduler configured jobs
- [ ] Audit current session storage (Redis/DB)

### Design Phase
- [ ] Define termination grace period (30-60s recommended)
- [ ] Plan leadership release strategy
- [ ] Design readiness/liveness probe strategy
- [ ] Plan monitoring and alerting
- [ ] Review edge cases (long-running requests, locked DB, etc.)
- [ ] Get stakeholder sign-off on downtime risks

---

## Implementation Roadmap

### Phase 1: Core Graceful Shutdown (Week 1)

**Files to Create:**
```
src/kubedash/
├── lib/shutdown.py           # NEW - Core shutdown logic
├── routes/shutdown.py        # NEW - Shutdown endpoints
└── lib/session_cleanup.py    # NEW - Session cleanup

Deploy files:
├── templates/deployment.yaml # UPDATE - Add preStop hook
└── values.yaml              # UPDATE - Add termination settings
```

**Implementation Steps:**

1. **Create Shutdown Library**
   ```bash
   # Create src/kubedash/lib/shutdown.py
   # - GracefulShutdown class
   # - Signal handlers
   # - Shutdown phases
   # - Request tracking
   ```

2. **Create Shutdown Endpoint**
   ```bash
   # Create src/kubedash/routes/shutdown.py
   # - POST /api/shutdown endpoint
   # - Health check endpoints
   ```

3. **Integrate with Flask App**
   ```bash
   # Update src/kubedash/app.py
   # - Initialize graceful_shutdown
   # - Add request tracking middleware
   # - Register shutdown handlers
   ```

4. **Update Kubernetes Deployment**
   ```bash
   # Update deploy/kubedash/templates/deployment.yaml
   # - Add preStop hook (curl /api/shutdown)
   # - Add readiness probe
   # - Add terminationGracePeriodSeconds
   # - Add pod name/namespace env vars
   ```

5. **Testing**
   ```bash
   # Create tests/test-graceful-shutdown.sh
   # - Test signal handling
   # - Test shutdown endpoint
   # - Test request draining
   # - Test clean exit
   ```

**Deployment:**
```bash
# 1. Develop and test locally
python tests/test-graceful-shutdown.sh

# 2. Deploy to dev/staging
kubectl apply -f deploy/kubedash/

# 3. Watch logs during scale down
kubectl logs -f kubedash-0 | grep -i shutdown

# 4. Verify exit codes
kubectl describe pod <old-pod-name> | grep -A 3 "Last State"
```

**Success Criteria:**
- [ ] Pod terminates within 30 seconds on delete
- [ ] Exit code is 0 in logs
- [ ] All shutdown phases execute
- [ ] No 503 errors in load test
- [ ] Readiness probe returns 503 during shutdown

---

### Phase 2: Leader Election (Week 2)

**Files to Create:**
```
src/kubedash/
├── lib/leader_elector.py     # NEW - Kubernetes lease-based election
└── lib/scheduler.py          # UPDATE - Leader-only job handling

Deploy files:
├── rbac-role.yaml            # NEW - Lease API permissions
└── rbac-rolebinding.yaml     # NEW - ServiceAccount binding
```

**Implementation Steps:**

1. **Create Leader Election Library**
   ```bash
   # Create src/kubedash/lib/leader_elector.py
   # - KubernetesLeaderElector class
   # - Lease API client
   # - Renew and watch loops
   # - Callbacks for state changes
   ```

2. **Integrate with App**
   ```bash
   # Update src/kubedash/app.py
   # - Initialize leader_elector
   # - Register on_became_leader callback
   # - Register on_lost_leadership callback
   # - Pass to graceful_shutdown
   ```

3. **Configure RBAC**
   ```bash
   # Create deploy/rbac/
   # - ServiceAccount for kubedash
   # - Role for coordination.k8s.io/leases
   # - RoleBinding connecting them
   ```

4. **Update Deployment**
   ```bash
   # Update deploy/kubedash/templates/deployment.yaml
   # - Reference ServiceAccount
   # - Set automountServiceAccountToken: true
   # - Set POD_NAME and POD_NAMESPACE env vars
   ```

5. **Testing**
   ```bash
   # Create tests/test-leader-election.sh
   # - Test initial leader election
   # - Test leadership transitions on pod delete
   # - Test new leader continuity
   ```

**Deployment:**
```bash
# 1. Apply RBAC first
kubectl apply -f deploy/rbac/

# 2. Deploy with leader election
kubectl apply -f deploy/kubedash/

# 3. Monitor logs
kubectl logs -f kubedash-0 | grep -E "leader|BECAME|LOST"

# 4. Test leadership change
kubectl delete pod kubedash-0
kubectl logs -f kubedash-1  # Should see "BECAME LEADER"
```

**Success Criteria:**
- [ ] One leader elected on startup
- [ ] New leader elected within 5 seconds when leader deleted
- [ ] Leadership transitions logged clearly
- [ ] Lease persists in Kubernetes API
- [ ] RBAC errors in logs = 0

---

### Phase 3: Monitoring & Alerting (Week 3)

**Files to Create:**
```
monitoring/
├── prometheus-rules.yaml      # NEW - Alert rules
├── grafana-dashboards.yaml    # NEW - Grafana dashboard
└── service-monitor.yaml       # NEW - Prometheus scrape config
```

**Implementation Steps:**

1. **Add Prometheus Metrics**
   ```bash
   # Update src/kubedash/lib/metrics.py
   # - shutdown_initiated_total
   # - shutdown_successful_total
   # - shutdown_failed_total
   # - shutdown_duration_seconds
   # - in_flight_requests
   # - leadership_transitions_total
   ```

2. **Create Alert Rules**
   ```bash
   # Create monitoring/prometheus-rules.yaml
   # - KubeDashShutdownTimeout (> 30s)
   # - KubeDashNoLeader (> 30s)
   # - KubeDashLeadershipFlapping (> 0.5/min)
   # - KubeDashShutdownFailing (failures > 0)
   ```

3. **Create Dashboard**
   ```bash
   # Create monitoring/grafana-dashboards.yaml
   # - In-flight requests gauge
   # - Shutdown duration histogram
   # - Leadership state indicator
   # - Error rate chart
   ```

4. **Deploy Monitoring**
   ```bash
   kubectl apply -f monitoring/
   ```

**Success Criteria:**
- [ ] Metrics scraped by Prometheus
- [ ] Dashboard displays shutdown metrics
- [ ] Alerts fire on failures
- [ ] Historical data retained > 30 days

---

### Phase 4: Documentation (Week 3-4)

**Files Already Created:**
```
docs/operations/
├── graceful-shutdown.md                    # ✅ Overview & architecture
├── graceful-shutdown-implementation.md     # ✅ Code implementation
├── graceful-shutdown-troubleshooting.md    # ✅ Troubleshooting guide
└── leader-election-graceful-shutdown.md    # ✅ Leader election details
```

**Additional Documentation:**
- [ ] Runbook for responding to shutdown failures
- [ ] Capacity planning guide (grace period calculation)
- [ ] Migration guide from current to graceful shutdown
- [ ] FAQ with common questions

---

## Step-by-Step Deployment

### Local Development & Testing

```bash
# 1. Start with Phase 1 (Core Graceful Shutdown)
cd /data/git/kubedash

# 2. Create lib/shutdown.py (copy from implementation docs)
cat > src/kubedash/lib/shutdown.py <<'EOF'
# [... contents from graceful-shutdown-implementation.md ...]
EOF

# 3. Create routes/shutdown.py
cat > src/kubedash/routes/shutdown.py <<'EOF'
# [... contents from graceful-shutdown-implementation.md ...]
EOF

# 4. Update app.py with request tracking
# (see graceful-shutdown-implementation.md for code)

# 5. Run local tests
bash tests/test-graceful-shutdown.sh

# 6. Verify output
# Should see: ✅ Graceful shutdown test PASSED
```

### Staging Environment

```bash
# Prerequisites
export KUBE_CONTEXT=staging

# 1. Create namespace and RBAC (if needed)
kubectl create namespace kubedash-staging
kubectl apply -f deploy/rbac/ -n kubedash-staging

# 2. Deploy with graceful shutdown
helm upgrade --install kubedash deploy/kubedash/ \
  --namespace kubedash-staging \
  --values deploy/kubedash/values-staging.yaml \
  --set shutdownGracePeriodSeconds=30 \
  --set replicaCount=3

# 3. Verify pods are running
kubectl get pods -n kubedash-staging

# 4. Run smoke tests
kubectl run load-gen --image=curlimages/curl -- \
  sh -c 'for i in {1..100}; do \
    curl http://kubedash:8000/api/v1/cluster/mode && sleep 0.1; \
  done &
  sleep 5 && \
  exit 0' \
  -n kubedash-staging

# 5. Delete a pod during load
kubectl delete pod kubedash-0 -n kubedash-staging

# 6. Observe in logs
kubectl logs -f kubedash-0 -n kubedash-staging | \
  grep -E "shutdown|leadership|request"

# 7. Verify graceful shutdown success
# Check exit code in pod describe
kubectl describe pod <old-pod-name> -n kubedash-staging | \
  grep -A 5 "Last State"
```

### Production Deployment

**Pre-Deployment Checklist:**
- [ ] All tests passing in staging
- [ ] Performance benchmarks acceptable
- [ ] Monitoring and alerts configured
- [ ] Team trained on graceful shutdown behavior
- [ ] Runbook documented and reviewed
- [ ] Canary deployment plan in place

**Deployment:**
```bash
# 1. Canary: Deploy to 1 pod first
helm upgrade kubedash deploy/kubedash/ \
  --set replicaCount=1 \
  --wait

# 2. Monitor for 1-2 hours
# Watch: logs, metrics, alerts

# 3. Gradual rollout
helm upgrade kubedash deploy/kubedash/ \
  --set replicaCount=3 \
  --wait

# 4. Run end-to-end tests
bash tests/test-leader-election.sh
bash tests/test-graceful-shutdown-production.sh

# 5. Monitor dashboard (1 week)
# Verify:
# - Shutdown duration < 15s average
# - No failures
# - Leadership stable
# - Request drain successful 100%
```

---

## Configuration Reference

### Kubernetes Deployment Values

```yaml
# deploy/kubedash/values.yaml

# Shutdown configuration
terminationGracePeriodSeconds: 30  # Max time for graceful shutdown

# Probe configuration
readinessProbe:
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 2
  timeoutSeconds: 3

livenessProbe:
  initialDelaySeconds: 30
  periodSeconds: 10
  failureThreshold: 3
  timeoutSeconds: 3

# Replica count for leader election
replicaCount: 3

# APScheduler configuration
scheduler:
  enabled: true
  coalesce: true
  maxInstances: 1

# Graceful shutdown specific
gracefulShutdown:
  enabled: true
  timeoutSeconds: 30
  preStopHookTimeout: 28
  requestDrainTimeout: 20
```

### Environment Variables

```bash
# Container env vars for graceful shutdown
POD_NAME                    # Pod name (for leadership)
POD_NAMESPACE              # Pod namespace (for leadership)
GRACEFUL_SHUTDOWN_ENABLED  # (default: true)
SHUTDOWN_TIMEOUT_SECONDS   # (default: 30)
REQUEST_DRAIN_TIMEOUT      # (default: 20)
LOG_LEVEL                  # (default: INFO)
```

---

## Testing Checklist

### Unit Tests
```
tests/
├── test_graceful_shutdown.py
│   ├── test_signal_handler()
│   ├── test_request_tracking()
│   ├── test_phase_execution()
│   └── test_timeout_handling()
├── test_leader_election.py
│   ├── test_lease_acquisition()
│   ├── test_lease_renewal()
│   ├── test_leadership_transition()
│   └── test_election_timeout()
└── test_request_draining.py
    ├── test_request_accepted_before_shutdown()
    ├── test_request_rejected_after_shutdown_start()
    └── test_in_flight_tracking()
```

### Integration Tests
```
tests/
├── test_graceful_shutdown_integration.sh
│   ├── Test signal handling
│   ├── Test endpoint response
│   └── Test process termination
├── test_leader_election_integration.sh
│   ├── Test lease creation
│   ├── Test leadership transition
│   └── Test new leader election
└── test_e2e_scaling.sh
    ├── Deploy 3 replicas
    ├── Generate load
    ├── Delete pods
    ├── Verify no errors
    └── Verify zero downtime
```

### Load Tests
```bash
# Concurrent requests during shutdown
kubectl run load-test --image=load/apache-bench -- \
  -n 100 -c 10 http://kubedash:8000/api/v1/cluster/mode

# Monitor during: kubectl delete pod kubedash-0
# Verify: No HTTP 503 or connection errors
```

---

## Success Metrics

### Performance Targets
| Metric | Target | Alert |
|--------|--------|-------|
| Shutdown Duration | < 15s | > 25s |
| Leadership Release | < 1s | > 2s |
| Request Drain | < 10s | > 18s |
| Exit Code | 0 | != 0 |
| Readiness Probe Response | 503 immediate | > 1s |

### Reliability Targets
| Metric | Target | Alert |
|--------|--------|-------|
| Successful Shutdowns | 100% | < 99.9% |
| Leadership Uptime | 99.9% | < 99% |
| Leadership Transitions | < 1/week | > 1/week |
| Stuck Requests | 0 | > 1 |

### Observability Targets
| Metric | Target |
|--------|--------|
| Log Lines Per Shutdown | 20-30 |
| Prometheus Metrics Available | Yes |
| Dashboard Queries | All < 1s |
| Alert Firing Time | < 2s |

---

## Rollback Plan

If graceful shutdown causes problems:

```bash
# Option 1: Reduce grace period (faster termination)
kubectl patch deployment kubedash -p \
  '{"spec":{"template":{"spec":{"terminationGracePeriodSeconds":10}}}}'

# Option 2: Disable graceful shutdown endpoint
kubectl set env deployment/kubedash \
  GRACEFUL_SHUTDOWN_ENABLED=false

# Option 3: Rollback to previous image
helm rollback kubedash

# Option 4: Force delete stuck pods (last resort)
kubectl delete pods --all --namespace=kubedash --grace-period=0 --force
```

---

## Maintenance & Operations

### Weekly Checks
- [ ] Review alert history (false positives?)
- [ ] Check shutdown duration trends
- [ ] Verify leader election stability
- [ ] Confirm metric collection working

### Monthly Review
- [ ] Analyze shutdown logs for patterns
- [ ] Review performance vs targets
- [ ] Update runbooks if needed
- [ ] Train new team members

### Quarterly Audit
- [ ] Full e2e test in production-like environment
- [ ] Verify monitoring coverage
- [ ] Review and update docs
- [ ] Disaster recovery drill

---

## Training & Handoff

### Team Training Topics
1. How graceful shutdown works
2. What to monitor
3. How to troubleshoot issues
4. Runbook procedures
5. Manual intervention scenarios

### Documentation for Team
- [ ] Operations runbook (link: graceful-shutdown-troubleshooting.md)
- [ ] Metrics and dashboards guide
- [ ] Alert response procedures
- [ ] Emergency contact list

### Knowledge Transfer
- [ ] Demo shutdown process
- [ ] Simulate failure scenarios
- [ ] Review actual logs from production
- [ ] Practice troubleshooting exercises

---

## Support & Escalation

### Support Levels

**L1: Automated**
- Alerts trigger automatically
- Dashboards show real-time status
- Logs available in aggregator

**L2: Debugging**
- Review logs (see troubleshooting guide)
- Check metrics in Prometheus
- Verify configuration matches docs

**L3: Engineering**
- Code review of shutdown logic
- Performance optimization
- Design changes/improvements

**L4: Escalation**
- Kernel-level issues
- Kubernetes bugs
- Infrastructure problems

### Getting Help

```
Documentation: docs/operations/graceful-shutdown*.md
Metrics: https://prometheus/graph?query=kubedash_shutdown*
Dashboard: https://grafana/d/kubedash-shutdown
Alert Rules: monitoring/prometheus-rules.yaml
Contact: platform-team@company.com
```

---

## Next Steps

1. **Review** all documentation above
2. **Implement** Phase 1 in isolation
3. **Test** thoroughly with load
4. **Deploy** to staging gradually
5. **Monitor** for 1 week
6. **Complete** Phase 2 (Leader Election)
7. **Deploy** to production with canary
8. **Iterate** based on metrics and feedback
