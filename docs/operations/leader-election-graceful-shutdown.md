# Leader Election & Graceful Shutdown Integration

## Overview

In a multi-replica KubeDash deployment, proper leader election ensures that:
- Only one pod runs leader-only tasks (cluster scanning, metrics aggregation, license checks)
- On leader pod deletion, a new leader is elected from remaining replicas within ~5 seconds
- During graceful shutdown, the departing leader releases the lease before terminating

---

## Architecture

### Leader Election Flow

```
┌─────────────────────────────────────────┐
│      Kubernetes Lease Object            │
│   (kubedash-leader in Lease API)        │
│                                         │
│  holderIdentity: "kubedash-0"           │
│  acquireTime: 2026-04-05...             │
│  renewTime: 2026-04-05... (+15s)        │
│  leaseDurationSeconds: 30                │
└─────────────────────────────────────────┘
         ▲                  ▲
         │                  │
    ┌────┘      ┌───────────┘
    │           │
 POLL (5s)   RENEW (10s)
    │           │
    │      ┌────────────────┐
    │      │  kubedash-0    │ ← LEADER
    │      │  (Running)     │
    │      │  Renews lease  │
    │      │  every 10s     │
    │      └────────────────┘
    │
    └─────────────────────┐
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   ┌────────────┐    ┌────────────┐   ┌────────────┐
   │ kubedash-1 │    │ kubedash-2 │   │ kubedash-3 │
   │   (Follower)   │  (Follower)   │  (Follower) │
   │  Watch lease   │  Watch lease  │ Watch lease │
   │  every 5s      │  every 5s     │  every 5s   │
   └────────────┘    └────────────┘   └────────────┘
```

### Graceful Shutdown + Leadership Release

```
Timeline:
t=0     : SIGTERM received by kubedash-0
          ├─→ Is leader → Release lease (Phase 1)
          ├─→ New leader elected from kubedasg-1, -2, -3
          ├─→ Followers immediately detect leadership change
          └─→ Existing leader tasks stop, leader tasks start on new leader

t=1     : Lease released, new leader elected
          ├─→ kubedash-1 becomes leader (if won election)
          ├─→ Leader-only heartbeat task starts on -1
          └─→ Non-leader pods continue normally

t=2-3   : Drain in-flight requests
          └─→ Current leader (-1) handles requests

t=4     : Close database connections
```

---

## Implementation

### 1. Leader Election with Kubernetes Lease API

File: `src/kubedash/lib/leader_elector.py`

```python
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Callable

from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


class KubernetesLeaderElector:
    """Elect leader using Kubernetes Lease API"""
    
    def __init__(
        self,
        lease_name: str,
        namespace: str,
        pod_name: str,
        lease_duration_seconds: int = 30,
        renew_interval_seconds: int = 10,
    ):
        self.lease_name = lease_name
        self.namespace = namespace
        self.pod_name = pod_name
        self.lease_duration_seconds = lease_duration_seconds
        self.renew_interval_seconds = renew_interval_seconds
        
        # State
        self.is_leader = False
        self.is_running = False
        self.renew_thread: Optional[threading.Thread] = None
        self.watch_thread: Optional[threading.Thread] = None
        self.current_leader: Optional[str] = None
        
        # Callbacks
        self.on_became_leader: Optional[Callable] = None
        self.on_lost_leadership: Optional[Callable] = None
        
        # Kubernetes client
        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()  # For local testing
        
        self.v1 = client.CoreV1Api()
    
    def start(self):
        """Start leader election"""
        if self.is_running:
            logger.warning("Leader elector already running")
            return
        
        self.is_running = True
        logger.info("🗳️  Starting leader election...")
        
        # Acquire initial lease
        self._acquire_lease()
        
        # Start renewal thread
        self.renew_thread = threading.Thread(
            target=self._renew_loop,
            daemon=True,
            name='leader-renew'
        )
        self.renew_thread.start()
        
        # Start watch thread
        self.watch_thread = threading.Thread(
            target=self._watch_loop,
            daemon=True,
            name='leader-watch'
        )
        self.watch_thread.start()
        
        logger.info("✅ Leader election started")
    
    def stop(self):
        """Stop leader election and release lease"""
        if not self.is_running:
            return
        
        self.is_running = False
        logger.info("🛑 Stopping leader election...")
        
        # Release lease
        try:
            self._release_lease()
            logger.info("✅ Released lease on stop")
        except Exception as e:
            logger.error(f"Error releasing lease: {e}")
        
        # Wait for threads to finish (max 5 seconds)
        if self.renew_thread:
            self.renew_thread.join(timeout=2)
        if self.watch_thread:
            self.watch_thread.join(timeout=2)
        
        self.is_leader = False
        logger.info("✅ Leader election stopped")
    
    def _acquire_lease(self):
        """Try to acquire or renew the leader lease"""
        
        lease_body = {
            'apiVersion': 'coordination.k8s.io/v1',
            'kind': 'Lease',
            'metadata': {
                'name': self.lease_name,
                'namespace': self.namespace,
            },
            'spec': {
                'holderIdentity': self.pod_name,
                'leaseDurationSeconds': self.lease_duration_seconds,
                'acquireTime': datetime.utcnow().isoformat() + 'Z',
                'renewTime': datetime.utcnow().isoformat() + 'Z',
            },
        }
        
        try:
            # Try to get existing lease
            lease = self.v1.read_namespaced_lease(
                self.lease_name,
                self.namespace
            )
            
            # Check if we already hold the lease
            if lease.spec.holder_identity == self.pod_name:
                # Renew our lease
                lease.spec.renew_time = datetime.utcnow().isoformat() + 'Z'
                self.v1.patch_namespaced_lease(
                    self.lease_name,
                    self.namespace,
                    lease
                )
                self._became_leader()
                logger.debug("🔄  Renewed lease")
                return
            
            # Check if lease is expired
            renew_time = lease.spec.renew_time
            if renew_time and isinstance(renew_time, str):
                renew_time = datetime.fromisoformat(renew_time.replace('Z', '+00:00'))
            
            lease_age = datetime.utcnow() - renew_time.replace(tzinfo=None)
            
            if lease_age.total_seconds() > self.lease_duration_seconds:
                # Lease expired, take over
                lease.spec.holder_identity = self.pod_name
                lease.spec.acquire_time = datetime.utcnow().isoformat() + 'Z'
                lease.spec.renew_time = datetime.utcnow().isoformat() + 'Z'
                self.v1.patch_namespaced_lease(
                    self.lease_name,
                    self.namespace,
                    lease
                )
                self._became_leader()
                logger.info(f"📍 Took over expired lease from {lease.spec.holder_identity}")
                return
            
            # Lease held by someone else
            logger.debug(f"📍 Lease held by {lease.spec.holder_identity}, waiting...")
            self._lost_leadership()
        
        except ApiException as e:
            if e.status == 404:
                # Lease doesn't exist, create it
                try:
                    self.v1.create_namespaced_lease(
                        self.namespace,
                        lease_body
                    )
                    self._became_leader()
                    logger.info("✨ Created new lease, became leader")
                except Exception as err:
                    logger.error(f"Error creating lease: {err}")
            else:
                logger.error(f"Error acquiring lease: {e}")
    
    def _release_lease(self):
        """Release the leader lease"""
        try:
            lease = self.v1.read_namespaced_lease(
                self.lease_name,
                self.namespace
            )
            
            if lease.spec.holder_identity == self.pod_name:
                # Clear holder identity to release lease
                lease.spec.holder_identity = None
                self.v1.patch_namespaced_lease(
                    self.lease_name,
                    self.namespace,
                    lease
                )
                logger.info("🔓 Released lease")
                self._lost_leadership()
        except Exception as e:
            logger.error(f"Error releasing lease: {e}")
    
    def _renew_loop(self):
        """Periodically renew lease if leader"""
        while self.is_running:
            try:
                time.sleep(self.renew_interval_seconds)
                
                if not self.is_running:
                    break
                
                self._acquire_lease()
            
            except Exception as e:
                logger.error(f"Error in renew loop: {e}")
    
    def _watch_loop(self):
        """Watch lease changes"""
        while self.is_running:
            try:
                # Watch for lease changes
                w = watch.Watch()
                
                for event in w.stream(
                    self.v1.list_namespaced_lease,
                    self.namespace,
                    field_selector=f'metadata.name={self.lease_name}',
                    timeout_seconds=30,
                ):
                    if not self.is_running:
                        break
                    
                    lease = event['object']
                    holder = lease.spec.holder_identity if lease.spec else None
                    
                    if holder != self.current_leader:
                        self.current_leader = holder
                        
                        if holder == self.pod_name:
                            self._became_leader()
                        else:
                            self._lost_leadership()
                            logger.info(f"👑 New leader detected: {holder}")
            
            except Exception as e:
                logger.error(f"Error watching lease: {e}")
                time.sleep(5)  # Backoff on error
    
    def _became_leader(self):
        """Called when this pod becomes leader"""
        if not self.is_leader:
            self.is_leader = True
            logger.info("👑 BECAME LEADER")
            
            if self.on_became_leader:
                try:
                    self.on_became_leader()
                except Exception as e:
                    logger.error(f"Error in on_became_leader callback: {e}")
    
    def _lost_leadership(self):
        """Called when this pod loses leadership"""
        if self.is_leader:
            self.is_leader = False
            logger.info("👤 LOST LEADERSHIP")
            
            if self.on_lost_leadership:
                try:
                    self.on_lost_leadership()
                except Exception as e:
                    logger.error(f"Error in on_lost_leadership callback: {e}")
```

### 2. Flask App Integration

```python
# src/kubedash/app.py

from lib.leader_elector import KubernetesLeaderElector

def create_app(config_name='default'):
    app = Flask(__name__)
    
    # ... other initialization ...
    
    # Initialize leader election
    pod_name = os.environ.get('POD_NAME', 'kubedash-local')
    pod_namespace = os.environ.get('POD_NAMESPACE', 'default')
    
    leader_elector = KubernetesLeaderElector(
        lease_name='kubedash-leader',
        namespace=pod_namespace,
        pod_name=pod_name,
    )
    
    # Register callbacks
    def on_became_leader():
        """Leadership acquired - start leader-only tasks"""
        logger.info("Starting leader-only tasks...")
        scheduler.add_job(
            cluster_health_scan,
            'interval',
            seconds=60,
            id='cluster_health_scan',
            replace_existing=True
        )
    
    def on_lost_leadership():
        """Leadership lost - stop leader-only tasks"""
        logger.info("Stopping leader-only tasks...")
        job = scheduler.get_job('cluster_health_scan')
        if job:
            scheduler.remove_job('cluster_health_scan')
    
    leader_elector.on_became_leader = on_became_leader
    leader_elector.on_lost_leadership = on_lost_leadership
    
    # Start leader election
    leader_elector.start()
    
    # Initialize graceful shutdown with leader_elector
    graceful_shutdown = init_graceful_shutdown(
        app, db, scheduler, leader_elector
    )
    
    return app
```

### 3. Kubernetes Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubedash
  namespace: default
spec:
  replicas: 3
  
  template:
    spec:
      # Enable leader election
      serviceAccountName: kubedash-sa
      automountServiceAccountToken: true
      
      containers:
      - name: kubedash
        image: kubedash:latest
        
        env:
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
```

### 4. RBAC Configuration

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubedash-sa
  namespace: default

---

apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kubedash-leader
  namespace: default
rules:
# Leader election via Lease API
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update", "patch"]

---

apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kubedash-leader
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubedash-leader
subjects:
- kind: ServiceAccount
  name: kubedash-sa
  namespace: default
```

---

## Shutdown with Leadership

### Complete Flow

```python
# src/kubedash/lib/shutdown.py - enhanced version

class GracefulShutdown:
    
    def _release_leadership(self):
        """Phase 1: Release leadership immediately"""
        
        if not self.leader_elector or not self.leader_elector.is_leader:
            logger.debug("Not leader, skipping leadership release")
            return
        
        logger.info("  Releasing Kubernetes Lease...")
        
        start = datetime.utcnow()
        try:
            # Stop renewing lease
            self.leader_elector.stop()
            
            # Wait for new leader election (max 5 seconds)
            deadline = datetime.utcnow() + timedelta(seconds=5)
            while datetime.utcnow() < deadline:
                if not self.leader_elector.is_leader:
                    break
                threading.Event().wait(0.1)
            
            elapsed = (datetime.utcnow() - start).total_seconds()
            logger.info(f"  Released lease in {elapsed:.2f}s")
            
            # Record metric
            from prometheus_client import Histogram
            leadership_release_time_seconds.observe(elapsed)
        
        except Exception as e:
            logger.error(f"  Error releasing leadership: {e}")
            raise
```

---

## Monitoring Leader Election

### Key Metrics

```python
from prometheus_client import Counter, Gauge, Histogram

# Leader state
is_leader = Gauge(
    'kubedash_is_leader',
    'Is this pod the current leader',
    ['pod']
)

# Leadership transitions
leadership_transitions_total = Counter(
    'kubedash_leadership_transitions_total',
    'Number of leadership transitions',
    ['pod', 'transition_type']  # 'became_leader', 'lost_leader'
)

# Lease operations
lease_acquire_time_seconds = Histogram(
    'kubedash_lease_acquire_time_seconds',
    'Time to acquire lease',
    buckets=(0.1, 0.5, 1, 2, 5)
)

lease_renew_time_seconds = Histogram(
    'kubedash_lease_renew_time_seconds',
    'Time to renew lease',
    buckets=(0.01, 0.05, 0.1, 0.5)
)

# Update metrics in KubernetesLeaderElector
def _became_leader(self):
    """Called when this pod becomes leader"""
    if not self.is_leader:
        self.is_leader = True
        
        is_leader.labels(pod=self.pod_name).set(1)
        leadership_transitions_total.labels(
            pod=self.pod_name,
            transition_type='became_leader'
        ).inc()
        
        logger.info("👑 BECAME LEADER")
        # ... callback ...

def _lost_leadership(self):
    """Called when this pod loses leadership"""
    if self.is_leader:
        self.is_leader = False
        
        is_leader.labels(pod=self.pod_name).set(0)
        leadership_transitions_total.labels(
            pod=self.pod_name,
            transition_type='lost_leader'
        ).inc()
        
        logger.info("👤 LOST LEADERSHIP")
        # ... callback ...
```

### Prometheus Queries

```promql
# Current leader
kubedash_is_leader{job="kubedash"}

# Leadership change rate (should be 0 in steady state)
rate(kubedash_leadership_transitions_total[1m])

# Time to acquire leadership (should be < 1 second)
histogram_quantile(0.99, rate(kubedash_lease_acquire_time_seconds_bucket[5m]))

# Elections per day
increase(kubedash_leadership_transitions_total{transition_type="became_leader"}[1d])
```

### Alerting

```yaml
groups:
- name: kubedash_leader_election
  alerts:
  
  # Alert if no leader for > 30 seconds
  - alert: KubeDashNoLeaderElected
    expr: |
      sum(kubedash_is_leader{job="kubedash"}) == 0
    for: 30s
    annotations:
      summary: "No KubeDash leader elected"
  
  # Alert on rapid leadership flapping
  - alert: KubeDashLeadershipFlapping
    expr: |
      rate(kubedash_leadership_transitions_total{transition_type="became_leader"}[1m]) > 0.5
    annotations:
      summary: "KubeDash experiencing leadership flapping"
  
  # Alert on slow leadership election
  - alert: KubeDashSlowLeadershipElection
    expr: |
      histogram_quantile(0.99, rate(kubedash_lease_acquire_time_seconds_bucket[5m])) > 5
    annotations:
      summary: "KubeDash leadership election taking > 5s"
```

---

## Troubleshooting Leader Election Issues

### No Leader Elected

**Diagnosis:**
```bash
# Check if Lease exists
kubectl get leases -l app=kubedash

# Check Lease details
kubectl get lease kubedash-leader -o yaml

# Check pod logs for election errors
kubectl logs kubedash-0 | grep -i "leader\|lease"

# Check RBAC permissions
kubectl auth can-i get leases --as=system:serviceaccount:default:kubedash-sa
kubectl auth can-i create leases --as=system:serviceaccount:default:kubedash-sa
kubectl auth can-i patch leases --as=system:serviceaccount:default:kubedash-sa
```

**Fixes:**
```bash
# Create Lease manually if missing
kubectl apply -f - <<EOF
apiVersion: coordination.k8s.io/v1
kind: Lease
metadata:
  name: kubedash-leader
  namespace: default
spec:
  holderIdentity: kubedash-0
  leaseDurationSeconds: 30
EOF

# Verify permissions
kubectl auth can-i '*' leases --as=system:serviceaccount:default:kubedash-sa
# Should return: yes
```

### Leadership Flapping

**Diagnosis:**
```bash
# Check logs for rapid transitions
kubectl logs kubedash-0 | grep -E "BECAME LEADER|LOST LEADERSHIP" | tail -20

# Check metrics
promql> rate(kubedash_leadership_transitions_total[1m])
# Should be ~0 in steady state
```

**Causes:**
1. **Network issues** - Lease API unreachable
2. **Clock skew** - Pod time differs significantly
3. **Long GC pauses** - Renew thread blocked

**Fixes:**
```bash
# Check pod network
kubectl exec kubedash-0 -- curl -v https://kubernetes.default.svc

# Check pod time vs server time
kubectl exec kubedash-0 -- date
date  # on localhost

# Check for GC pauses
kubectl logs kubedash-0 | grep "GC\|garbage"

# Increase lease duration if too aggressive
# Change: lease_duration_seconds=30 (or higher)
```

---

## Testing Leader Election

```bash
#!/bin/bash
# tests/test-leader-election.sh

set -e

echo "🧪 Testing Leader Election"

# Deploy 3 replicas
kubectl scale deployment kubedash --replicas=3
kubectl wait --for=condition=ready pod -l app=kubedash -n default --timeout=60s

# Find initial leader
LEADER=$(kubectl logs -l app=kubedash --tail=50 | grep "BECAME LEADER" | head -1 | awk '{print $NF}')
echo "✓ Initial leader: $LEADER"

# Monitor leadership transitions in all pods
echo "📊 Monitoring leadership (20 seconds)..."
kubectl logs -f -l app=kubedash --tail=0 --max-log-requests=3 | \
  grep -E "BECAME LEADER|LOST LEADERSHIP" &
TAIL_PID=$!

# Delete leader pod
echo "🔪 Deleting leader pod ($LEADER)..."
kubectl delete pod $LEADER

# Wait for new leader election
echo "⏳ Waiting for new leader election..."
sleep 8

# Kill tail
kill $TAIL_PID 2>/dev/null || true

# Verify new leader elected
NEW_LEADER=$(kubectl logs -l app=kubedash --tail=50 | grep "BECAME LEADER" | tail -1 | awk '{print $NF}')
echo "✓ New leader elected: $NEW_LEADER"

if [ "$LEADER" != "$NEW_LEADER" ]; then
  echo "✅ Leader election test PASSED"
  exit 0
else
  echo "❌ Leader election test FAILED (same leader)"
  exit 1
fi
```

---

## Best Practices

✅ **DO:**
- Set `leaseDurationSeconds` to 30+ to avoid flapping
- Use separate watch thread for scalability
- Release lease in first shutdown phase
- Test leader election in staging
- Monitor leadership transitions
- Use Pod Name as `holderIdentity` for easy debugging

❌ **DON'T:**
- Use single pod's hostname (use Pod Name)
- Set lease duration too short (< 15s)
- Block renew thread on I/O
- Skip RBAC configuration
- Skip metrics collection
- Use `oneof` or random IDs as holder

---

## Summary

**Leader + Graceful Shutdown:**

1. **SIGTERM** received on leader pod
2. **Phase 1** (~0.5s): Release Kubernetes Lease
3. **New Leader** elected from replicas (~2-5s)
4. **Phase 2-6** (~10-20s): Standard graceful shutdown on old leader
5. **New Leader** continues leader-only tasks without interruption

**Result:** Zero-downtime leadership transition ✅
