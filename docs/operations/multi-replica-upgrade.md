# Multi-Replica Upgrade and Rollback Procedures

## Overview

This guide covers upgrading KubeDash from single-replica to multi-replica mode, and rolling back if needed.

## Pre-Upgrade Checklist

Before upgrading to multi-replica mode:

- [ ] PostgreSQL database is ready (not SQLite)
- [ ] Redis is deployed and accessible
- [ ] All pods have network connectivity
- [ ] Backup of PostgreSQL database is current
- [ ] Maintenance window is scheduled
- [ ] Team is aware of brief downtime (~5-10 minutes)
- [ ] Monitoring and alerting are configured

## Upgrade Path: Single → Multi-Replica (2+ replicas)

### Step 1: Backup Current State

```bash
# Backup PostgreSQL database
kubectl exec -it kubedash-single-0 -- \
  pg_dump $DATABASE_URL > kubedash-backup-$(date +%Y%m%d-%H%M%S).sql

# Export current configuration
kubectl get configmap kubedash-config -o yaml > kubedash-configmap-backup.yaml
kubectl get secret kubedash-secrets -o yaml > kubedash-secrets-backup.yaml

# Save current deployment
kubectl get deployment kubedash -o yaml > kubedash-deployment-backup.yaml
```

### Step 2: Enable Prerequisites

#### Enable PostgreSQL (if using SQLite)

If currently using SQLite, migrate to PostgreSQL:

```bash
# Create PostgreSQL secret
kubectl create secret generic kubedash-postgres \
  --from-literal=database-url="postgresql://user:pass@postgres:5432/kubedash"

# Update deployment to use PostgreSQL
kubectl set env deployment/kubedash \
  SQLALCHEMY_DATABASE_URI="postgresql://user:pass@postgres:5432/kubedash"
```

#### Enable Redis

```bash
# Deploy Redis (or use existing)
helm install redis bitnami/redis \
  --set auth.enabled=true \
  --set auth.password=<secure-password>

# Create Redis secret
kubectl create secret generic kubedash-redis \
  --from-literal=redis-url="redis://:<password>@redis:6379/0"

# Update deployment to use Redis
kubectl set env deployment/kubedash \
  SESSION_REDIS_URL="redis://:<password>@redis:6379/0"
```

### Step 3: Create RBAC for Leader Election

```bash
# Apply leader election RBAC
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubedash
  namespace: default

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kubedash-leader-election
  namespace: default
rules:
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "create", "update"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kubedash-leader-election
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubedash-leader-election
subjects:
- kind: ServiceAccount
  name: kubedash
  namespace: default
EOF
```

### Step 4: Enable Cluster Mode Configuration

```bash
# Update deployment configuration
kubectl set env deployment/kubedash \
  REPLICA_MODE=cluster \
  REPLICA_COUNT=3 \
  LEADER_LEASE_DURATION=30 \
  LEADER_RENEW_DEADLINE=20 \
  LEADER_RETRY_PERIOD=2
```

### Step 5: Update Pod Configuration

Add downward API environment variables to deployment:

```bash
kubectl patch deployment kubedash --type='json' -p='[
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/env/-",
    "value": {
      "name": "POD_NAME",
      "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}
    }
  },
  {
    "op": "add",
    "path": "/spec/template/spec/containers/0/env/-",
    "value": {
      "name": "POD_NAMESPACE",
      "valueFrom": {"fieldRef": {"fieldPath": "metadata.namespace"}}
    }
  }
]'
```

### Step 6: Scale Up to Multi-Replica

```bash
# Scale to 3 replicas
kubectl scale deployment kubedash --replicas=3

# Watch rollout progress
kubectl rollout status deployment/kubedash -w

# Verify replicas are running
kubectl get pods -l app=kubedash
```

Expected output:
```
NAME                         READY   STATUS    RESTARTS   AGE
kubedash-5d6b8c7f9d-abc12   1/1     Running   0          2m
kubedash-5d6b8c7f9d-def45   1/1     Running   0          1m
kubedash-5d6b8c7f9d-ghi78   1/1     Running   0          30s
```

### Step 7: Verify Leader Election

```bash
# Check cluster status endpoint
kubectl port-forward svc/kubedash 8000:8000

# In another terminal
curl http://localhost:8000/api/cluster/status | jq .

# Expected response:
# {
#   "replica_mode": "cluster",
#   "is_leader": true,
#   "leader_pod": "kubedash-5d6b8c7f9d-abc12",
#   "pod_name": "kubedash-5d6b8c7f9d-abc12",
#   "pod_namespace": "default",
#   "replica_count": 3
# }
```

### Step 8: Verify Task Coordination

```bash
# Check that only the leader runs cluster health checks
kubectl logs -l app=kubedash -c kubedash --tail=50 | grep "leader-only"

# Expected: See leader-only tasks only on one pod (the leader)
```

## Rollback Path: Multi-Replica → Single

If issues occur, rollback to single-replica mode:

### Step 1: Stop Multi-Replica

```bash
# Scale down to 1 replica
kubectl scale deployment kubedash --replicas=1

# Wait for pod to stabilize
kubectl rollout status deployment/kubedash -w
```

### Step 2: Disable Cluster Mode

```bash
# Switch back to single-replica mode
kubectl set env deployment/kubedash \
  REPLICA_MODE=single

# Restart pod to apply changes
kubectl rollout restart deployment/kubedash
kubectl rollout status deployment/kubedash -w
```

### Step 3: Verify Single-Replica Mode

```bash
# Check cluster status
curl http://localhost:8000/api/cluster/status | jq .

# Expected:
# {
#   "replica_mode": "single",
#   "is_leader": true,  # Always true in single mode
#   "leader_pod": null,  # N/A in single mode
#   ...
# }
```

### Step 4: Restore from Backup (If Needed)

```bash
# If data was corrupted, restore from backup
psql $DATABASE_URL < kubedash-backup-YYYYMMDD-HHMMSS.sql

# Restart deployment
kubectl rollout restart deployment/kubedash
kubectl rollout status deployment/kubedash -w
```

## Troubleshooting

### Leader Election Not Working

```bash
# Check RBAC permissions
kubectl get rolebindings kubedash-leader-election -o yaml

# Check if leases are being created
kubectl get leases -A | grep kubedash

# Check pod logs for errors
kubectl logs <pod-name> | grep -i "leader\|election"
```

### Pods Not Reaching Ready State

```bash
# Check readiness probe
curl http://<pod-ip>:8000/api/health/ready

# Check pod events
kubectl describe pod <pod-name>

# Check pod logs
kubectl logs <pod-name>
```

### Session Data Not Shared

```bash
# Verify Redis connectivity
kubectl exec -it <pod-name> -- redis-cli -u $SESSION_REDIS_URL ping

# Check session configuration
kubectl set env pods -l app=kubedash --list | grep SESSION
```

## Validation Commands

Post-upgrade validation:

```bash
# 1. Verify all replicas running
kubectl get pods -l app=kubedash

# 2. Check cluster status
curl http://localhost:8000/api/cluster/status | jq .

# 3. Verify leader election
kubectl logs -l app=kubedash | grep "acquired leadership"

# 4. Test session sharing (create session on pod 1, read on pod 2)
# 5. Verify task coordination (leader-only tasks only on leader)
# 6. Test leader failover (kill leader pod, observe election)
# 7. Check monitoring dashboard (Grafana)
```

## Post-Upgrade

- Update monitoring dashboards
- Enable alerting rules
- Notify operations team
- Document any custom configurations
- Schedule periodic testing of failover
