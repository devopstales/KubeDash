# Staging Environment for Multi-Replica Testing

## Overview

This staging environment validates multi-replica KubeDash deployments before production.

## Architecture

```
Staging Namespace: kubedash-staging
├── PostgreSQL (managed or self-hosted)
├── Redis
├── KubeDash Replicas (3 pods)
├── Prometheus (monitoring)
├── Grafana (dashboards)
├── Jaeger (tracing)
└── Load Testing Tools
```

## Prerequisites

- Kubernetes cluster (1.19+)
- Helm 3.x
- kubectl access to cluster

## Setup

### Step 1: Create Staging Namespace

```bash
kubectl create namespace kubedash-staging
kubectl label namespace kubedash-staging environment=staging
```

### Step 2: Deploy PostgreSQL (Example: Google Cloud SQL)

```bash
# Create database
gcloud sql instances create kubedash-staging \
  --database-version=POSTGRES_14 \
  --tier=db-g1-small \
  --region=us-central1

# Create database
gcloud sql databases create kubedash --instance=kubedash-staging

# Create user
gcloud sql users create kubedash --instance=kubedash-staging --password

# Export connection string
DB_HOST=$(gcloud sql instances describe kubedash-staging --format="value(ipAddresses[0].ipAddress)")
DB_USER=kubedash
DB_PASSWORD=<generated>
DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@$DB_HOST:5432/kubedash"
```

Create secret:

```bash
kubectl create secret generic kubedash-postgres \
  --from-literal=database-url="$DATABASE_URL" \
  -n kubedash-staging
```

### Step 3: Deploy Redis

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install redis bitnami/redis \
  -n kubedash-staging \
  --set auth.enabled=true \
  --set auth.password=staging-redis-password \
  --set persistence.size=10Gi
```

Get Redis URL:

```bash
REDIS_URL="redis://default:staging-redis-password@redis-master:6379/0"
kubectl create secret generic kubedash-redis \
  --from-literal=redis-url="$REDIS_URL" \
  -n kubedash-staging
```

### Step 4: Deploy KubeDash (3 Replicas)

Create `values-staging.yaml`:

```yaml
replicaCount: 3

image:
  tag: staging-latest
  pullPolicy: Always

environment:
  REPLICA_MODE: cluster
  REPLICA_COUNT: "3"
  FLASK_ENV: staging
  LOG_LEVEL: DEBUG

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi

secretRefs:
  - name: kubedash-postgres
    key: database-url
    envName: SQLALCHEMY_DATABASE_URI
  - name: kubedash-redis
    key: redis-url
    envName: SESSION_REDIS_URL

rbac:
  enabled: true

serviceAccount:
  create: true

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app
            operator: In
            values:
            - kubedash
        topologyKey: kubernetes.io/hostname

podDisruptionBudget:
  enabled: true
  minAvailable: 1

autoscaling:
  enabled: false  # Manual scaling in staging

monitoring:
  enabled: true
  prometheus:
    enabled: true
```

Deploy:

```bash
helm install kubedash ./charts/kubedash \
  -n kubedash-staging \
  -f values-staging.yaml
```

### Step 5: Deploy Prometheus for Staging

Create `prometheus-staging.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: prometheus-config
  namespace: kubedash-staging
data:
  prometheus.yml: |
    global:
      scrape_interval: 15s
      evaluation_interval: 15s
    
    scrape_configs:
    - job_name: 'kubedash'
      static_configs:
      - targets: ['kubedash:8000']
    
    - job_name: 'redis'
      static_configs:
      - targets: ['redis-master:6379']
    
    - job_name: 'kubernetes-pods'
      kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
          - kubedash-staging

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: prometheus
  namespace: kubedash-staging
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus
  template:
    metadata:
      labels:
        app: prometheus
    spec:
      serviceAccountName: prometheus
      containers:
      - name: prometheus
        image: prom/prometheus:latest
        args:
          - '--config.file=/etc/prometheus/prometheus.yml'
          - '--storage.tsdb.path=/prometheus'
        ports:
        - containerPort: 9090
        volumeMounts:
        - name: config
          mountPath: /etc/prometheus
        - name: storage
          mountPath: /prometheus
      volumes:
      - name: config
        configMap:
          name: prometheus-config
      - name: storage
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: prometheus
  namespace: kubedash-staging
spec:
  selector:
    app: prometheus
  ports:
  - port: 9090
    targetPort: 9090
  type: NodePort
```

Deploy:

```bash
kubectl apply -f prometheus-staging.yaml
```

### Step 6: Deploy Grafana

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm install grafana grafana/grafana \
  -n kubedash-staging \
  --set adminPassword=staging-grafana-password \
  --set persistence.enabled=true \
  --set persistence.size=5Gi \
  --set datasources."prometheus.yaml".datasources[0].url="http://prometheus:9090"
```

Access Grafana:

```bash
kubectl port-forward svc/grafana 3000:80 -n kubedash-staging
# Navigate to http://localhost:3000
# Default credentials: admin / staging-grafana-password
```

## Testing Workflows

### Test 1: Basic Multi-Replica Functionality

```bash
# 1. Verify all pods are running
kubectl get pods -n kubedash-staging

# 2. Check cluster status
kubectl port-forward svc/kubedash 8000:8000 -n kubedash-staging
curl http://localhost:8000/api/cluster/status | jq .

# 3. Verify leader election
kubectl logs -l app=kubedash -n kubedash-staging | grep "leadership\|acquired"

# 4. Test session sharing
# In pod 1: Create session
# In pod 2: Verify session exists
```

### Test 2: Leader Failover

```bash
# 1. Get current leader
LEADER=$(kubectl get pods -o jsonpath='{.items[0].metadata.name}' -n kubedash-staging)

# 2. Delete leader pod
kubectl delete pod $LEADER -n kubedash-staging

# 3. Watch new leader election (< 30 seconds)
kubectl logs -f -l app=kubedash -n kubedash-staging | grep "leadership"

# 4. Verify new leader (should not be the deleted pod)
curl http://localhost:8000/api/cluster/status | jq '.leader_pod'
```

### Test 3: Load Testing

Deploy load generator:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kubedash-load-test
  namespace: kubedash-staging
spec:
  parallelism: 5
  completions: 100
  template:
    spec:
      containers:
      - name: load
        image: loadimpact/k6:latest
        script: |
          import http from 'k6/http';
          import { sleep } from 'k6';
          
          export let options = {
            stages: [
              { duration: '2m', target: 100 },
              { duration: '5m', target: 100 },
              { duration: '2m', target: 0 },
            ],
          };
          
          export default function () {
            http.get('http://kubedash:8000/api/cluster/status');
            sleep(1);
          }
      restartPolicy: Never
```

Monitor with Prometheus during load test.

### Test 4: Pod Disruption

```bash
# Test PDB enforcement
kubectl delete pod kubedash-0 kubedash-1 -n kubedash-staging

# Verify minimum availability maintained
kubectl get pods -n kubedash-staging

# Simulate node drain
kubectl drain <node> --ignore-daemonsets --kubelet-critical-pods \
  --pod-selector=app=kubedash --namespace=kubedash-staging
```

### Test 5: Database Failover

For managed PostgreSQL (RDS, Cloud SQL):

```bash
# Trigger failover via cloud provider console
# Watch KubeDash handle reconnection
kubectl logs -f -l app=kubedash -n kubedash-staging

# Verify application continues working
curl http://localhost:8000/api/cluster/status
```

### Test 6: Redis Disconnection

```bash
# Simulate Redis outage
kubectl delete pod redis-master-0 -n kubedash-staging

# Watch session error handling
kubectl logs -f -l app=kubedash -n kubedash-staging | grep -i redis

# Verify session fallback (if configured)
```

## Staging Dashboards

### Key Metrics to Monitor

1. **Leader Election**
   - Current leader pod name
   - Leadership transitions
   - Election success rate

2. **Tasks**
   - Leader-only task execution
   - Task success/failure rates
   - Task execution duration

3. **Sessions**
   - Redis connection status
   - Session operations rate
   - Session error rate

4. **Pod Health**
   - Pod restart count
   - CPU/Memory usage
   - Network I/O

## Cleanup

```bash
# Remove staging deployment
helm uninstall kubedash -n kubedash-staging
helm uninstall redis -n kubedash-staging
helm uninstall grafana -n kubedash-staging
helm uninstall prometheus -n kubedash-staging

# Delete namespace
kubectl delete namespace kubedash-staging

# Delete database (if using cloud)
gcloud sql instances delete kubedash-staging
```

## Checklist Before Production

- [ ] All 3+ replicas start successfully
- [ ] Leader election works (< 30 sec)
- [ ] Session sharing across pods verified
- [ ] Leader-only tasks run only on leader
- [ ] Failover tested (pod deletion, node drain)
- [ ] Database failover tested
- [ ] Redis failover tested
- [ ] Load testing completed (5+ min sustained)
- [ ] PDB enforced (pods not deleted simultaneously)
- [ ] Monitoring dashboards display correctly
- [ ] Alerting rules fire correctly
- [ ] Graceful shutdown tested
- [ ] Upgrade path verified
- [ ] Rollback procedure verified
