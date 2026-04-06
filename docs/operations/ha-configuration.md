# High Availability Configuration

## HorizontalPodAutoscaler (HPA) Setup

### Overview

HPA automatically scales KubeDash replicas based on CPU and memory usage.

### Prerequisites

- Metrics Server installed (`kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml`)
- Resource requests/limits defined in deployment

### Configuration

Create `kubedash-hpa.yaml`:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: kubedash-hpa
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: kubedash
  minReplicas: 2          # Minimum replicas for HA
  maxReplicas: 10         # Maximum replicas
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70  # Scale up at 70% CPU
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80  # Scale up at 80% memory
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300  # Wait 5 min before scaling down
      policies:
      - type: Utilization
        value: 50
        periodSeconds: 15
    scaleUp:
      stabilizationWindowSeconds: 0   # Scale up immediately
      policies:
      - type: Percent
        value: 100  # Double the replicas
        periodSeconds: 15
```

### Deploy HPA

```bash
kubectl apply -f kubedash-hpa.yaml

# Verify HPA is working
kubectl get hpa kubedash-hpa -w

# Check metrics
kubectl top pods -l app=kubedash
```

### Monitoring HPA Activity

```bash
# Watch HPA decisions
kubectl describe hpa kubedash-hpa

# View HPA events
kubectl get events --sort-by='.lastTimestamp' | grep HorizontalPodAutoscaler
```

---

## PodDisruptionBudget (PDB) Setup

### Overview

PDB ensures minimum availability during voluntary disruptions (node drains, updates).

### Prerequisites

- At least 2 replicas running
- Cluster has multiple nodes (or anti-affinity is configured)

### Configuration for Multi-Replica

Create `kubedash-pdb.yaml`:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: kubedash-pdb
  namespace: default
spec:
  unhealthyPodEvictionPolicy: IfHealthyBudget
  minAvailable: 1  # Always keep at least 1 pod running
  selector:
    matchLabels:
      app: kubedash
```

### Deploy PDB

```bash
kubectl apply -f kubedash-pdb.yaml

# Verify PDB is working
kubectl get pdb kubedash-pdb

# Check PDB status
kubectl describe pdb kubedash-pdb
```

### Expected Output

```
Name:             kubedash-pdb
Namespace:        default
Min Available:    1
Allowed Disruptions: 1  # Can disrupt 1 pod, keep 1 available
Status:           Normal
Violations:       0 events
```

---

## Pod Disruption Scenarios

### Scenario 1: Node Drain (cluster upgrade)

```bash
# Before drain
kubectl get pods -o wide

# PDB allows disruption only if 1 pod remains
kubectl drain <node> --ignore-daemonsets --delete-emptydir-data

# New pod scheduled on different node
kubectl get pods -o wide
```

### Scenario 2: Operator Shutdown

With PDB active:
- First pod terminates gracefully (5-30 sec)
- Second pod starts up (takes priority)
- No service interruption

### Scenario 3: Emergency Restart

```bash
# PDB is respected even for force deletes
kubectl delete pod <leader-pod> --grace-period=10

# New leader elected automatically
# Service continues without interruption
```

---

## Combined HA Configuration

Helm values for full HA setup:

```yaml
# values.yaml
replicas: 3  # Start with 3 for redundancy

resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 1000m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

podDisruptionBudget:
  enabled: true
  minAvailable: 1

# Pod anti-affinity for spreading across nodes
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
```

### Deploy with Helm

```bash
helm install kubedash ./charts/kubedash \
  -f values.yaml \
  --set replicas=3 \
  --set autoscaling.enabled=true \
  --set podDisruptionBudget.enabled=true
```

---

## Validation

```bash
# 1. Verify HPA is active
kubectl get hpa kubedash-hpa

# 2. Verify PDB is active
kubectl get pdb kubedash-pdb

# 3. Check anti-affinity pod distribution
kubectl get pods -o wide

# 4. Simulate load and verify HPA scales up
# kubectl run -it load-gen --image=busybox --restart=Never -- \
#   /bin/sh -c "while true; do
#     curl http://kubedash:8000/api/cluster/status
#   done"

# 5. Drain a node and verify pods reschedule
# kubectl drain <node> --ignore-daemonsets
```

---

## Troubleshooting

### HPA Not Scaling

```bash
# Check if metrics are available
kubectl get --raw /apis/metrics.k8s.io/v1/nodes | jq .

# Check HPA events
kubectl describe hpa kubedash-hpa

# Verify resource requests are set
kubectl get deployment kubedash -o yaml | grep -A 10 resources
```

### PDB Blocking Maintenance

```bash
# Check if PDB is blocking
kubectl get pdb kubedash-pdb -o yaml

# Temporarily disable if needed (not recommended for production):
# kubectl delete pdb kubedash-pdb
```

### Pods Not Spreading Across Nodes

```bash
# Check pod affinity rules
kubectl get deployment kubedash -o yaml | grep -A 10 affinity

# Check node labels
kubectl get nodes --show-labels

# Adjust affinity if needed
```
