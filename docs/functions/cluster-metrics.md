# Cluster Metrics & Dashboard

KubeDash provides a comprehensive dashboard for monitoring cluster health, resource utilization, and events.

## Cluster Metrics Overview

Navigate to `Dashboard > Cluster Metrics` to see the main dashboard:

![Cluster Metrics](../img/dashboard/cluster-metrics.png)

## Resource Metrics

### CPU Metrics

The dashboard displays cluster-wide CPU information:

| Metric | Description |
|--------|-------------|
| **Total CPU** | Sum of all node CPU capacity |
| **Allocatable CPU** | CPU available for scheduling |
| **Used CPU** | Current CPU usage across all pods |
| **Usage %** | Percentage of allocatable CPU used |

### Memory Metrics

The dashboard displays cluster-wide memory information:

| Metric | Description |
|--------|-------------|
| **Total Memory** | Sum of all node memory capacity |
| **Allocatable Memory** | Memory available for scheduling |
| **Used Memory** | Current memory usage across all pods |
| **Usage %** | Percentage of allocatable memory used |

### Visualization

Metrics are displayed as:

- **Gauges**: Real-time utilization percentages
- **Progress bars**: Visual resource consumption
- **Numerical values**: Exact values in appropriate units

```
CPU Usage                    Memory Usage
┌────────────────────┐      ┌────────────────────┐
│ ████████░░░░░░░░░░ │      │ ██████████████░░░░ │
│       42%          │      │        72%         │
│   8.4 / 20 cores   │      │   28.8 / 40 GB    │
└────────────────────┘      └────────────────────┘
```

## Node Summary

The dashboard provides a quick overview of node health:

| Status | Description |
|--------|-------------|
| **Total Nodes** | Total nodes in cluster |
| **Ready** | Nodes in Ready state |
| **Not Ready** | Nodes with issues |
| **Schedulable** | Nodes accepting new pods |

## Cluster Events

The dashboard shows recent cluster events for quick troubleshooting:

![Cluster Events](../img/dashboard/cluster-events.png)

### Event Types

| Type | Color | Description |
|------|-------|-------------|
| **Normal** | Blue/Green | Informational events |
| **Warning** | Yellow/Orange | Potential issues |
| **Error** | Red | Failures and errors |

### Event Information

Each event shows:

| Field | Description |
|-------|-------------|
| **Type** | Normal or Warning |
| **Reason** | Event reason (e.g., Scheduled, Pulled, Created) |
| **Object** | Related Kubernetes object |
| **Message** | Detailed event message |
| **Age** | Time since event occurred |
| **Count** | Number of occurrences |

### Common Events

| Reason | Description |
|--------|-------------|
| `Scheduled` | Pod scheduled to node |
| `Pulled` | Container image pulled |
| `Created` | Container created |
| `Started` | Container started |
| `Killing` | Container being killed |
| `BackOff` | Container restart backoff |
| `FailedScheduling` | Pod couldn't be scheduled |
| `Unhealthy` | Health check failed |

## Workload Map

Navigate to `Dashboard > Workload Map` to see a visual representation of resources:

![Workload Map](../img/dashboard/workload-map.png)

### Visualization Features

The workload map shows:

- **Pods**: Individual pod nodes
- **Services**: Service connections
- **Deployments**: Deployment groupings
- **Connections**: Network relationships

### Namespace Filtering

Select a namespace to view resources within that namespace:

1. Use the namespace dropdown
2. The map updates to show only selected namespace resources
3. Connections to resources in other namespaces are indicated

### Node Information

Each node in the map displays:

- Resource name
- Resource type (icon)
- Status (color coding)
- Click for detailed information

### Connection Types

| Connection | Description |
|------------|-------------|
| **Pod → Service** | Pod exposed by service |
| **Service → Ingress** | Service exposed via ingress |
| **Deployment → Pod** | Pods managed by deployment |

## Health Indicators

### Color Coding

| Color | Status |
|-------|--------|
| 🟢 Green | Healthy/Running |
| 🟡 Yellow | Warning/Pending |
| 🔴 Red | Error/Failed |
| ⚪ Gray | Unknown/Terminating |

### Resource Health

| Resource | Healthy Condition |
|----------|------------------|
| Node | Ready = True |
| Pod | Phase = Running, All containers ready |
| Deployment | Available replicas = Desired replicas |
| Service | Endpoints available |

## Metrics Requirements

### Prerequisites

To display metrics, you need:

1. **metrics-server**: For CPU/memory metrics
   ```bash
   kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
   ```

2. **Proper RBAC**: Service account needs metrics access

### Troubleshooting Metrics

**No metrics displayed:**

1. Check metrics-server is running:
   ```bash
   kubectl get pods -n kube-system | grep metrics-server
   ```

2. Verify metrics API:
   ```bash
   kubectl get --raw /apis/metrics.k8s.io/v1beta1/nodes
   ```

3. Check KubeDash service account permissions

## Best Practices

### Dashboard Usage

- Check dashboard daily for cluster health
- Investigate warning events promptly
- Monitor resource trends over time
- Use workload map for dependency understanding

### Alerting

The dashboard is for observation. For alerting, consider:

- Prometheus + AlertManager
- Cloud provider monitoring
- Third-party monitoring solutions

### Capacity Planning

Use dashboard metrics to:

- Track utilization trends
- Plan node additions
- Identify resource-hungry workloads
- Optimize resource requests/limits

## Refresh and Real-time Updates

### Auto-refresh

The dashboard can auto-refresh at configurable intervals:

- Manual refresh: Click refresh button
- Auto-refresh: Set interval in settings

### WebSocket Updates

Some components receive real-time updates via WebSocket:

- Pod logs (streaming)
- Event updates
- Status changes
