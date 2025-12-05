# Autoscaling & Resource Management

KubeDash provides visibility into Kubernetes autoscaling and resource management features including Horizontal Pod Autoscalers (HPA), Vertical Pod Autoscalers (VPA), Pod Disruption Budgets (PDB), Resource Quotas, and Limit Ranges.

## Horizontal Pod Autoscaler (HPA)

HPAs automatically scale the number of pod replicas based on observed metrics.

### Viewing HPAs

Navigate to `Other Resources > Horizontal Pod Autoscaler` to see all HPAs in the selected namespace:

![HPA List](../img/autoscaling/hpa-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | HPA name |
| Reference | Target deployment/statefulset |
| Min Pods | Minimum replicas |
| Max Pods | Maximum replicas |
| Current | Current replica count |
| Targets | Current vs target metrics |
| Age | Time since creation |

### HPA Details

Click on an HPA to view:

- **Scale Target**: Deployment, StatefulSet, or other scalable resource
- **Min/Max Replicas**: Scaling boundaries
- **Metrics**: CPU, memory, or custom metrics
- **Current Metrics**: Real-time metric values
- **Conditions**: Scaling status and events

### Metrics Types

| Metric Type | Description |
|-------------|-------------|
| **Resource** | CPU or memory utilization |
| **Pods** | Custom metrics per pod |
| **Object** | Metrics from other Kubernetes objects |
| **External** | Metrics from external systems |

### HPA Behavior

```
Replicas
    ▲
Max │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─
    │                    ╱────────
    │                   ╱
    │              ╱───╱
    │         ╱───╱
    │    ╱───╱
Min │───╱
    └──────────────────────────────▶ Load
```

## Vertical Pod Autoscaler (VPA)

VPAs automatically adjust CPU and memory requests/limits for containers.

### Viewing VPAs

Navigate to `Other Resources > Vertical Pod Autoscaler` to see all VPAs in the selected namespace:

![VPA List](../img/autoscaling/vpa-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | VPA name |
| Mode | Off, Initial, Auto |
| Target | Target deployment/statefulset |
| Recommendations | Current resource recommendations |
| Age | Time since creation |

### VPA Details

Click on a VPA to view:

- **Target**: Workload being managed
- **Update Policy**: How updates are applied
- **Resource Policy**: Min/max resource boundaries
- **Recommendations**: Suggested resource values

### Update Modes

| Mode | Description |
|------|-------------|
| `Off` | Only provides recommendations |
| `Initial` | Sets resources on pod creation |
| `Auto` | Updates running pods (may restart) |

### VPA Recommendations

VPA provides recommendations for:

| Field | Description |
|-------|-------------|
| **Lower Bound** | Minimum recommended resources |
| **Target** | Optimal resource values |
| **Upper Bound** | Maximum recommended resources |
| **Uncapped Target** | Target without policy limits |

## Pod Disruption Budget (PDB)

PDBs limit the number of pods that can be unavailable during voluntary disruptions.

### Viewing PDBs

Navigate to `Other Resources > Pod Disruption Budget` to see all PDBs in the selected namespace:

![PDB List](../img/autoscaling/pdb-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | PDB name |
| Min Available | Minimum pods that must be available |
| Max Unavailable | Maximum pods that can be unavailable |
| Current | Current healthy pods |
| Desired | Desired pod count |
| Age | Time since creation |

### PDB Details

Click on a PDB to view:

- **Selector**: Which pods the PDB protects
- **Min Available**: Minimum available pods (number or percentage)
- **Max Unavailable**: Maximum unavailable pods (number or percentage)
- **Status**: Current healthy, desired, and disruptions allowed

### PDB Configuration Options

| Field | Example | Description |
|-------|---------|-------------|
| `minAvailable` | `2` or `50%` | Minimum pods that must stay running |
| `maxUnavailable` | `1` or `25%` | Maximum pods that can be down |

!!! note
    You can only specify one of `minAvailable` or `maxUnavailable`, not both.

## Resource Quotas

Resource Quotas limit aggregate resource consumption per namespace.

### Viewing Resource Quotas

Navigate to `Other Resources > Resource Quota` to see all quotas in the selected namespace:

![Resource Quota List](../img/autoscaling/quota-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Quota name |
| Age | Time since creation |

### Resource Quota Details

Click on a quota to view:

- **Hard Limits**: Maximum allowed values
- **Used**: Current usage
- **Scopes**: Optional quota scopes

### Quotable Resources

| Resource | Description |
|----------|-------------|
| `requests.cpu` | Total CPU requests |
| `requests.memory` | Total memory requests |
| `limits.cpu` | Total CPU limits |
| `limits.memory` | Total memory limits |
| `pods` | Total number of pods |
| `services` | Total number of services |
| `secrets` | Total number of secrets |
| `configmaps` | Total number of configmaps |
| `persistentvolumeclaims` | Total number of PVCs |
| `requests.storage` | Total storage requested |

### Quota Status Display

```
Resource Quota: team-quota
┌────────────────────┬───────────┬───────────┐
│ Resource           │ Used      │ Hard      │
├────────────────────┼───────────┼───────────┤
│ requests.cpu       │ 4         │ 10        │
│ requests.memory    │ 8Gi       │ 20Gi      │
│ limits.cpu         │ 8         │ 20        │
│ limits.memory      │ 16Gi      │ 40Gi      │
│ pods               │ 12        │ 50        │
│ services           │ 3         │ 10        │
└────────────────────┴───────────┴───────────┘
```

## Limit Ranges

Limit Ranges set default, minimum, and maximum resource constraints for containers in a namespace.

### Viewing Limit Ranges

Navigate to `Other Resources > Limit Range` to see all limit ranges in the selected namespace:

![Limit Range List](../img/autoscaling/limitrange-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Limit range name |
| Age | Time since creation |

### Limit Range Details

Click on a limit range to view:

- **Type**: Container, Pod, or PersistentVolumeClaim
- **Default**: Default values applied to containers
- **Default Request**: Default request values
- **Min**: Minimum allowed values
- **Max**: Maximum allowed values
- **Max Limit/Request Ratio**: Maximum ratio between limits and requests

### Limit Range Types

| Type | Description |
|------|-------------|
| `Container` | Per-container constraints |
| `Pod` | Per-pod aggregate constraints |
| `PersistentVolumeClaim` | Storage constraints |

### Example Limit Range

```yaml
limits:
  - type: Container
    default:
      cpu: 500m
      memory: 256Mi
    defaultRequest:
      cpu: 100m
      memory: 128Mi
    min:
      cpu: 50m
      memory: 64Mi
    max:
      cpu: 2
      memory: 2Gi
```

## Best Practices

### HPA Configuration

- Set appropriate min/max boundaries
- Use stabilization windows to prevent thrashing
- Monitor scaling behavior
- Consider using custom metrics for better accuracy

### VPA Configuration

- Start with "Off" mode to observe recommendations
- Set resource policies to prevent extreme values
- Coordinate with HPAs (avoid conflicts)
- Monitor pod restarts

### PDB Configuration

- Always create PDBs for production workloads
- Set reasonable availability requirements
- Account for deployment update strategies
- Test disruption behavior

### Resource Quota Strategy

- Set quotas per team/project namespace
- Leave headroom for scaling
- Monitor quota usage trends
- Review and adjust periodically

### Limit Range Strategy

- Set sensible defaults for your workloads
- Use min/max to prevent resource abuse
- Align with cluster capacity
- Document defaults for developers

## Troubleshooting

### HPA Not Scaling

1. Verify metrics-server is running
2. Check target resource has requests set
3. Review HPA events for errors
4. Verify metric values are reported

### VPA Recommendations Wrong

1. Wait for sufficient observation period
2. Check resource policy constraints
3. Verify metrics are accurate
4. Review container startup behavior

### PDB Blocking Eviction

1. Check current healthy pod count
2. Verify PDB configuration
3. Scale up before maintenance
4. Review disruption budget
