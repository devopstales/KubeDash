# Node Management

KubeDash provides visibility into your cluster's nodes, including their status, resources, and metrics.

## Viewing Nodes

Navigate to `Cluster > Nodes` to see all nodes in the cluster:

![Node List](../img/cluster/node-list.png)

The node list shows:

| Column | Description |
|--------|-------------|
| Name | Node hostname |
| Status | Ready, NotReady, SchedulingDisabled |
| Roles | control-plane, worker, etc. |
| Version | Kubernetes version |
| Age | Time since node joined cluster |
| CPU | CPU usage / allocatable |
| Memory | Memory usage / allocatable |

## Node Details

Click on a node to view comprehensive details:

### System Information

| Field | Description |
|-------|-------------|
| **Architecture** | CPU architecture (amd64, arm64) |
| **OS** | Operating system (linux, windows) |
| **OS Image** | Full OS image name |
| **Kernel Version** | Linux kernel version |
| **Container Runtime** | containerd, docker, cri-o |
| **Kubelet Version** | Kubelet version |

### Capacity & Allocatable

| Resource | Capacity | Allocatable |
|----------|----------|-------------|
| CPU | Total CPU cores | Available for pods |
| Memory | Total memory | Available for pods |
| Pods | Max pods | Available pod slots |
| Ephemeral Storage | Total storage | Available storage |

!!! note
    "Allocatable" is less than "Capacity" because the system reserves resources for kubelet, OS, and other system components.

### Node Conditions

| Condition | Healthy Value | Description |
|-----------|---------------|-------------|
| Ready | True | Node is healthy and ready |
| MemoryPressure | False | No memory pressure |
| DiskPressure | False | No disk pressure |
| PIDPressure | False | No process ID pressure |
| NetworkUnavailable | False | Network is configured |

### Node Labels

Common node labels include:

| Label | Description |
|-------|-------------|
| `kubernetes.io/hostname` | Node hostname |
| `kubernetes.io/os` | Operating system |
| `kubernetes.io/arch` | CPU architecture |
| `node.kubernetes.io/instance-type` | Cloud instance type |
| `topology.kubernetes.io/zone` | Availability zone |
| `topology.kubernetes.io/region` | Cloud region |

### Node Annotations

Annotations store additional metadata:

| Annotation | Description |
|------------|-------------|
| `node.alpha.kubernetes.io/ttl` | Node TTL |
| `volumes.kubernetes.io/controller-managed-attach-detach` | Volume attach mode |

### Taints

Taints prevent pods from scheduling on nodes unless they have matching tolerations:

| Taint | Effect | Description |
|-------|--------|-------------|
| `node-role.kubernetes.io/control-plane` | NoSchedule | Control plane node |
| `node.kubernetes.io/not-ready` | NoExecute | Node not ready |
| `node.kubernetes.io/unreachable` | NoExecute | Node unreachable |
| `node.kubernetes.io/disk-pressure` | NoSchedule | Disk pressure |
| `node.kubernetes.io/memory-pressure` | NoSchedule | Memory pressure |

## Node Metrics

KubeDash displays real-time metrics for each node when metrics-server is installed:

### CPU Metrics

- **Usage**: Current CPU utilization
- **Requests**: Total CPU requested by pods
- **Limits**: Total CPU limits set by pods
- **Allocatable**: CPU available for scheduling

### Memory Metrics

- **Usage**: Current memory utilization
- **Requests**: Total memory requested by pods
- **Limits**: Total memory limits set by pods
- **Allocatable**: Memory available for scheduling

### Metrics Visualization

The node detail page includes:

- CPU usage gauge/chart
- Memory usage gauge/chart
- Historical usage trends (if available)

!!! tip
    Install [metrics-server](https://github.com/kubernetes-sigs/metrics-server) to enable resource metrics collection.

## Cluster Metrics Overview

The Nodes page also shows aggregate cluster metrics:

| Metric | Description |
|--------|-------------|
| Total Nodes | Number of nodes in cluster |
| Ready Nodes | Nodes in Ready state |
| Total CPU | Sum of all node CPU |
| Total Memory | Sum of all node memory |
| CPU Usage | Cluster-wide CPU utilization |
| Memory Usage | Cluster-wide memory utilization |

## Best Practices

### Node Monitoring

- Monitor node conditions for early warning signs
- Set up alerts for NotReady nodes
- Track resource utilization trends
- Monitor disk and network I/O

### Capacity Planning

- Track allocatable vs used resources
- Plan for headroom (20-30% free capacity)
- Consider pod density limits
- Account for DaemonSet overhead

### Node Maintenance

- Use `kubectl drain` before maintenance
- Cordon nodes to prevent new scheduling
- Plan rolling updates for node upgrades

### Labels and Taints

- Use labels for workload placement
- Apply taints for dedicated nodes
- Document your labeling strategy
- Use node affinity for critical workloads

## Troubleshooting

### Node NotReady

Common causes:

1. **Kubelet issues**: Check kubelet service status
2. **Network problems**: Verify node network connectivity
3. **Resource exhaustion**: Check disk, memory, PIDs
4. **Certificate issues**: Verify kubelet certificates

### Node Disk Pressure

Solutions:

1. Clean up unused images: `crictl rmi --prune`
2. Remove old pods/containers
3. Expand node disk
4. Review PVC usage on the node

### Node Memory Pressure

Solutions:

1. Review memory requests/limits
2. Identify memory-hungry pods
3. Consider vertical scaling
4. Add memory to the node
