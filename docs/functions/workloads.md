# Workload Management

KubeDash provides comprehensive management capabilities for all Kubernetes workload types. You can view, inspect, scale, and manage your applications directly from the web UI.

## Pods

Pods are the smallest deployable units in Kubernetes. KubeDash allows you to:

- **List pods** in any namespace
- **View pod details** including containers, volumes, and status
- **Delete pods** for troubleshooting or forcing recreation

### Viewing Pods

Navigate to `Workloads > Pods` to see all pods in the selected namespace:

![Pod List](../img/workloads/pod-list.png)

The pod list shows:

| Column | Description |
|--------|-------------|
| Name | Pod name |
| Ready | Number of ready containers vs total |
| Status | Current pod phase (Running, Pending, etc.) |
| Restarts | Total container restart count |
| Age | Time since pod creation |

### Pod Details

Click on a pod to view its details:

- **Metadata**: Labels, annotations, creation timestamp
- **Containers**: Image, ports, environment variables, resource requests/limits
- **Volumes**: Mounted volumes and their sources
- **Conditions**: Pod conditions and their status
- **Events**: Recent events related to the pod

### Deleting Pods

To delete a pod, click the delete icon next to the pod name. This is useful for:

- Forcing a pod to be rescheduled
- Clearing pods in error states
- Testing pod disruption budgets

!!! warning
    Deleting a pod managed by a controller (Deployment, StatefulSet, etc.) will cause it to be recreated automatically.

## Deployments

Deployments provide declarative updates for Pods and ReplicaSets.

### Viewing Deployments

Navigate to `Workloads > Deployments` to see all deployments:

![Deployment List](../img/workloads/deployment-list.png)

The deployment list shows:

| Column | Description |
|--------|-------------|
| Name | Deployment name |
| Ready | Ready replicas vs desired |
| Up-to-date | Replicas with latest template |
| Available | Available replicas |
| Age | Time since creation |

### Deployment Details

Click on a deployment to view:

- **Spec**: Replicas, strategy, selector
- **Template**: Pod template specification
- **Status**: Current deployment status and conditions
- **Labels & Annotations**: Metadata

### Scaling Deployments

You can scale deployments directly from the UI:

1. Click on the deployment
2. Enter the desired replica count
3. Click "Scale"

The deployment will gradually scale to the desired number of replicas according to its update strategy.

## StatefulSets

StatefulSets manage stateful applications with stable network identities and persistent storage.

### Viewing StatefulSets

Navigate to `Workloads > StatefulSets` to see all StatefulSets:

![StatefulSet List](../img/workloads/statefulset-list.png)

### StatefulSet Details

Click on a StatefulSet to view:

- **Spec**: Replicas, update strategy, pod management policy
- **Volume Claim Templates**: PVC templates for persistent storage
- **Status**: Current and ready replicas

### Scaling StatefulSets

StatefulSets can be scaled up or down:

1. Click on the StatefulSet
2. Enter the desired replica count
3. Click "Scale"

!!! note
    StatefulSets scale pods in order (0, 1, 2, ...) and scale down in reverse order.

## DaemonSets

DaemonSets ensure that all (or some) nodes run a copy of a pod.

### Viewing DaemonSets

Navigate to `Workloads > DaemonSets` to see all DaemonSets:

![DaemonSet List](../img/workloads/daemonset-list.png)

The DaemonSet list shows:

| Column | Description |
|--------|-------------|
| Name | DaemonSet name |
| Desired | Number of nodes that should run the pod |
| Current | Number of nodes running the pod |
| Ready | Number of ready pods |
| Age | Time since creation |

### DaemonSet Details

Click on a DaemonSet to view:

- **Spec**: Selector, update strategy
- **Template**: Pod template specification
- **Status**: Desired, current, ready, and available counts

### Scaling DaemonSets

DaemonSets can be "scaled down" by modifying the node selector to match no nodes:

1. Click on the DaemonSet
2. Select "Scale Down" to pause the DaemonSet
3. Select "Scale Up" to restore normal operation

## ReplicaSets

ReplicaSets maintain a stable set of replica pods. They are typically managed by Deployments.

### Viewing ReplicaSets

Navigate to `Workloads > ReplicaSets` to see all ReplicaSets:

![ReplicaSet List](../img/workloads/replicaset-list.png)

The ReplicaSet list shows:

| Column | Description |
|--------|-------------|
| Name | ReplicaSet name |
| Desired | Desired number of replicas |
| Current | Current number of replicas |
| Ready | Number of ready replicas |
| Age | Time since creation |

!!! tip
    ReplicaSets are usually managed by Deployments. Editing them directly is not recommended unless you have a specific reason.
