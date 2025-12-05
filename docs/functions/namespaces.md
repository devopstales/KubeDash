# Namespace Management

Namespaces provide a way to divide cluster resources between multiple users or projects. KubeDash offers comprehensive namespace management including creation, deletion, and bulk workload operations.

## Viewing Namespaces

Navigate to `Cluster > Namespaces` to see all namespaces in the cluster:

![Namespace List](../img/cluster/namespace-list.png)

The namespace list shows:

| Column | Description |
|--------|-------------|
| Name | Namespace name |
| Status | Active or Terminating |
| Labels | Applied labels |
| Age | Time since creation |

## Namespace Details

Click on a namespace to view its details:

- **Metadata**: Labels, annotations, creation timestamp
- **Status**: Current phase
- **Resource Quotas**: Applied quotas (if any)
- **Limit Ranges**: Applied limits (if any)
- **Live Workloads**: Count of running workloads

## Creating Namespaces

To create a new namespace:

1. Click the **Add Namespace** button
2. Enter the namespace name
3. Click **Create**

![Create Namespace](../img/cluster/namespace-create.png)

!!! note "Naming Conventions"
    Namespace names must:
    
    - Be lowercase
    - Start with a letter
    - Contain only letters, numbers, and hyphens
    - Be no longer than 63 characters

## Deleting Namespaces

To delete a namespace:

1. Click the delete icon next to the namespace
2. Confirm the deletion

!!! danger "Warning"
    Deleting a namespace will **permanently delete all resources** within it, including:
    
    - Pods, Deployments, StatefulSets, DaemonSets
    - Services, Ingresses
    - ConfigMaps, Secrets
    - PersistentVolumeClaims
    - All other namespaced resources

## Scaling Workloads in a Namespace

KubeDash provides a powerful feature to scale all workloads in a namespace up or down. This is useful for:

- **Cost savings**: Scale down development/staging environments overnight
- **Maintenance**: Temporarily stop all workloads
- **Testing**: Reset a namespace to zero state

### Scale Down (Stop All Workloads)

To scale down all workloads in a namespace:

1. Navigate to `Cluster > Namespaces`
2. Click on the namespace
3. Click **Scale Down**

This will:

| Workload Type | Action |
|--------------|--------|
| Deployments | Scale to 0 replicas, save original count in annotation |
| StatefulSets | Scale to 0 replicas, save original count in annotation |
| DaemonSets | Add node selector to prevent scheduling |

The original replica counts are saved in annotations so they can be restored later.

### Scale Up (Restore All Workloads)

To restore all workloads in a namespace:

1. Navigate to `Cluster > Namespaces`
2. Click on the namespace
3. Click **Scale Up**

This will restore all workloads to their original replica counts using the saved annotations.

!!! tip
    This feature is perfect for development and staging environments where you want to save cluster resources during off-hours.

## Namespace Annotations

KubeDash supports special annotations on namespaces to store project metadata. See [Project Data](../integrations/project-data.md) for details.

| Annotation | Description |
|------------|-------------|
| `metadata.k8s.io/owner` | Project owner username |
| `metadata.k8s.io/description` | Project description |
| `metadata.k8s.io/chat` | Slack channel or chat link |
| `metadata.k8s.io/bugs` | Bug tracker link |
| `metadata.k8s.io/documentation` | Documentation link |
| `metadata.k8s.io/repository` | VCS repository link |
| `metadata.k8s.io/pipeline` | CI/CD pipeline link |

## Best Practices

### Namespace Organization

- Use namespaces to separate environments (dev, staging, prod)
- Use namespaces to separate teams or projects
- Apply resource quotas to prevent resource exhaustion
- Apply limit ranges to set default resource limits

### RBAC per Namespace

KubeDash allows you to assign users and groups to specific namespaces with role templates:

- `template-namespaced-resources---developer`: Read/write for development
- `template-namespaced-resources---operation`: Full admin within namespace
- `template-namespaced-resources---deployer`: Deploy-only access

See [Manage Privileges](rbac.md) for more details.

### Resource Management

Consider applying:

- **Resource Quotas**: Limit total CPU, memory, and object counts
- **Limit Ranges**: Set default and maximum resource requests/limits
- **Network Policies**: Control traffic between namespaces
