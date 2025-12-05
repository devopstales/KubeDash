# Cluster Permissions

KubeDash provides visibility into Kubernetes RBAC (Role-Based Access Control) resources including Service Accounts, Roles, RoleBindings, ClusterRoles, and ClusterRoleBindings.

## Service Accounts

Service Accounts provide an identity for processes running in pods.

### Viewing Service Accounts

Navigate to `Cluster Permissions > Service Accounts` to see all service accounts in the selected namespace:

![Service Account List](../img/permissions/service-account-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Service account name |
| Secrets | Number of associated secrets |
| Age | Time since creation |

### Default Service Account

Every namespace has a `default` service account that pods use unless another is specified.

### Service Account Usage

Service accounts are used for:

- Pod identity for API server authentication
- Image pull secrets
- Workload identity for cloud providers
- RBAC authorization

## Roles

Roles define permissions within a single namespace.

### Viewing Roles

Navigate to `Cluster Permissions > Roles` to see all roles in the selected namespace:

![Role List](../img/permissions/role-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Role name |
| Rules | Number of permission rules |
| Age | Time since creation |

### Role Details

Click on a role to view its permissions:

- **API Groups**: Which API groups the rules apply to
- **Resources**: Which resources can be accessed
- **Verbs**: Allowed operations (get, list, watch, create, update, delete, etc.)

### Permission Verbs

| Verb | Description |
|------|-------------|
| `get` | Read a single resource |
| `list` | List resources |
| `watch` | Watch for changes |
| `create` | Create new resources |
| `update` | Update existing resources |
| `patch` | Partially update resources |
| `delete` | Delete resources |
| `deletecollection` | Delete multiple resources |

### Example Role Structure

```yaml
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch", "create", "update", "delete"]
```

## Role Bindings

RoleBindings grant the permissions defined in a Role to users, groups, or service accounts within a namespace.

### Viewing Role Bindings

Navigate to `Cluster Permissions > Role Bindings` to see all role bindings in the selected namespace:

![RoleBinding List](../img/permissions/rolebinding-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | RoleBinding name |
| Role | Referenced Role or ClusterRole |
| Subjects | Users, groups, or service accounts |
| Age | Time since creation |

### Subject Types

| Type | Description |
|------|-------------|
| `User` | Kubernetes user |
| `Group` | Kubernetes group |
| `ServiceAccount` | Service account in a namespace |

## Cluster Roles

ClusterRoles define permissions cluster-wide or across all namespaces.

### Viewing Cluster Roles

Navigate to `Cluster Permissions > Cluster Roles` to see all cluster roles:

![ClusterRole List](../img/permissions/clusterrole-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | ClusterRole name |
| Rules | Number of permission rules |
| Age | Time since creation |

### ClusterRole Details

Click on a cluster role to view its permissions, similar to Roles but with additional capabilities:

- **Non-namespaced resources**: nodes, persistentvolumes, etc.
- **Non-resource URLs**: /healthz, /metrics, etc.
- **Aggregation rules**: Combine multiple ClusterRoles

### Built-in ClusterRoles

| ClusterRole | Description |
|-------------|-------------|
| `cluster-admin` | Full cluster access |
| `admin` | Full access within a namespace |
| `edit` | Read/write access to most resources |
| `view` | Read-only access to most resources |

### KubeDash Role Templates

KubeDash provides pre-configured templates for common use cases:

| Template | Scope | Description |
|----------|-------|-------------|
| `template-cluster-resources---admin` | Cluster | Full cluster admin |
| `template-cluster-resources---reader` | Cluster | Cluster read-only |
| `template-namespaced-resources---deployer` | Namespace | Deploy workloads |
| `template-namespaced-resources---developer` | Namespace | Developer access |
| `template-namespaced-resources---operation` | Namespace | Namespace admin |

## Cluster Role Bindings

ClusterRoleBindings grant ClusterRole permissions cluster-wide.

### Viewing Cluster Role Bindings

Navigate to `Cluster Permissions > Cluster Role Bindings` to see all cluster role bindings:

![ClusterRoleBinding List](../img/permissions/clusterrolebinding-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | ClusterRoleBinding name |
| Role | Referenced ClusterRole |
| Subjects | Users, groups, or service accounts |
| Age | Time since creation |

## Managing Permissions with KubeDash

KubeDash provides a simplified interface for managing RBAC. See:

- [Manage User Roles](rbac.md#manage-user-roles) - Assign permissions to users
- [Manage Group Roles](rbac.md#manage-group-roles) - Assign permissions to SSO groups

### Assigning Permissions

1. Navigate to `User Management > Users`
2. Click on a user's privilege icon
3. Select appropriate role templates
4. Choose namespaces (for namespaced roles)
5. Save changes

### Role Template Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    Role Template Selection                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Cluster Role:  [template-cluster-resources---reader    ▼]  │
│                                                              │
│  Namespace Role 1:                                           │
│    Template: [template-namespaced-resources---developer ▼]  │
│    Namespaces: [✓ dev] [✓ staging] [ ] prod                 │
│    [✓ All namespaces                                        │
│                                                              │
│  Namespace Role 2:                                           │
│    Template: [template-namespaced-resources---operation ▼]  │
│    Namespaces: [ ] dev [ ] staging [✓] prod                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Best Practices

### Least Privilege

- Grant minimum required permissions
- Use namespaced roles when possible
- Avoid cluster-admin for regular users
- Review permissions regularly

### Audit and Monitoring

- Enable RBAC audit logging
- Monitor privilege escalation attempts
- Track role binding changes
- Review service account usage

### Organization

- Use consistent naming conventions
- Document role purposes
- Group related permissions
- Use role aggregation for complex scenarios

### Service Account Security

- Create dedicated service accounts per workload
- Don't use default service account for applications
- Disable auto-mounting when not needed
- Apply minimal permissions

## Troubleshooting

### Permission Denied Errors

1. Check user/service account identity
2. Verify role bindings exist
3. Confirm role has required verbs
4. Check namespace scope

### Common Issues

| Error | Cause | Solution |
|-------|-------|----------|
| `forbidden` | Missing permission | Add appropriate role binding |
| `cannot list resource` | Missing `list` verb | Update role to include `list` |
| `unauthorized` | Authentication failed | Verify credentials/token |
