## ADDED Requirements

### Requirement: System supports per-cluster user role assignments
The system SHALL allow administrators to assign different roles to users for different clusters.

#### Scenario: Admin assigns user role for specific cluster
- **WHEN** admin assigns user "alice" role "Admin" for cluster "prod-east"
- **THEN** system creates user_cluster_roles entry linking user, cluster, and role

#### Scenario: User has different roles per cluster
- **WHEN** user "alice" is "Admin" for "prod-east" and "User" for "prod-west"
- **THEN** system evaluates role based on currently selected cluster

#### Scenario: Duplicate role assignment update
- **WHEN** admin assigns role to user for cluster where role already exists
- **THEN** system updates existing role instead of creating duplicate entry

#### Scenario: Role removal
- **WHEN** admin removes user's role from cluster
- **THEN** system deletes corresponding user_cluster_roles entry

### Requirement: System evaluates permissions based on cluster context
The system SHALL evaluate user permissions using both global role and cluster-specific role.

#### Scenario: Cluster-specific role takes precedence
- **WHEN** user has global role "User" but cluster role "Admin" for selected cluster
- **THEN** system grants "Admin" permissions for that cluster only

#### Scenario: No cluster role falls back to global role
- **WHEN** user has no cluster-specific role for selected cluster
- **THEN** system uses user's global role for permission evaluation

#### Scenario: No permissions when no roles exist
- **WHEN** user has no global role and no cluster role for selected cluster
- **THEN** system denies access with "No permissions in this cluster" error

### Requirement: System restricts cluster visibility based on roles
The system SHALL only show clusters where user has explicit or implicit permissions.

#### Scenario: Admin sees all clusters
- **WHEN** user has global "Admin" role
- **THEN** cluster switcher displays all active clusters

#### Scenario: User sees only assigned clusters
- **WHEN** user has global "User" role with cluster assignments
- **THEN** cluster switcher displays only clusters where user has user_cluster_roles entry

#### Scenario: No access to unassigned cluster
- **WHEN** user without admin role attempts to access unassigned cluster via API
- **THEN** system returns 403 Forbidden "No access to cluster '{name}'"

### Requirement: System provides cluster role management UI
The system SHALL provide UI for administrators to manage per-cluster user roles.

#### Scenario: View user's cluster roles
- **WHEN** admin views user details page
- **THEN** page shows table of cluster-specific role assignments

#### Scenario: Add cluster role from UI
- **WHEN** admin selects cluster and role from dropdown and clicks "Add"
- **THEN** system creates cluster role assignment and shows success message

#### Scenario: Edit cluster role from UI
- **WHEN** admin changes role for existing cluster assignment
- **THEN** system updates role and shows confirmation

#### Scenario: Remove cluster role from UI
- **WHEN** admin clicks "Remove" on cluster role assignment
- **THEN** system removes assignment after confirmation and refreshes list

### Requirement: System enforces cluster-scoped RBAC for all operations
The system SHALL evaluate cluster-specific permissions for all Kubernetes resource operations.

#### Scenario: Pod list respects cluster role
- **WHEN** user with "User" role in cluster A requests pod list
- **THEN** system allows request and returns pods from cluster A only

#### Scenario: Pod deletion requires cluster Admin role
- **WHEN** user with "User" role attempts to delete pod in cluster A
- **THEN** system returns 403 Forbidden "Admin role required for cluster A"

#### Scenario: Cross-cluster operation prevention
- **WHEN** user with access to cluster A attempts to access cluster B resources
- **THEN** system returns 403 Forbidden regardless of user's role in cluster A

### Requirement: System supports cluster role templates
The system SHALL provide predefined role templates for common cluster access patterns.

#### Scenario: Viewer role template
- **WHEN** admin assigns "Viewer" template to user for cluster
- **THEN** system grants read-only permissions (list, get, watch) for that cluster

#### Scenario: Operator role template
- **WHEN** admin assigns "Operator" template to user for cluster
- **THEN** system grants read-write permissions except delete and RBAC management

#### Scenario: Admin role template
- **WHEN** admin assigns "Admin" template to user for cluster
- **THEN** system grants full permissions including delete and namespace management

#### Scenario: Custom role definition
- **WHEN** admin defines custom role with specific permissions
- **THEN** system stores custom role and applies to user-cluster assignment

### Requirement: System audits cluster role changes
The system SHALL log all cluster role assignment changes for audit purposes.

#### Scenario: Audit log on role assignment
- **WHEN** admin assigns cluster role to user
- **THEN** system logs audit event with actor, user, cluster, role, timestamp

#### Scenario: Audit log on role removal
- **WHEN** admin removes cluster role from user
- **THEN** system logs audit event with actor, user, cluster, action="role_removed"

#### Scenario: Audit query by cluster
- **WHEN** admin queries audit log for cluster "prod-east"
- **THEN** system returns all role changes for that cluster

### Requirement: System handles cluster deletion role cleanup
The system SHALL handle user roles when clusters are deleted.

#### Scenario: Prevent cluster deletion with existing roles
- **WHEN** admin attempts to delete cluster with user_cluster_roles entries
- **THEN** system returns error "Remove all user roles before deleting cluster"

#### Scenario: Cascade delete option for cluster roles
- **WHEN** admin selects "Delete cluster and remove all roles" option
- **THEN** system deletes cluster and all associated user_cluster_roles entries

#### Scenario: Notify users of cluster removal
- **WHEN** cluster is deleted
- **THEN** system notifies affected users "Cluster '{name}' you had access to has been removed"
