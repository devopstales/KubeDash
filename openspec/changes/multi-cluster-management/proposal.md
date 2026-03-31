## Why

KubeDash currently supports only a single Kubernetes cluster connection at a time, limiting its usefulness for platform teams managing multiple clusters. This change enables true multi-cluster management, allowing users to view, switch between, and manage resources across multiple Kubernetes clusters from a single dashboard instance.

## What Changes

- **Cluster Registry**: New database model and UI to register/manage multiple cluster configurations (name, API server URL, CA cert, connection method)
- **Cluster Context Switching**: UI component to switch between registered clusters; cluster selection persisted per user session
- **Per-Cluster Resource Views**: All resource blueprints (workloads, network, storage, etc.) query the currently selected cluster
- **Cluster Health Dashboard**: Overview page showing all registered clusters with connection status, version, node count, and health indicators
- **Multi-Cluster RBAC**: User permissions evaluated per cluster (users may have different roles in different clusters)
- **Extension API Updates**: Support cluster-scoped queries via query parameters (e.g., `?cluster=cluster-name`)
- **Default Cluster Behavior**: System boots with a default cluster; admins can change default via settings

**BREAKING**: 
- Existing single-cluster configuration migrates to default cluster named `default`
- Extension API consumers must specify cluster context for multi-cluster queries (backward compatible with single-cluster deployments)

## Capabilities

### New Capabilities
- `cluster-registry`: CRUD operations for cluster configurations, connection testing, cluster metadata discovery
- `cluster-context-switching`: UI and session management for cluster selection, cluster-aware navigation
- `cluster-health-monitor`: Real-time cluster connectivity status, version detection, resource counts
- `multi-cluster-rbac`: Per-cluster role assignments, cluster-scoped permission evaluation

### Modified Capabilities
- `extension-api`: Add cluster query parameter support, return cluster context in responses
- `resource-blueprints`: All resource queries (pods, deployments, services, etc.) execute against selected cluster context

## Impact

**Code Changes**:
- `lib/k8s/server.py`: Refactor client loading to accept cluster context parameter
- All blueprint API endpoints: Add cluster context resolution middleware
- `blueprint/cluster/`: New cluster registry management UI and API
- `blueprint/dashboard/`: Cluster switcher component, cluster health widgets
- `blueprint/auth/`: Per-cluster RBAC evaluation
- Extension API: Cluster routing logic

**Database**:
- New `cluster_registry` table (replaces single `k8s_cluster_config`)
- Migration script to migrate existing config to new schema
- New `user_cluster_roles` table for per-cluster permissions

**APIs**:
- New REST endpoints: `/api/v1/clusters/*` for cluster management
- Existing resource endpoints accept optional `?cluster=` query parameter
- Extension API: `/apis/kubedash.io/v1/clusters/<name>/...` for cluster-scoped resources

**Dependencies**:
- No new external dependencies
- Kubernetes Python client already supports multi-kubeconfig contexts

**User Experience**:
- Cluster switcher in global navigation (always visible)
- Cluster health indicators (color-coded status badges)
- Default cluster auto-selected on login
- Users see only clusters they have permission to access
