### PRD: Multi‑Cluster Management

**OpenSpec change**: `openspec/changes/multi-cluster-management/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

Many users operate **multiple Kubernetes clusters** (prod, staging, regions, tenants), but:

- Today, KubeDash is primarily focused on a **single cluster context**.
- Operators must juggle separate dashboards or browser tabs to see cluster health and switch contexts.

We want KubeDash to provide a **coherent multi‑cluster experience**.

#### Goals

- Introduce a **cluster registry** KubeDash can use to discover and configure multiple clusters.
- Provide a simple UX for **cluster context switching** in the UI.
- Surface **per‑cluster health** and basic status in a central view.

#### Functional Requirements

- **Cluster Registry**
  - Represent clusters as first‑class entities (e.g. name, API endpoint, credentials/config, labels).
  - Support at least:
    - Static configuration (e.g. via config file/env).
    - DB‑backed storage so clusters can be added/edited from KubeDash (if enabled).
- **Cluster Health Monitoring**
  - Periodically probe each registered cluster for:
    - API server reachability.
    - Basic readiness signals (e.g. core components up, metrics availability).
  - Persist and expose health data for display in UI and via API.
- **Cluster Context Switching**
  - Allow users to switch active clusters from the KubeDash UI.
  - Respect user permissions per cluster; a user may have access to only a subset of registered clusters.
  - Clearly indicate the current cluster context in all views.

#### Non‑Functional Requirements

- **Scalability**
  - Design should handle at least dozens of clusters gracefully.
- **Security**
  - Credentials for each cluster must be stored securely and never exposed in logs or UI.
  - Multi‑cluster RBAC must ensure users cannot access clusters they are not authorized to.

---

### Implementation Tasks (from OpenSpec)

#### 1. Database Schema and Migration

- [ ] 1.1 Create Alembic migration for `cluster_registry` table.
- [ ] 1.2 Create Alembic migration for `user_cluster_roles` table.
- [ ] 1.3 Implement migration script to copy existing `k8s_cluster_config` to `cluster_registry` as `default` cluster.
- [ ] 1.4 Add backup and rollback procedures for migration.
- [ ] 1.5 Update database models in `lib/components/db.py` or equivalent.
- [ ] 1.6 Create SQLAlchemy models for `ClusterRegistry` and `UserClusterRole`.
- [ ] 1.7 Add foreign key constraints and indexes for performance.

#### 2. Core Kubernetes Client Refactoring

- [ ] 2.1 Create new `lib/k8s/context.py` module for cluster context resolution.
- [ ] 2.2 Implement `@cluster_context` decorator for blueprint routes.
- [ ] 2.3 Refactor `k8sClientConfigGet()` to accept `cluster_name` parameter.
- [ ] 2.4 Implement connection pooling with LRU eviction (max 100 connections).
- [ ] 2.5 Add TTL‑based cache invalidation for client connections.
- [ ] 2.6 Update `k8sServerConfigList()` to return all clusters from registry.
- [ ] 2.7 Implement `get_k8s_client(cluster_name, user_role, user_token)` function.
- [ ] 2.8 Add error handling for cluster‑not‑found scenarios.

#### 3. Cluster Registry API Endpoints

- [ ] 3.1 Create `blueprint/cluster/registry.py` with Flask blueprint.
- [ ] 3.2 Implement `GET /api/v1/clusters` – list all clusters.
- [ ] 3.3 Implement `POST /api/v1/clusters` – create new cluster.
- [ ] 3.4 Implement `GET /api/v1/clusters/{name}` – get cluster details.
- [ ] 3.5 Implement `PUT /api/v1/clusters/{name}` – update cluster.
- [ ] 3.6 Implement `DELETE /api/v1/clusters/{name}` – delete cluster.
- [ ] 3.7 Implement `POST /api/v1/clusters/{name}/test-connection` – validate connectivity.
- [ ] 3.8 Implement `GET /api/v1/clusters/health` – get health status for all clusters.
- [ ] 3.9 Implement `GET /api/v1/clusters/{name}/health` – get single cluster health.
- [ ] 3.10 Add request validation and error responses for all endpoints.
- [ ] 3.11 Add audit logging for cluster CRUD operations.

#### 4. Cluster Health Monitoring

- [ ] 4.1 Create `lib/k8s/health.py` module for health check logic.
- [ ] 4.2 Implement `check_cluster_health(cluster)` function.
- [ ] 4.3 Integrate APScheduler for periodic health checks (60‑second interval).
- [ ] 4.4 Implement health check scheduler startup/shutdown lifecycle.
- [ ] 4.5 Add health status update logic (healthy/unhealthy/unreachable/unknown).
- [ ] 4.6 Implement Kubernetes metadata discovery (version, node count, namespace count).
- [ ] 4.7 Add OpenTelemetry metrics for health check duration and results.
- [ ] 4.8 Create Prometheus metrics endpoints for cluster health gauges.

#### 5. Cluster Context Switching UI

- [ ] 5.1 Design cluster switcher dropdown component (Bootstrap 5).
- [ ] 5.2 Create cluster switcher HTML/JavaScript component.
- [ ] 5.3 Add cluster switcher to base template (global navigation).
- [ ] 5.4 Implement cluster switch API endpoint `/api/v1/clusters/switch`.
- [ ] 5.5 Add session management for `session['current_cluster']`.
- [ ] 5.6 Implement cluster switch with page reload.
- [ ] 5.7 Add cluster health indicators (colored badges) to switcher.
- [ ] 5.8 Create cluster metadata tooltips (version, URL, node count).
- [ ] 5.9 Add JavaScript for cluster switcher dynamic updates.
- [ ] 5.10 Implement cluster switch error handling and notifications.

#### 6. Cluster Management UI

- [ ] 6.1 Create cluster list page for admins (`/settings/clusters`).
- [ ] 6.2 Implement cluster registration form (name, URL, CA cert, connection type).
- [ ] 6.3 Create cluster edit modal/page.
- [ ] 6.4 Implement cluster deletion with confirmation dialog.
- [ ] 6.5 Add cluster health dashboard page (`/settings/clusters/health`).
- [ ] 6.6 Create cluster health cards with status indicators.
- [ ] 6.7 Add “Add Cluster” wizard with connection test step.
- [ ] 6.8 Implement CA certificate file upload handling.
- [ ] 6.9 Add kubeconfig file parser for bulk cluster import.
- [ ] 6.10 Create cluster metadata display (version, platform, stats).

#### 7. Multi‑Cluster RBAC Implementation

- [ ] 7.1 Create `blueprint/cluster/rbac.py` for cluster role management.
- [ ] 7.2 Implement `GET /api/v1/clusters/{name}/users` – list user roles.
- [ ] 7.3 Implement `POST /api/v1/clusters/{name}/users` – assign role.
- [ ] 7.4 Implement `PUT /api/v1/clusters/{name}/users/{user_id}` – update role.
- [ ] 7.5 Implement `DELETE /api/v1/clusters/{name}/users/{user_id}` – remove role.
- [ ] 7.6 Update permission evaluation logic to check cluster‑specific roles.
- [ ] 7.7 Add cluster role templates (Viewer, Operator, Admin).
- [ ] 7.8 Implement custom role definition storage.
- [ ] 7.9 Create UI for managing cluster‑specific user roles.
- [ ] 7.10 Add cluster role assignment to user detail page.

#### 8. Blueprint Integration – Cluster Context Resolution

- [ ] 8.1 Add `@cluster_context` decorator to all `blueprint/workload` routes.
- [ ] 8.2 Add `@cluster_context` decorator to all `blueprint/network` routes.
- [ ] 8.3 Add `@cluster_context` decorator to all `blueprint/storage` routes.
- [ ] 8.4 Add `@cluster_context` decorator to all `blueprint/security` routes.
- [ ] 8.5 Add `@cluster_context` decorator to all `blueprint/other_resources` routes.
- [ ] 8.6 Add `@cluster_context` decorator to all `blueprint/metrics` routes.
- [ ] 8.7 Update `blueprint/cluster` routes to use cluster context.
- [ ] 8.8 Test all blueprints with multiple cluster contexts.
- [ ] 8.9 Add cluster name to audit log context for all operations.

#### 9. Extension API Updates

- [ ] 9.1 Add `?cluster=` query parameter support to Extension API.
- [ ] 9.2 Implement `X-Cluster-Context` header support.
- [ ] 9.3 Add cluster routing logic in `blueprint/extension_api`.
- [ ] 9.4 Update Extension API documentation with cluster parameter.
- [ ] 9.5 Add cluster context to Extension API response metadata.
- [ ] 9.6 Implement cluster‑scoped resource paths `/apis/kubedash.io/v1/clusters/{name}/...`.
- [ ] 9.7 Test Extension API with `kubectl` using multi‑cluster config.
- [ ] 9.8 Add backward compatibility for single‑cluster queries.

#### 10. User Experience and Navigation

- [ ] 10.1 Update page titles to include cluster name (e.g., “Pods – cluster‑name”).
- [ ] 10.2 Add cluster name to breadcrumb navigation.
- [ ] 10.3 Implement cluster‑aware bookmarks (URL includes cluster parameter).
- [ ] 10.4 Add cluster switch confirmation for unsaved changes.
- [ ] 10.5 Create “no clusters available” empty state page.
- [ ] 10.6 Add cluster onboarding tour for first‑time users.
- [ ] 10.7 Implement cluster search/filter in switcher (for many clusters).
- [ ] 10.8 Add recent clusters quick‑switch menu.

#### 11. Error Handling and Edge Cases

- [ ] 11.1 Implement graceful handling of unreachable selected cluster.
- [ ] 11.2 Add auto‑switch to default cluster when current cluster deleted.
- [ ] 11.3 Handle session expiration and cluster context restoration.
- [ ] 11.4 Implement “last cluster” deletion prevention.
- [ ] 11.5 Add warning dialogs for unhealthy cluster selection.
- [ ] 11.6 Create user‑friendly error messages for cluster‑related errors.
- [ ] 11.7 Add retry logic for transient cluster connection failures.
- [ ] 11.8 Implement cluster context validation on every request.

#### 12. Testing

- [ ] 12.1 Write unit tests for cluster context resolution logic.
- [ ] 12.2 Write unit tests for connection pooling.
- [ ] 12.3 Write integration tests for cluster CRUD API.
- [ ] 12.4 Write integration tests for health check scheduler.
- [ ] 12.5 Write E2E tests for cluster switching workflow.
- [ ] 12.6 Write E2E tests for multi‑cluster RBAC.
- [ ] 12.7 Test migration script with production‑like data.
- [ ] 12.8 Performance test connection pooling under load.
- [ ] 12.9 Test with 50+ registered clusters.
- [ ] 12.10 Write accessibility tests for cluster switcher.

#### 13. Documentation

- [ ] 13.1 Update user guide with multi‑cluster features.
- [ ] 13.2 Document cluster registration process.
- [ ] 13.3 Document cluster role management.
- [ ] 13.4 Update Extension API documentation with cluster parameter.
- [ ] 13.5 Create migration guide for single‑cluster installations.
- [ ] 13.6 Document health check configuration options.
- [ ] 13.7 Add troubleshooting guide for cluster connectivity issues.
- [ ] 13.8 Update architecture diagrams with multi‑cluster flow.
- [ ] 13.9 Create admin guide for cluster lifecycle management.

#### 14. Deployment and Operations

- [ ] 14.1 Update Helm chart with cluster registry database migrations.
- [ ] 14.2 Add environment variables for health check interval.
- [ ] 14.3 Add configuration for connection pool size.
- [ ] 14.4 Update monitoring dashboards with cluster health panels.
- [ ] 14.5 Add alerts for cluster health check failures.
- [ ] 14.6 Create runbook for cluster addition/removal procedures.
- [ ] 14.7 Test rollback procedure in staging environment.
- [ ] 14.8 Document backup requirements for cluster registry data.

