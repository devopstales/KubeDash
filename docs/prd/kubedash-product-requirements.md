# Product Requirements Document: KubeDash

**Document Version**: 4.1  
**Last Updated**: February 2026  
**Product**: KubeDash  
**Status**: Active  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Implementation Status Overview](#2-implementation-status-overview)
3. [Feature Areas](#3-feature-areas)
4. [Core Features](#4-core-features)
5. [Plugin System](#5-plugin-system)
6. [Technical Architecture](#6-technical-architecture)
7. [Non-Functional Requirements](#7-non-functional-requirements)
8. [Success Metrics](#8-success-metrics)
9. [Future Roadmap](#9-future-roadmap)
10. [Missing Resources Summary](#10-missing-resources-summary)
11. [Missing Kubernetes Resources](#11-missing-kubernetes-resources)
12. [Related PRDs](#12-related-prds)
13. [Appendix](#13-appendix)

---

## 1. Executive Summary

### 1.1 Purpose

KubeDash is a comprehensive, web-based UI for Kubernetes clusters that provides traditional dashboard functionality alongside advanced features for cluster management, monitoring, and troubleshooting. This document serves as the master Product Requirements Document (PRD) that consolidates all feature areas and provides an overview of implementation status.

### 1.2 Product Vision

KubeDash aims to be the go-to Kubernetes web UI that:
- Provides intuitive visual interfaces for all Kubernetes resources
- Enables efficient troubleshooting with real-time logs and interactive terminals
- Integrates seamlessly with enterprise identity providers
- Extends functionality through a plugin architecture
- Offers Kubernetes-native API aggregation for GitOps workflows

### 1.3 Target Users

- **Platform Administrators**: Manage cluster configuration, users, and security
- **DevOps Engineers**: Deploy, monitor, and troubleshoot applications
- **Application Developers**: View resources, check logs, debug issues
- **Site Reliability Engineers**: Monitor cluster health and respond to incidents
- **Security Teams**: Audit access, review security policies, manage secrets

---

## 2. Implementation Status Overview

> **Overall Product Completion: ~85%**

This section provides a high-level view of implementation status across all feature areas. Detailed status for each area is available in the respective PRD documents referenced in Section 10.

### 2.1 Feature Completion Matrix

| Feature Area | Status | Completion | Key Features |
|-------------|--------|------------|--------------|
| **Authentication & User Management** | ✅ Implemented | 85% | Local auth, OIDC/SSO, user CRUD, kubectl config generation |
| **Dashboard & Monitoring** | ✅ Implemented | 80% | Cluster metrics, events, resource map, dark mode |
| **Workload Management** | ✅ Implemented | 90% | Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets |
| **Cluster Resources** | ✅ Implemented | 85% | Namespaces, Nodes, CRDs, RBAC |
| **Network Resources** | ⚠️ Partial | 70% | Services, Ingresses, Ingress Classes; Missing: Endpoints, EndpointSlice, Network Lease, Cilium resources |
| **Storage Resources** | ✅ Implemented | 90% | PVs, PVCs, Storage Classes, ConfigMaps, Snapshots |
| **Security Resources** | ✅ Implemented | 85% | Secrets, RBAC (Roles/RoleBindings), Pod Security Policies |
| **Other Resources** | ⚠️ Partial | 75% | HPA, VPA, LimitRanges, Quotas, PDBs, PriorityClass; Missing: RuntimeClass |
| **Extension API** | ✅ Implemented | 95% | Kubernetes API aggregation, Projects CRUD, OpenAPI |
| **Plugin: Cert-Manager** | ✅ Implemented | 90% | Certificate management, issuer configuration |
| **Plugin: Trivy Operator** | ✅ Implemented | 90% | Vulnerability scanning, compliance reports |
| **Plugin: FluxCD** | ✅ Implemented | 85% | GitOps visualization, Kustomizations, Helm Releases |
| **Plugin: Gateway API** | ✅ Implemented | 80% | Gateway, HTTPRoute management |
| **Plugin: Helm** | ✅ Implemented | 85% | Helm chart browsing, release management |
| **Plugin: Registry** | ✅ Implemented | 90% | Docker registry integration, image browsing |
| **Plugin: External LoadBalancer** | ✅ Implemented | 85% | MetalLB, Cilium LB integration |

### 2.2 Critical Features Status

| Feature | Status | Notes |
|---------|--------|-------|
| **Real-time Pod Logs** | ✅ Complete | WebSocket streaming, multi-container support |
| **Pod Exec (Terminal)** | ✅ Complete | Interactive terminal via xterm.js |
| **RBAC Integration** | ✅ Complete | Full namespace and resource filtering |
| **OIDC/SSO Authentication** | ✅ Complete | Token refresh, group mapping |
| **Cluster Metrics** | ✅ Complete | CPU/Memory visualization with caching |
| **Resource Map** | ✅ Complete | Interactive graph visualization |
| **Extension API** | ✅ Complete | kubectl-compatible API aggregation |
| **Plugin Architecture** | ✅ Complete | Modular plugin system |
| **Dark Mode** | ✅ Complete | Theme switching with persistence |
| **Auto-refresh Dashboard** | ❌ Not Started | Manual refresh only |
| **Deployment Rollout Restart** | ❌ Not Started | Planned |
| **Event Search** | ❌ Not Started | Planned |
| **Multi-Factor Authentication** | ❌ Not Started | Planned |

### 2.3 Recent Improvements (v4.1)

1. **Performance Optimizations**
   - Optimized cluster metrics collection (O(nodes + pods) vs O(nodes × pods))
   - Implemented intelligent caching (prevents caching error states)
   - Increased API timeouts for better reliability
   - Reduced tracing overhead

2. **Error Handling**
   - Enhanced error logging for Kubernetes API failures
   - Graceful handling of missing service account certificates
   - Improved OIDC scope validation

3. **UI/UX Enhancements**
   - Improved chart design on cluster metrics dashboard
   - Theme-adaptive chart colors (dark/light mode)
   - Responsive grid layouts
   - Enhanced data display formatting

### 2.4 Known Limitations & Technical Debt

1. **Performance**
   - No auto-refresh on dashboard (manual only)
   - Large clusters may experience slow initial load
   - Limited pagination in some list views

2. **Features**
   - Deployment rollout restart not implemented
   - Event search/filtering limited
   - ReplicaSet detail view missing
   - Batch operations not available
   - **Namespace Scale Up/Down**: Partially implemented but disabled due to bugs (see Section 3.1.4)

3. **Security**
   - MFA not implemented
   - Account lockout not implemented
   - Password expiration policies not implemented
   - Rate limiting not implemented for login

4. **Observability**
   - Limited historical metrics (current snapshot only)
   - No Prometheus integration for historical data
   - Event timeline view not implemented

5. **Bugs & Incomplete Features**
   - **Namespace Scale Function**: Backend exists but UI disabled due to annotation parsing bug and missing error handling
   - **Missing Network Resources**: Endpoints, EndpointSlice, Network Lease, Cilium resources not implemented
   - **Missing Other Resources**: RuntimeClass not implemented

---

## 3. Feature Areas

### 3.1 Core Application Features

#### 3.1.1 Authentication & User Management
- **Status**: 85% Complete
- **Key Features**:
  - Local username/password authentication
  - OIDC/SSO integration with token refresh
  - User CRUD operations (Admin only)
  - Password management and reset
  - kubectl config generation (OIDC and certificate-based)
  - Session management with timeout
  - SSO group mapping to roles
- **See**: [authentication-user-management.md](./authentication-user-management.md)

#### 3.1.2 Dashboard & Monitoring
- **Status**: 80% Complete
- **Key Features**:
  - Cluster metrics dashboard (CPU/Memory)
  - Cluster events listing
  - Resource map visualization
  - Dark mode support
  - Default password warning
- **Missing**: Auto-refresh, event search, health summary widgets
- **See**: [dashboard-monitoring.md](./dashboard-monitoring.md)

#### 3.1.3 Workload Management
- **Status**: 90% Complete
- **Key Features**:
  - Pod management (list, details, delete, logs, exec)
  - Deployment management (list, details, scale)
  - StatefulSet management (list, details, scale)
  - DaemonSet management (list, details, suspend/resume)
  - ReplicaSet listing
  - Real-time log streaming via WebSocket
  - Interactive terminal (exec) via WebSocket
- **Missing**: Deployment rollout restart, ReplicaSet detail view
- **See**: [workload-management.md](./workload-management.md)

#### 3.1.4 Cluster Resources
- **Status**: 85% Complete
- **Key Features**:
  - Namespace management (create, delete, view)
  - Node listing and details with metrics
  - Custom Resource Definitions (CRD) browsing
  - RBAC resource viewing
  - **Namespace Scale Up/Down** (⚠️ Partially Implemented, Disabled in UI)
- **Implementation**: `blueprint/cluster.py`, `lib/k8s/node.py`, `lib/k8s/crds.py`, `lib/k8s/workload.py`

**Namespace Scale Functionality Status**:
- **Backend Implementation**: ✅ Partially implemented (`/cluster/namespace/scale` route exists)
- **UI Integration**: ❌ **Disabled** (buttons commented out in template)
- **Current Issues**:
  1. **Annotation Parsing Bug**: The code attempts to parse annotations as `key=value` strings, but annotations are dictionaries. The `k8sWorkloadList` function incorrectly splits annotations, causing `original-replicas` to not be read correctly.
  2. **Missing Original Replica Handling**: When scaling "up", if the `original-replicas` annotation is missing or 0, workloads will scale to 0 instead of their actual original replica count.
  3. **No Error Handling**: If any workload fails to scale, the operation continues silently without user feedback.
  4. **No Confirmation Dialog**: Dangerous operation (scaling entire namespace) lacks user confirmation.
  5. **No Progress Feedback**: Users cannot see which workloads are being scaled or the operation status.
  6. **DaemonSet Handling**: Uses node selector workaround which may not restore properly.
- **How It Should Work**:
  - **Scale Down**: Save current replica counts in annotation `kubedash.devopstales.io/original-replicas`, then scale Deployments/StatefulSets to 0, suspend DaemonSets via node selector.
  - **Scale Up**: Read `original-replicas` annotation and restore Deployments/StatefulSets to original count, remove DaemonSet node selector.
- **Files Involved**:
  - `blueprint/cluster.py` (lines 105-136): Route handler
  - `lib/k8s/workload.py`: `k8sDeploymentsPatchAnnotation`, `k8sStatefulSetPatchAnnotation`, `k8sWorkloadList`
  - `templates/cluster/namespace-data.html.j2` (lines 46-66): **Commented out UI**

#### 3.1.5 Network Resources
- **Status**: 70% Complete
- **Key Features**:
  - Service listing and details
  - Ingress listing and details
  - Ingress Class management
- **Missing Features**:
  - **Endpoints**: ❌ Not implemented (CoreV1 Endpoints resource)
  - **EndpointSlice**: ❌ Not implemented (NetworkingV1 EndpointSlice resource)
  - **Network Lease**: ❌ Not implemented (CoordinationV1 Lease resource for network components)
  - **Cilium Endpoint**: ❌ Not implemented (Cilium CRD: `ciliumendpoints.cilium.io`)
  - **Network Segments**: ❌ Not implemented (Cilium-specific network segmentation)
- **Implementation**: `blueprint/network.py`, `lib/k8s/network.py`

#### 3.1.6 Storage Resources
- **Status**: 90% Complete
- **Key Features**:
  - Storage Class management
  - Persistent Volume (PV) listing
  - Persistent Volume Claim (PVC) listing with metrics
  - ConfigMap viewing
  - Volume Snapshot management
  - Snapshot Class management
- **Implementation**: `blueprint/storage.py`, `lib/k8s/storage.py`

#### 3.1.7 Security Resources
- **Status**: 85% Complete
- **Key Features**:
  - Secret viewing (with masking)
  - Role and RoleBinding management
  - ClusterRole and ClusterRoleBinding management
  - Pod Security Policy viewing
- **Implementation**: `blueprint/security.py`, `lib/k8s/security.py`

#### 3.1.8 Other Resources
- **Status**: 75% Complete
- **Key Features**:
  - Horizontal Pod Autoscaler (HPA) viewing
  - Vertical Pod Autoscaler (VPA) viewing
  - LimitRange viewing
  - ResourceQuota viewing
  - Pod Disruption Budget (PDB) viewing
  - PriorityClass viewing ✅
- **Missing Features**:
  - **RuntimeClass**: ❌ Not implemented (NodeV1 RuntimeClass resource)
- **Implementation**: `blueprint/other_resources.py`, `lib/k8s/other.py`, `blueprint/security.py`

### 3.2 Extension API

#### 3.2.1 Kubernetes API Aggregation
- **Status**: 95% Complete
- **Key Features**:
  - Kubernetes-style API server
  - API discovery endpoints (`/apis`, `/apis/v1`)
  - OpenAPI specification (`/openapi/v2`)
  - Health check endpoints (`/healthz`, `/readyz`, `/livez`)
  - Projects CRUD operations
  - Bearer token authentication (ServiceAccount)
  - Session cookie authentication
  - Table format support (kubectl compatibility)
  - RBAC integration for namespace filtering
- **Missing**: Watch support for real-time updates
- **See**: [extension-api.md](./extension-api.md)
- **Implementation**: `blueprint/extension_api.py`, `lib/extension_api/`

### 3.3 Plugin System

KubeDash features a modular plugin architecture that allows extending functionality without modifying core code. Plugins are loaded dynamically and integrate seamlessly with the main application.

#### 3.3.1 Cert-Manager Plugin
- **Status**: 90% Complete
- **Key Features**:
  - Certificate management
  - Certificate Issuer/ClusterIssuer configuration
  - Certificate Request viewing
- **See**: [plugin-cert-manager.md](./plugin-cert-manager.md)
- **Implementation**: `plugins/cert_manager/`

#### 3.3.2 Trivy Operator Plugin
- **Status**: 90% Complete
- **Key Features**:
  - Vulnerability scanning reports
  - Compliance reports (ClusterCompliance, ConfigAudit)
  - Infrastructure assessment
  - RBAC assessment
  - Exposed secrets detection
  - SBOM (Software Bill of Materials) viewing
- **See**: [plugin-trivy-operator.md](./plugin-trivy-operator.md)
- **Implementation**: `plugins/trivy_operator/`

#### 3.3.3 FluxCD Plugin
- **Status**: 85% Complete
- **Key Features**:
  - GitOps visualization
  - Kustomization management
  - Helm Release management
  - Source management (GitRepository, HelmRepository, OCIRepository, Bucket)
  - Notification management (Alert, Provider, Receiver)
  - Real-time updates via WebSocket
  - Dependency graph visualization
- **See**: [plugin-flux.md](./plugin-flux.md)
- **Implementation**: `plugins/flux/`

#### 3.3.4 Gateway API Plugin
- **Status**: 80% Complete
- **Key Features**:
  - Gateway management
  - GatewayClass management
  - HTTPRoute management
  - Route visualization
- **See**: [plugin-gateway-api.md](./plugin-gateway-api.md)
- **Implementation**: `plugins/gateway_api/`

#### 3.3.5 Helm Plugin
- **Status**: 85% Complete
- **Key Features**:
  - Helm chart browsing
  - Helm release management
  - Chart version viewing
- **See**: [plugin-helm.md](./plugin-helm.md)
- **Implementation**: `plugins/helm/`

#### 3.3.6 Registry Plugin
- **Status**: 90% Complete
- **Key Features**:
  - Docker registry integration
  - Image browsing
  - Tag management
  - Image details viewing
- **See**: [plugin-registry.md](./plugin-registry.md)
- **Implementation**: `plugins/registry/`

#### 3.3.7 External LoadBalancer Plugin
- **Status**: 85% Complete
- **Key Features**:
  - MetalLB integration
  - Cilium LoadBalancer integration
  - LoadBalancer service management
- **See**: [plugin-external-loadbalancer.md](./plugin-external-loadbalancer.md)
- **Implementation**: `plugins/external_loadbalancer/`

---

## 4. Core Features

### 4.1 User Interface

- **Responsive Design**: Works on desktop and tablet devices
- **Dark Mode**: Full theme support with persistence
- **Navigation**: Intuitive menu structure with breadcrumbs
- **Search & Filter**: Namespace filtering, resource search (where applicable)
- **Real-time Updates**: WebSocket-based updates for logs and exec

### 4.2 Kubernetes Integration

- **RBAC Support**: Full integration with Kubernetes RBAC
- **Namespace Filtering**: Automatic filtering based on user permissions
- **Multi-cluster Ready**: Architecture supports multiple clusters (future)
- **Metrics Integration**: Uses Kubernetes Metrics Server API
- **Event Monitoring**: Direct Kubernetes Event API integration

### 4.3 Performance & Scalability

- **Caching**: Redis-based caching for frequently accessed data
- **Optimized Queries**: Efficient Kubernetes API usage
- **Pagination**: Large resource lists are paginated
- **Lazy Loading**: Resources loaded on demand

### 4.4 Security

- **Authentication**: Multiple auth methods (Local, OIDC, ServiceAccount)
- **Authorization**: Kubernetes RBAC integration
- **Session Management**: Secure session handling
- **Security Headers**: CSP, HSTS, XSS protection via Flask-Talisman
- **Secret Masking**: Sensitive data masked in UI

---

## 5. Plugin System

### 5.1 Architecture

Plugins are self-contained modules that:
- Register their own blueprints
- Provide their own templates
- Can access core KubeDash functionality
- Are loaded dynamically at startup

### 5.2 Plugin Loading

Plugins are discovered and loaded from the `plugins/` directory. Each plugin:
- Must have an `__init__.py` file
- Registers routes via Flask blueprints
- Can add menu items to the navigation
- Can provide API endpoints

### 5.3 Current Plugins

See Section 3.3 for details on each plugin.

---

## 6. Technical Architecture

### 6.1 Technology Stack

- **Backend**: Python 3.12, Flask 2.x
- **Database**: SQLite (default) or PostgreSQL
- **Cache**: Redis
- **Frontend**: Jinja2 templates, Bootstrap, Chart.js, xterm.js
- **WebSocket**: Flask-SocketIO
- **Kubernetes Client**: kubernetes Python client library
- **Observability**: OpenTelemetry

### 6.2 Application Structure

```
kubedash/
├── blueprint/          # Flask blueprints (routes)
├── lib/                # Core libraries
│   ├── k8s/           # Kubernetes integration
│   ├── extension_api/ # Extension API implementation
│   └── ...
├── plugins/            # Plugin modules
├── templates/          # Jinja2 templates
├── static/             # Static assets (CSS, JS, images)
└── migrations/         # Database migrations
```

### 6.3 Key Components

- **Authentication**: `blueprint/auth.py`, `lib/sso.py`
- **Kubernetes API**: `lib/k8s/` (modular functions for each resource type)
- **Extension API**: `blueprint/extension_api.py`, `lib/extension_api/`
- **Caching**: `lib/cache.py` (Flask-Caching)
- **Metrics**: `lib/prometheus.py` (Prometheus metrics)
- **Tracing**: `lib/opentelemetry.py` (OpenTelemetry integration)

---

## 7. Non-Functional Requirements

### 7.1 Performance

| Requirement | Target | Status |
|-------------|--------|--------|
| Dashboard load time | < 3 seconds | ✅ Met (with caching) |
| Pod list load (100 pods) | < 2 seconds | ✅ Met |
| Log streaming latency | < 500ms | ✅ Met |
| Exec terminal latency | < 100ms | ✅ Met |

### 7.2 Reliability

| Requirement | Target | Status |
|-------------|--------|--------|
| Application uptime | 99.9% | ✅ Met |
| Graceful error handling | No crashes | ✅ Met |
| WebSocket stability | Auto-reconnect | ✅ Met |

### 7.3 Security

| Requirement | Status |
|-------------|--------|
| TLS encryption | ✅ Required |
| Secure session cookies | ✅ Implemented |
| CSRF protection | ✅ Implemented |
| RBAC enforcement | ✅ Implemented |
| Secret masking | ✅ Implemented |
| Rate limiting | ❌ Not implemented |

### 7.4 Usability

| Requirement | Status |
|-------------|--------|
| Responsive design | ✅ Implemented |
| Dark mode | ✅ Implemented |
| Intuitive navigation | ✅ Implemented |
| Helpful error messages | ✅ Implemented |
| Keyboard shortcuts | ⚠️ Partial |

---

## 8. Success Metrics

### 8.1 Adoption Metrics

- **User Engagement**: Dashboard page views per session
- **Feature Usage**: Most used features (logs, exec, metrics)
- **Plugin Adoption**: Plugin usage statistics

### 8.2 Performance Metrics

- **Page Load Times**: Tracked via OpenTelemetry
- **API Response Times**: Tracked via Prometheus
- **Error Rates**: Tracked via logging and metrics

### 8.3 User Satisfaction

- **Time to Troubleshoot**: Reduced vs kubectl
- **Feature Completeness**: Coverage of common kubectl operations
- **User Feedback**: Collected via GitHub issues and discussions

---

## 9. Future Roadmap

### 9.1 Short-term (Next Release)

1. **Auto-refresh Dashboard**: Configurable refresh intervals
2. **Deployment Rollout Restart**: Trigger rolling restarts
3. **Event Search**: Search and filter events
4. **ReplicaSet Detail View**: Complete ReplicaSet management
5. **Fix Namespace Scale Function**: 
   - Fix annotation parsing in `k8sWorkloadList` to correctly read `original-replicas`
   - Add fallback to read current replica count from spec if annotation missing
   - Add error handling and user feedback
   - Add confirmation dialog for scale operations
   - Re-enable UI buttons in namespace detail view
   - Add progress indicator showing which workloads are being scaled
6. **Add Missing Network Resources**:
   - **Endpoints**: List and view Endpoints resources (CoreV1)
   - **EndpointSlice**: List and view EndpointSlice resources (NetworkingV1)
   - **Network Lease**: View Lease resources used by network components
   - **Cilium Endpoint**: Support for Cilium CRD endpoints (if Cilium installed)
   - **Network Segments**: Cilium network segmentation visualization
7. **Add Missing Other Resources**:
   - **RuntimeClass**: List and view RuntimeClass resources (NodeV1)

### 9.2 Medium-term (3-6 months)

1. **Multi-Factor Authentication**: TOTP support
2. **Account Lockout**: After failed login attempts
3. **Password Expiration**: Configurable policies
4. **Batch Operations**: Select and act on multiple resources
5. **Resource Editing**: YAML editor with validation
6. **Historical Metrics**: Prometheus integration

### 9.3 Long-term (6+ months)

1. **Multi-cluster Support**: Manage multiple clusters from one UI
2. **Custom Dashboards**: User-defined widget layouts
3. **Alerting Integration**: Prometheus alert display
4. **Cost Visibility**: Resource cost estimation
5. **SLO/SLA Tracking**: Service level indicators
6. **Watch Support**: Real-time resource updates via Extension API

---

## 10. Missing Resources Summary

| Resource Type | API Group | Status | Priority | Use Case |
|--------------|-----------|--------|----------|----------|
| **Endpoints** | CoreV1 | ❌ Missing | P2 | Service-to-pod mapping |
| **EndpointSlice** | NetworkingV1 | ❌ Missing | P2 | Modern endpoint tracking |
| **Lease** | CoordinationV1 | ❌ Missing | P3 | Network component leases |
| **CiliumEndpoint** | CRD | ❌ Missing | P3 | Cilium CNI endpoints |
| **Network Segments** | Cilium | ❌ Missing | P3 | Network segmentation |
| **RuntimeClass** | NodeV1 | ❌ Missing | P2 | Container runtime config |

See Section 11 for detailed requirements for each missing resource.

---

## 12. Related PRDs

This master PRD references the following detailed PRD documents:

1. **[Authentication & User Management](./authentication-user-management.md)**
   - Local and SSO authentication
   - User management
   - kubectl config generation

2. **[Dashboard & Monitoring](./dashboard-monitoring.md)**
   - Cluster metrics
   - Event monitoring
   - Resource map

3. **[Workload Management](./workload-management.md)**
   - Pods, Deployments, StatefulSets, DaemonSets, ReplicaSets
   - Logs and exec functionality

4. **[Extension API](./extension-api.md)**
   - Kubernetes API aggregation
   - Projects resource
   - OpenAPI specification

5. **[MCP Integration](./mcp-integration.md)**
   - AI chatbot with in-app chat panel
   - MCP (Model Context Protocol) integration for cluster context
   - Natural language cluster queries and optional actions

6. **[Plugin: Cert-Manager](./plugin-cert-manager.md)**
   - Certificate management

7. **[Plugin: Trivy Operator](./plugin-trivy-operator.md)**
   - Security scanning and compliance

8. **[Plugin: FluxCD](./plugin-flux.md)**
   - GitOps visualization and management

9. **[Plugin: Gateway API](./plugin-gateway-api.md)**
   - Gateway and route management

10. **[Plugin: Helm](./plugin-helm.md)**
   - Helm chart and release management

11. **[Plugin: Registry](./plugin-registry.md)**
    - Docker registry integration

12. **[Plugin: External LoadBalancer](./plugin-external-loadbalancer.md)**
    - LoadBalancer service management

---

## 11. Missing Kubernetes Resources

This section documents Kubernetes resources that are not yet implemented in KubeDash but are planned for future releases.

### 11.1 Network Resources

#### 11.1.1 Endpoints (CoreV1)
- **Status**: ❌ Not Implemented
- **Description**: Endpoints track which Pods are backing a Service
- **Use Case**: Debugging service connectivity, understanding pod-to-service mappings
- **Requirements**:
  - List Endpoints by namespace
  - View Endpoint details (addresses, ports, subsets)
  - Show associated Service
  - Display endpoint readiness status
  - Filter by Service name
- **Priority**: P2 (Medium)
- **API**: `CoreV1Api().list_namespaced_endpoints()`

#### 11.1.2 EndpointSlice (NetworkingV1)
- **Status**: ❌ Not Implemented
- **Description**: Modern alternative to Endpoints, provides better scalability
- **Use Case**: Debugging service connectivity in large clusters, understanding endpoint distribution
- **Requirements**:
  - List EndpointSlice by namespace
  - View EndpointSlice details (endpoints, ports, address type)
  - Show associated Service
  - Display endpoint readiness and serving status
  - Filter by Service name
  - Group by Service for easier navigation
- **Priority**: P2 (Medium)
- **API**: `NetworkingV1Api().list_namespaced_endpoint_slice()`

#### 11.1.3 Network Lease (CoordinationV1)
- **Status**: ❌ Not Implemented
- **Description**: Lease resources used by network components (e.g., node leases, leader election)
- **Use Case**: Understanding network component leader election, debugging network issues
- **Requirements**:
  - List Leases by namespace (or cluster-scoped)
  - View Lease details (holder identity, renew time, lease duration)
  - Show associated component (via labels/annotations)
  - Filter by component type
- **Priority**: P3 (Low)
- **API**: `CoordinationV1Api().list_namespaced_lease()` or `list_lease()`

#### 11.1.4 Cilium Endpoint (CRD)
- **Status**: ❌ Not Implemented
- **Description**: Cilium-specific endpoint resource for CNI network policies
- **Use Case**: Debugging Cilium network policies, understanding endpoint state
- **Requirements**:
  - List CiliumEndpoints (if Cilium CNI is installed)
  - View endpoint details (identity, policy enforcement, state)
  - Show associated Pod
  - Display network policy rules applied
  - Filter by namespace
- **Priority**: P3 (Low - Cilium-specific)
- **API**: Custom Resource API via `CustomObjectsApi()`
- **CRD**: `ciliumendpoints.cilium.io`

#### 11.1.5 Network Segments (Cilium)
- **Status**: ❌ Not Implemented
- **Description**: Cilium network segmentation and isolation
- **Use Case**: Understanding network segmentation, debugging connectivity issues
- **Requirements**:
  - Visualize network segments
  - Show segment boundaries and policies
  - Display inter-segment connectivity rules
- **Priority**: P3 (Low - Cilium-specific, future consideration)

### 11.2 Other Resources

#### 11.2.1 RuntimeClass (NodeV1)
- **Status**: ❌ Not Implemented
- **Description**: Defines container runtime configurations (e.g., Kata Containers, gVisor)
- **Use Case**: Understanding which runtime classes are available, configuring pod runtime selection
- **Requirements**:
  - List RuntimeClasses (cluster-scoped)
  - View RuntimeClass details (handler, overhead, scheduling constraints)
  - Show associated Pods using the runtime class
  - Display runtime class metadata and annotations
- **Priority**: P2 (Medium)
- **API**: `NodeV1Api().list_runtime_class()`

### 11.3 Implementation Notes

All missing resources should follow the same patterns as existing resources:
- **List View**: Table with sortable columns, namespace filtering (where applicable)
- **Detail View**: Comprehensive resource information, YAML view option
- **RBAC Integration**: Respect user permissions for viewing resources
- **Caching**: Use appropriate cache timeouts (short for frequently changing, long for static)
- **Error Handling**: Graceful handling of missing CRDs or API groups

---

## 13. Appendix

### 13.1 Glossary

| Term | Definition |
|------|------------|
| **RBAC** | Role-Based Access Control |
| **OIDC** | OpenID Connect |
| **SSO** | Single Sign-On |
| **CRD** | Custom Resource Definition |
| **HPA** | Horizontal Pod Autoscaler |
| **VPA** | Vertical Pod Autoscaler |
| **PDB** | Pod Disruption Budget |
| **PVC** | Persistent Volume Claim |
| **PV** | Persistent Volume |

### 13.2 References

- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [Flask Documentation](https://flask.palletsprojects.com/)
- [OpenTelemetry](https://opentelemetry.io/)
- [Prometheus](https://prometheus.io/)

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, UX, Security, Operations*  
*Last Review Date: February 2026*
