# Product Requirements Document: Flux Plugin

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Product**: KubeDash  
**Feature Area**: Flux GitOps Plugin  
**Status**: Active  

---

## Implementation Status

> **Overall Progress: ~90% Complete**

| Feature | Status | Completion | Notes |
|---------|--------|------------|-------|
| **GitRepository Sources** | ✅ Implemented | 100% | Full listing and details |
| **HelmRepository Sources** | ✅ Implemented | 100% | Full listing and details |
| **OCIRepository Sources** | ✅ Implemented | 100% | Full listing and details |
| **Bucket Sources** | ✅ Implemented | 100% | Full listing and details |
| **Kustomizations** | ✅ Implemented | 100% | Full listing and details |
| **HelmReleases** | ✅ Implemented | 100% | Full listing and details |
| **Alerts/Providers/Receivers** | ✅ Implemented | 90% | Notification objects |
| **Suspend/Resume Actions** | ✅ Implemented | 100% | Working actions |
| **Sync Action** | ✅ Implemented | 100% | Manual reconciliation |
| **Object Graph** | ✅ Implemented | 90% | Cytoscape.js visualization |
| **Detail View** | ✅ Implemented | 95% | Conditions, events |
| **WebSocket Updates** | ✅ Implemented | 80% | Real-time log streaming |

### User Story Status
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-FLUX-001: List Git Repositories | ✅ Done | `plugins/flux/sources.py` |
| US-FLUX-002: List Helm Repositories | ✅ Done | `plugins/flux/sources.py` |
| US-FLUX-003: List OCI Repositories | ✅ Done | `plugins/flux/sources.py` |
| US-FLUX-010: List Kustomizations | ✅ Done | `plugins/flux/kustomizations.py` |
| US-FLUX-011: View Kustomization Details | ✅ Done | `plugins/flux/details.py` |
| US-FLUX-020: List HelmReleases | ✅ Done | `plugins/flux/helm_releases.py` |
| US-FLUX-021: View HelmRelease Details | ✅ Done | `plugins/flux/details.py` |
| US-FLUX-030: Flux Dashboard | ✅ Done | Summary API endpoint |

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for the KubeDash Flux Plugin. The plugin provides visibility into Flux GitOps resources, enabling users to monitor source synchronization, reconciliation status, and manage GitOps workflows through a web interface.

### 1.2 Background

Flux is a popular GitOps toolkit for Kubernetes that keeps clusters in sync with sources like Git repositories and Helm charts. While Flux provides excellent CLI tools, a web-based dashboard improves visibility and accessibility for teams adopting GitOps practices.

### 1.3 Goals

1. **GitOps Visibility**: Comprehensive view of all Flux resources
2. **Reconciliation Monitoring**: Track sync status and detect issues
3. **Source Management**: View and manage Git, Helm, and OCI sources
4. **Quick Actions**: Suspend, resume, and trigger reconciliation
5. **Dependency Visualization**: Understand resource relationships

---

## 2. User Personas

### 2.1 GitOps Engineer

- **Role**: Manages GitOps workflows with Flux
- **Technical Level**: Advanced
- **Goals**: Monitor reconciliation, track sources, troubleshoot sync issues
- **Frustrations**: Flux status scattered across multiple resources

### 2.2 Release Manager

- **Role**: Oversees application releases and deployments
- **Technical Level**: Intermediate
- **Goals**: Verify deployments synced from Git, track versions
- **Frustrations**: Deployment status unclear without CLI

### 2.3 Platform Engineer

- **Role**: Maintains Flux infrastructure
- **Technical Level**: Expert
- **Goals**: Configure sources, manage dependencies, ensure reliability
- **Frustrations**: Complex debugging without visualization

---

## 3. User Stories

### 3.1 Source Management

#### US-FLUX-001: List Git Repositories
**As a** user  
**I want to** see all Flux GitRepository sources  
**So that** I can monitor Git sync status  

**Acceptance Criteria**:
- Display GitRepository resources
- Information:
  - Name
  - Namespace
  - URL (masked credentials)
  - Branch/Tag/SemVer
  - Interval
  - Last sync time
  - Status (Ready/Failed/Progressing)
  - Artifact revision (commit SHA)
- Visual status indicators (green/yellow/red)
- Filter by namespace
- Link to repository URL (external)
- Show sync errors prominently

**Priority**: P0 (Critical)

---

#### US-FLUX-002: List Helm Repositories
**As a** user  
**I want to** see Flux HelmRepository sources  
**So that** I can monitor Helm chart sources  

**Acceptance Criteria**:
- Display HelmRepository resources
- Information:
  - Name
  - Namespace
  - URL
  - Type (default/OCI)
  - Interval
  - Status
  - Last sync time
- Status indicators
- Show OCI vs traditional repos differently

**Priority**: P1 (High)

---

#### US-FLUX-003: List OCI Repositories
**As a** user  
**I want to** see OCI artifact sources  
**So that** I can track OCI-based deployments  

**Acceptance Criteria**:
- Display OCIRepository resources
- Information:
  - Name
  - Namespace
  - URL
  - Reference (tag/semver/digest)
  - Status
  - Last sync time
- Link to registry plugin (if configured)

**Priority**: P2 (Medium)

---

#### US-FLUX-004: List Bucket Sources
**As a** user  
**I want to** see S3-compatible bucket sources  
**So that** I can monitor bucket-based deployments  

**Acceptance Criteria**:
- Display Bucket resources
- Information:
  - Name
  - Namespace
  - Endpoint
  - Bucket name
  - Status
  - Last sync time

**Priority**: P2 (Medium)

---

#### US-FLUX-005: View Source Details
**As a** user  
**I want to** see detailed source information  
**So that** I can troubleshoot sync issues  

**Acceptance Criteria**:
- Display full source spec
- Show all status conditions
- List Kubernetes events
- Show artifact details (revision, checksum, size)
- Display last sync error if failed
- Show resources depending on this source

**Priority**: P1 (High)

---

### 3.2 Kustomization Management

#### US-FLUX-010: List Kustomizations
**As a** user  
**I want to** see Flux Kustomizations  
**So that** I can track reconciliation status  

**Acceptance Criteria**:
- Display Kustomization resources
- Information:
  - Name
  - Namespace
  - Source (GitRepo/Bucket/OCIRepo)
  - Path within source
  - Ready status
  - Last applied revision
  - Last reconcile time
  - Interval
  - Suspended status
- Visual reconciliation status
- Filter/search capabilities
- Show dependency chain

**Priority**: P0 (Critical)

---

#### US-FLUX-011: View Kustomization Details
**As a** user  
**I want to** see Kustomization details  
**So that** I can troubleshoot reconciliation issues  

**Acceptance Criteria**:
- Display full spec:
  - Source reference
  - Path
  - Interval
  - Retry interval
  - Timeout
  - Target namespace
  - Prune enabled
  - Health checks
  - Dependencies
  - Post-build substitutions
- Display status:
  - Conditions (Ready, Healthy, Reconciling)
  - Last applied revision
  - Last reconcile time
  - Inventory (list of managed resources)
- Display events
- Show drift detection results (if available)
- List dependent Kustomizations

**Priority**: P1 (High)

---

### 3.3 HelmRelease Management

#### US-FLUX-020: List HelmReleases
**As a** user  
**I want to** see Flux HelmReleases  
**So that** I can track Helm deployments via GitOps  

**Acceptance Criteria**:
- Display HelmRelease resources
- Information:
  - Name
  - Namespace
  - Chart name/version
  - Source (HelmRepo/GitRepo/Bucket)
  - Ready status
  - Last deployed revision
  - Last reconcile time
  - Suspended status
- Link to Helm plugin (for release details)
- Status indicators

**Priority**: P1 (High)

---

#### US-FLUX-021: View HelmRelease Details
**As a** user  
**I want to** see HelmRelease configuration  
**So that** I can verify GitOps-managed releases  

**Acceptance Criteria**:
- Display spec:
  - Chart reference
  - Values (merged from sources)
  - Values from ConfigMaps/Secrets
  - Install/upgrade remediation settings
  - Target namespace
  - Dependencies
  - Rollback settings
- Display status:
  - Conditions
  - Last release revision
  - History (upgrades/rollbacks)
  - Failures count
- Display events

**Priority**: P2 (Medium)

---

### 3.4 Notification Resources

#### US-FLUX-030: List Alerts
**As a** user  
**I want to** see Flux Alert configurations  
**So that** I can understand notification setup  

**Acceptance Criteria**:
- Display Alert resources
- Information:
  - Name
  - Namespace
  - Provider reference
  - Event sources
  - Event severity filter
  - Suspended status
- Status indicators

**Priority**: P2 (Medium)

---

#### US-FLUX-031: List Providers
**As a** user  
**I want to** see notification Provider configurations  
**So that** I can verify alert destinations  

**Acceptance Criteria**:
- Display Provider resources
- Information:
  - Name
  - Namespace
  - Type (Slack, Discord, GitHub, etc.)
  - Status
- Hide sensitive webhook URLs

**Priority**: P2 (Medium)

---

### 3.5 Actions

#### US-FLUX-040: Suspend/Resume Resources
**As a** user  
**I want to** suspend and resume Flux resources  
**So that** I can pause reconciliation when needed  

**Acceptance Criteria**:
- Suspend button on resource detail/list
- Resume button for suspended resources
- Confirmation dialog
- Show suspended status prominently
- Support for:
  - Kustomization
  - HelmRelease
  - GitRepository
  - All sources

**Priority**: P1 (High)

---

#### US-FLUX-041: Trigger Reconciliation
**As a** user  
**I want to** trigger immediate reconciliation  
**So that** I can force sync without waiting  

**Acceptance Criteria**:
- Sync/Reconcile button
- Works for all Flux resources
- Show reconciliation progress
- Display result (success/failure)
- Audit logging

**Priority**: P1 (High)

---

### 3.6 Visualization

#### US-FLUX-050: Flux Object Graph
**As a** user  
**I want** a visual graph of Flux resources  
**So that** I can understand dependencies  

**Acceptance Criteria**:
- Interactive graph visualization (Cytoscape.js)
- Node types:
  - Sources (Git, Helm, OCI, Bucket)
  - Kustomizations
  - HelmReleases
- Edge types:
  - Source dependency
  - Kustomization dependency
- Color by status
- Click to navigate to details
- Zoom/pan controls
- Filter by namespace
- Full-screen mode

**Priority**: P1 (High)

---

#### US-FLUX-051: Flux Dashboard
**As a** user  
**I want** a unified Flux status dashboard  
**So that** I can quickly assess GitOps health  

**Acceptance Criteria**:
- Summary counts:
  - GitRepositories: synced/failed
  - HelmRepositories: synced/failed
  - Kustomizations: ready/failing/suspended
  - HelmReleases: ready/failing/suspended
- Recent reconciliation events
- Failed resources highlighted
- Quick links to problem areas

**Priority**: P2 (Medium)

---

## 4. Functional Requirements

### 4.1 Source Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-SRC-01 | Plugin shall list GitRepository resources | P0 |
| FR-SRC-02 | Plugin shall list HelmRepository resources | P1 |
| FR-SRC-03 | Plugin shall list OCIRepository resources | P2 |
| FR-SRC-04 | Plugin shall list Bucket resources | P2 |
| FR-SRC-05 | Plugin shall display source sync status | P0 |
| FR-SRC-06 | Plugin shall show artifact revision | P1 |

### 4.2 Reconciliation Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-REC-01 | Plugin shall list Kustomization resources | P0 |
| FR-REC-02 | Plugin shall list HelmRelease resources | P1 |
| FR-REC-03 | Plugin shall display reconciliation status | P0 |
| FR-REC-04 | Plugin shall show inventory of managed resources | P2 |
| FR-REC-05 | Plugin shall display dependency relationships | P1 |

### 4.3 Actions

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-ACT-01 | Plugin shall support suspend operation | P1 |
| FR-ACT-02 | Plugin shall support resume operation | P1 |
| FR-ACT-03 | Plugin shall support sync/reconcile trigger | P1 |
| FR-ACT-04 | Plugin shall log all actions for audit | P1 |

### 4.4 Plugin Behavior

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-PLG-01 | Plugin shall be disabled if Flux CRDs not present | P1 |
| FR-PLG-02 | Plugin shall auto-detect installed Flux controllers | P2 |
| FR-PLG-03 | Plugin shall cache Flux data for performance | P2 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Resource list load time (50 resources) | < 3 seconds |
| NFR-PERF-02 | Graph rendering time (100 nodes) | < 2 seconds |
| NFR-PERF-03 | Action response time | < 2 seconds |

### 5.2 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | Flux v2.x | Required |
| NFR-COMP-02 | Flux v1.x | Not supported |

### 5.3 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-USE-01 | Find failing resource | < 10 seconds |
| NFR-USE-02 | Trigger reconciliation | < 3 clicks |

---

## 6. Technical Considerations

### 6.1 Flux CRDs

| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| GitRepository | source.toolkit.fluxcd.io | v1 | Namespaced |
| HelmRepository | source.toolkit.fluxcd.io | v1 | Namespaced |
| OCIRepository | source.toolkit.fluxcd.io | v1beta2 | Namespaced |
| Bucket | source.toolkit.fluxcd.io | v1 | Namespaced |
| Kustomization | kustomize.toolkit.fluxcd.io | v1 | Namespaced |
| HelmRelease | helm.toolkit.fluxcd.io | v2 | Namespaced |
| Alert | notification.toolkit.fluxcd.io | v1beta3 | Namespaced |
| Provider | notification.toolkit.fluxcd.io | v1beta3 | Namespaced |
| Receiver | notification.toolkit.fluxcd.io | v1 | Namespaced |

### 6.2 Reconciliation Trigger

```python
def trigger_reconciliation(resource_type, name, namespace):
    """
    Trigger immediate reconciliation by annotating the resource.
    Flux watches for the reconcile.fluxcd.io/requestedAt annotation.
    """
    annotation = {
        "reconcile.fluxcd.io/requestedAt": datetime.now().isoformat()
    }
    patch = {"metadata": {"annotations": annotation}}
    k8s_client.CustomObjectsApi().patch_namespaced_custom_object(
        group=get_api_group(resource_type),
        version=get_api_version(resource_type),
        namespace=namespace,
        plural=get_plural(resource_type),
        name=name,
        body=patch
    )
```

### 6.3 Implementation Files

```
plugins/flux/
├── __init__.py          # Blueprint routes
├── sources.py           # Source resource functions
├── kustomizations.py    # Kustomization functions
├── helm_releases.py     # HelmRelease functions
├── notifications.py     # Alert/Provider/Receiver functions
├── actions.py           # Suspend/Resume/Sync actions
├── details.py           # Detail view helpers
├── graph.py             # Graph data building
├── websocket.py         # Real-time updates
└── templates/
    ├── flux_objects.html.j2
    ├── flux_detail.html.j2
    └── segments/
        ├── flux_conditions.html.j2
        ├── flux_events.html.j2
        ├── flux_graph.html.j2
        └── flux_table.html.j2
```

---

## 7. User Interface Guidelines

### 7.1 Flux Objects List View

```
+--------------------------------------------------+
| Flux GitOps                        [Namespace ▼] |
+--------------------------------------------------+
| [Sources] [Kustomizations] [HelmReleases] [Graph]|
+--------------------------------------------------+
| GitRepositories                                   |
+--------------------------------------------------+
| Name      | URL              | Rev     | Status  |
|-----------|------------------|---------|---------|
| infra     | github.com/...   | abc123  | ✅ Ready |
| apps      | github.com/...   | def456  | ✅ Ready |
| config    | gitlab.com/...   | <none>  | ❌ Failed|
+--------------------------------------------------+
| Kustomizations                                    |
+--------------------------------------------------+
| Name      | Source | Path     | Rev     | Status |
|-----------|--------|----------|---------|--------|
| infra     | infra  | ./cluster| abc123  | ✅ Ready|
| apps-prod | apps   | ./prod   | def456  | ⏸ Susp |
+--------------------------------------------------+
```

### 7.2 Resource Detail View

```
+--------------------------------------------------+
| ← Back | Kustomization: apps-prod                |
+--------------------------------------------------+
| Status: ✅ Ready                    [⏸ Suspend]  |
|                                     [🔄 Sync]    |
+--------------------------------------------------+
| [Overview] [Conditions] [Events] [Inventory]     |
+--------------------------------------------------+
| Source: GitRepository/apps                        |
| Path: ./environments/prod                         |
| Interval: 10m                                     |
| Last Applied: abc123def                          |
| Last Reconciled: 2025-12-09 10:30:00             |
+--------------------------------------------------+
| Conditions:                                       |
| ✅ Ready: True - Applied revision: abc123def     |
| ✅ Healthy: True - All health checks passed      |
+--------------------------------------------------+
```

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Kubernetes library (CustomObjects API)
- WebSocket infrastructure (Flask-SocketIO)
- Plugin framework
- Caching layer

### 8.2 External Dependencies

- Flux installed in cluster
- Flux CRDs available

### 8.3 RBAC Requirements

```yaml
- apiGroups: ["source.toolkit.fluxcd.io"]
  resources: ["gitrepositories", "helmrepositories", "ocirepositories", "buckets"]
  verbs: ["get", "list", "patch"]
- apiGroups: ["kustomize.toolkit.fluxcd.io"]
  resources: ["kustomizations"]
  verbs: ["get", "list", "patch"]
- apiGroups: ["helm.toolkit.fluxcd.io"]
  resources: ["helmreleases"]
  verbs: ["get", "list", "patch"]
- apiGroups: ["notification.toolkit.fluxcd.io"]
  resources: ["alerts", "providers", "receivers"]
  verbs: ["get", "list"]
```

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Flux not installed | High | Medium | Show install guidance, disable plugin |
| CRD version mismatch | Medium | Low | Version detection, graceful degradation |
| Large number of Flux objects | Medium | Medium | Pagination, filtering |
| Action permissions denied | Medium | Medium | Clear RBAC error messages |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Plugin adoption | 70% of Flux users | Feature analytics |
| Reconciliation visibility | 100% coverage | Status accuracy tests |
| Mean time to detect sync failure | < 1 minute | User research |
| Action success rate | > 99% | Action logs |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Diff View**: Show drift between Git and cluster state
2. **Rollback UI**: Revert HelmRelease to previous version
3. **Source Creation**: Create new GitRepository via UI
4. **Multi-cluster**: View Flux across multiple clusters
5. **GitOps Workflows**: Visual deployment pipelines
6. **Image Automation**: ImagePolicy and ImageRepository support

### 11.2 Out of Scope (This Version)

- Source creation/modification
- Kustomization creation
- HelmRelease creation
- Image automation controllers
- Multi-cluster Flux

---

## 12. Plugin Configuration

```ini
# kubedash.ini
[plugin_settings]
flux = true  # Enable Flux plugin
```

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, Platform, DevOps*
