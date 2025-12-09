# Product Requirements Document: Helm Plugin

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Product**: KubeDash  
**Feature Area**: Helm Plugin  
**Status**: Active  

---

## Implementation Status

> **Overall Progress: ~75% Complete**

This section tracks the current implementation status against the requirements defined in this PRD.

### Feature Implementation Matrix

| Feature Category | Status | Completion | Notes |
|-----------------|--------|------------|-------|
| **Release Listing** | ✅ Implemented | 100% | List releases per namespace |
| **Release Details** | ✅ Implemented | 90% | Chart info, metadata |
| **Release Values** | ✅ Implemented | 100% | YAML formatted view |
| **Release History** | ⚠️ Partial | 50% | Version shown, no full history |
| **Release Status** | ✅ Implemented | 100% | Status indicators |
| **Namespace Filter** | ✅ Implemented | 100% | Namespace dropdown |
| **Search/Filter** | ❌ Not Started | 0% | Planned |
| **Rollback** | ❌ Not Started | 0% | Future consideration |

### User Story Implementation Status

#### Release Listing
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-HELM-001: List Helm Releases | ✅ Done | `plugins/helm/__init__.py` |
| US-HELM-002: Search Releases | ❌ Not Done | Planned |

#### Release Details
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-HELM-003: View Release Details | ✅ Done | `plugins/helm/__init__.py` |
| US-HELM-004: View Release Values | ✅ Done | `plugins/helm/functions.py` |
| US-HELM-005: View Release Manifest | ⚠️ Partial | Values shown, not full manifest |

#### Release History
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-HELM-006: View Release History | ⚠️ Partial | Current version only |
| US-HELM-007: Compare Revisions | ❌ Not Done | Future consideration |

#### Release Status
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-HELM-008: View Release Status | ✅ Done | Status in list view |
| US-HELM-009: View Release Resources | ❌ Not Done | Planned |

### Key Implementation Details

- **Data Source**: Helm release secrets (`sh.helm.release.v1.*`)
- **Decoding**: Base64 decode → Gzip decompress → JSON parse
- **Routes**: `/plugins/helm-chart` (list), `/plugins/helm-charts/data` (details)
- **Templates**: `helm-charts.html.j2`, `helm-chart-data.html.j2`

### Technical Debt & Known Issues

1. **Full history** - Only shows current version, not revision history
2. **Manifest view** - Values shown, but not full rendered manifests
3. **Resource links** - No links to K8s resources created by release
4. **Search** - No search/filter functionality in release list

### Next Steps

1. Implement full revision history view
2. Add rendered manifest display
3. Implement search/filter for releases
4. Add links to related Kubernetes resources
5. Consider rollback functionality (future)

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for the KubeDash Helm Plugin. The plugin provides visibility into Helm chart releases installed in the Kubernetes cluster, allowing users to view release information, configuration values, and release history without using the Helm CLI.

### 1.2 Background

Helm is the de facto package manager for Kubernetes. Many organizations use Helm to deploy applications, but visibility into installed releases often requires CLI access. The Helm Plugin bridges this gap by providing a web-based interface to view Helm releases.

### 1.3 Goals

1. **Release Visibility**: View all Helm releases in the cluster
2. **Configuration Inspection**: View release values and configurations
3. **History Tracking**: Review release revision history
4. **Status Monitoring**: Monitor release health and status
5. **Integration**: Seamless integration with KubeDash navigation

---

## 2. User Personas

### 2.1 Release Manager

- **Role**: Manages application deployments via Helm
- **Technical Level**: Intermediate to advanced
- **Goals**: Track release status, review configurations
- **Frustrations**: Switching between CLI and UI tools

### 2.2 Support Engineer

- **Role**: Troubleshoots application issues
- **Technical Level**: Basic to intermediate Helm knowledge
- **Goals**: Verify release configuration, check versions
- **Frustrations**: Limited Helm CLI experience

### 2.3 Security Auditor

- **Role**: Reviews deployment configurations
- **Technical Level**: Intermediate
- **Goals**: Audit release configurations, verify versions
- **Frustrations**: Manual configuration extraction

---

## 3. User Stories

### 3.1 Release Listing

#### US-HELM-001: List Helm Releases
**As a** user  
**I want to** see all Helm releases in a namespace  
**So that** I can understand what's deployed via Helm  

**Acceptance Criteria**:
- Display releases in selected namespace
- Release information shown:
  - Name
  - Namespace
  - Revision number
  - Last updated timestamp
  - Status (deployed, failed, pending, etc.)
  - Chart name and version
  - App version
- Filter/sort capabilities
- Handle namespaces with no releases gracefully
- Show "All Namespaces" option for admins
- Loading indicator during data fetch

**Priority**: P0 (Critical)

---

#### US-HELM-002: Search Releases
**As a** user  
**I want to** search for specific releases  
**So that** I can quickly find what I'm looking for  

**Acceptance Criteria**:
- Search by release name
- Search by chart name
- Real-time filtering as user types
- Clear search functionality
- Highlight matching text

**Priority**: P2 (Medium)

---

### 3.2 Release Details

#### US-HELM-003: View Release Details
**As a** user  
**I want to** view detailed information about a release  
**So that** I can understand its configuration  

**Acceptance Criteria**:
- Display release metadata:
  - Name, Namespace, Revision
  - Chart name and version
  - App version
  - First deployed, Last deployed
  - Status with description
- Display release notes (if available)
- Links to related Kubernetes resources
- Back navigation to release list

**Priority**: P0 (Critical)

---

#### US-HELM-004: View Release Values
**As a** user  
**I want to** see the configuration values for a release  
**So that** I can verify the configuration  

**Acceptance Criteria**:
- Display computed values (merged from chart defaults and overrides)
- YAML formatted view
- Syntax highlighting
- Collapsible sections for nested values
- Copy to clipboard functionality
- Search within values
- Option to download values file

**Priority**: P1 (High)

---

#### US-HELM-005: View Release Manifest
**As a** user  
**I want to** see the rendered Kubernetes manifests  
**So that** I can understand what resources were created  

**Acceptance Criteria**:
- Display all manifests generated by the release
- Group by resource kind
- YAML formatted view with syntax highlighting
- Search within manifests
- Copy individual resources
- Expand/collapse sections

**Priority**: P2 (Medium)

---

### 3.3 Release History

#### US-HELM-006: View Release History
**As a** user  
**I want to** see the revision history of a release  
**So that** I can track changes over time  

**Acceptance Criteria**:
- List all revisions for a release
- Revision information:
  - Revision number
  - Last updated timestamp
  - Status
  - Chart version
  - App version
  - Description (if provided)
- Most recent revision highlighted
- Show superseded revisions
- Navigate to specific revision details

**Priority**: P1 (High)

---

#### US-HELM-007: Compare Revisions
**As a** user  
**I want to** compare two release revisions  
**So that** I can understand what changed  

**Acceptance Criteria**:
- Select two revisions to compare
- Side-by-side diff of values
- Highlight added/removed/changed values
- Visual diff indicators
- Option to show only changes

**Priority**: P3 (Future)

---

### 3.4 Release Status

#### US-HELM-008: View Release Status
**As a** user  
**I want to** see the current status of a release  
**So that** I can identify issues  

**Acceptance Criteria**:
- Display release status:
  - deployed
  - uninstalled
  - superseded
  - failed
  - uninstalling
  - pending-install
  - pending-upgrade
  - pending-rollback
- Visual status indicator (color/icon)
- Status message if failed
- Timestamp of status change

**Priority**: P0 (Critical)

---

#### US-HELM-009: View Release Resources
**As a** user  
**I want to** see Kubernetes resources created by a release  
**So that** I can troubleshoot issues  

**Acceptance Criteria**:
- List resources created by release
- Resource information:
  - Kind
  - Name
  - Namespace
  - Status
- Link to resource in KubeDash
- Show resource health indicators
- Group by resource kind

**Priority**: P2 (Medium)

---

## 4. Functional Requirements

### 4.1 Release Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-HELM-01 | System shall list Helm releases in a namespace | P0 |
| FR-HELM-02 | System shall display release details including chart info | P0 |
| FR-HELM-03 | System shall display release status with visual indicators | P0 |
| FR-HELM-04 | System shall display release values in YAML format | P1 |
| FR-HELM-05 | System shall display release revision history | P1 |
| FR-HELM-06 | System shall support namespace selection for releases | P0 |

### 4.2 Data Retrieval

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-HELM-10 | System shall retrieve release data from Helm secrets | P0 |
| FR-HELM-11 | System shall decode and parse Helm release data | P0 |
| FR-HELM-12 | System shall cache release data for performance | P2 |
| FR-HELM-13 | System shall respect Kubernetes RBAC for release access | P0 |

### 4.3 Integration

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-HELM-20 | System shall integrate with KubeDash navigation | P0 |
| FR-HELM-21 | System shall link to related Kubernetes resources | P2 |
| FR-HELM-22 | System shall be configurable as plugin (enable/disable) | P0 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Release list load time (50 releases) | < 3 seconds |
| NFR-PERF-02 | Release details load time | < 2 seconds |
| NFR-PERF-03 | Values rendering time (large values) | < 1 second |

### 5.2 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-USE-01 | Find release status | < 5 clicks |
| NFR-USE-02 | View release values | < 3 clicks |
| NFR-USE-03 | Responsive design | Desktop + tablet |

### 5.3 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | Helm 3.x release format support | Required |
| NFR-COMP-02 | Helm 2.x compatibility | Not required |

---

## 6. Technical Considerations

### 6.1 Helm Release Storage

Helm 3 stores releases as Kubernetes Secrets in the release namespace with the naming pattern `sh.helm.release.v1.<release>.<revision>`.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: sh.helm.release.v1.myapp.v1
  namespace: default
  labels:
    name: myapp
    owner: helm
    status: deployed
    version: "1"
type: helm.sh/release.v1
data:
  release: <base64-encoded-gzip-protobuf>
```

### 6.2 Data Parsing

The release data must be:
1. Base64 decoded
2. Gzip decompressed
3. Parsed (JSON/protobuf format)

### 6.3 RBAC Requirements

Users need read access to Secrets in namespaces to view Helm releases:
```yaml
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
```

---

## 7. User Interface Guidelines

### 7.1 Release List View

```
+------------------------------------------+
| Helm Charts                    [Namespace ▼] |
+------------------------------------------+
| 🔍 Search releases...                      |
+------------------------------------------+
| Name      | Chart      | Version | Status  |
|-----------|------------|---------|---------|
| myapp     | nginx      | 1.0.0   | ✅ Deployed |
| database  | postgresql | 11.9.0  | ✅ Deployed |
| cache     | redis      | 6.0.0   | ⚠️ Failed   |
+------------------------------------------+
```

### 7.2 Release Detail View

```
+------------------------------------------+
| ← Back to Charts                          |
+------------------------------------------+
| Release: myapp                            |
| Status: ✅ Deployed                        |
+------------------------------------------+
| [Info] [Values] [History] [Resources]     |
+------------------------------------------+
| Chart: nginx                              |
| Version: 1.0.0                            |
| App Version: 1.21.0                       |
| Namespace: default                        |
| Revision: 3                               |
| First Deployed: 2025-01-01 10:00:00       |
| Last Deployed: 2025-12-01 14:30:00        |
+------------------------------------------+
```

### 7.3 Values View

- Dark code editor theme
- YAML syntax highlighting
- Line numbers
- Code folding for nested structures
- Copy button

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Authentication system (for RBAC context)
- Kubernetes library (Secret access)
- Plugin framework (registration)

### 8.2 External Dependencies

- Kubernetes API (Secrets)
- Base64/Gzip libraries (data parsing)

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Large release values slow rendering | Medium | Medium | Lazy loading, pagination |
| Secret access denied | High | Medium | Clear error message, RBAC guidance |
| Helm 2 releases incompatible | Low | Low | Document Helm 3 requirement |
| Corrupted release data | Low | Low | Error handling, skip corrupt releases |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Plugin adoption | 60% of users | Feature analytics |
| Release lookup time | -70% vs CLI | User research |
| User satisfaction | NPS > 40 | Surveys |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Rollback UI**: Roll back to previous revision
2. **Upgrade UI**: Upgrade release with new values
3. **Install UI**: Install new Helm charts
4. **Uninstall UI**: Uninstall releases
5. **Chart Repository Browser**: Browse available charts
6. **Value Validation**: Validate values against schema
7. **Diff View**: Compare current vs desired state

### 11.2 Out of Scope (This Version)

- Helm chart installation
- Release upgrades
- Release rollback operations
- Chart repository management
- Helm 2 support
- OCI registry support

---

## 12. Plugin Configuration

### 12.1 Enable/Disable

```ini
# kubedash.ini
[plugin_settings]
helm = true  # Enable Helm plugin
```

### 12.2 Configuration Options

| Option | Default | Description |
|--------|---------|-------------|
| `helm` | `true` | Enable/disable plugin |

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, DevOps*
