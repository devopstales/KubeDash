# Product Requirements Document: Trivy Operator Plugin

**Document Version**: 1.1  
**Last Updated**: January 2025  
**Product**: KubeDash  
**Feature Area**: Trivy Operator Security Plugin  
**Status**: Active - MVP Implemented  

---

## Implementation Status

> **Overall Progress: ~75% Complete (MVP Fully Implemented)**

### MVP Implementation Summary
✅ **MVP Status: COMPLETE** - The core Trivy Operator plugin has been fully implemented as an MVP with dedicated plugin routes, comprehensive list and detail views for all primary report types, and full support for both API variants.

| Feature | Status | Completion | Notes |
|---------|--------|------------|-------|
| **Pod Vulnerability Summary** | ✅ Implemented | 90% | Summary counts in pod list (existing in `lib/k8s/security.py`) |
| **Pod Vulnerability Details** | ✅ Implemented | 85% | Per-container CVE list (existing in `lib/k8s/security.py`) |
| **VulnerabilityReport Listing** | ✅ **Implemented** | **100%** | **Full dedicated plugin view with tabs** |
| **VulnerabilityReport Details** | ✅ **Implemented** | **100%** | **Complete detail view with vulnerabilities table** |
| **ConfigAuditReport** | ✅ **Implemented** | **100%** | **Full list and detail views with check results** |
| **ExposedSecretReport** | ✅ **Implemented** | **100%** | **Full list and detail views** |
| **RbacAssessmentReport** | ✅ **Implemented** | **100%** | **Full list and detail views** |
| **InfraAssessmentReport** | ❌ Not Started | 0% | Planned (similar to ConfigAudit) |
| **ClusterComplianceReport** | ❌ Not Started | 0% | Planned |
| **SBOM Reports** | ❌ Not Started | 0% | Planned |
| **Vulnerability Dashboard** | ❌ Not Started | 0% | Aggregated statistics (P2) |

### User Story Status
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-TRIVY-001: View Pod Vulnerabilities | ✅ Done | `lib/k8s/security.py` |
| US-TRIVY-002: View Vulnerability Details | ✅ Done | `lib/k8s/security.py` |
| US-TRIVY-003: List VulnerabilityReports | ✅ **Done** | **`plugins/trivy_operator/`** |
| US-TRIVY-010: View ConfigAuditReports | ✅ **Done** | **`plugins/trivy_operator/`** |
| US-TRIVY-040: View Exposed Secrets | ✅ **Done** | **`plugins/trivy_operator/`** |
| US-TRIVY-020: View ClusterComplianceReports | ❌ Not Done | Planned |
| US-TRIVY-004: Vulnerability Dashboard | ❌ Not Done | Planned (P2) |
| US-TRIVY-011: View InfraAssessmentReports | ❌ Not Done | Planned (P3) |
| US-TRIVY-030: View SBOM Reports | ❌ Not Done | Planned (P3) |

### MVP Implementation Details

**Implemented Features:**
- ✅ Dedicated plugin route: `/plugins/trivy-operator`
- ✅ Main dashboard with tabbed interface for all report types
- ✅ Namespace filtering support
- ✅ Auto-detection of Trivy Operator API variants (both `aquasecurity.github.io/v1alpha1` and `trivy-operator.devopstales.io/v1`)
- ✅ Complete VulnerabilityReport support (list + detail views)
- ✅ Complete ConfigAuditReport support (list + detail views)
- ✅ Complete ExposedSecretReport support (list + detail views)
- ✅ Complete RbacAssessmentReport support (list + detail views)
- ✅ Detail views include: Overview, Findings, Events, and YAML tabs
- ✅ Color-coded severity indicators
- ✅ DataTables for sorting and filtering
- ✅ Integration with KubeDash plugin system
- ✅ Configuration support in `kubedash.ini`

**Implementation Files:**
- `plugins/trivy_operator/__init__.py` - Blueprint and routes
- `plugins/trivy_operator/functions.py` - All API interaction functions
- `plugins/trivy_operator/templates/trivy-operator.html.j2` - Main dashboard
- `plugins/trivy_operator/templates/vulnerability-detail.html.j2` - VulnerabilityReport detail
- `plugins/trivy_operator/templates/configaudit-detail.html.j2` - ConfigAuditReport detail
- `plugins/trivy_operator/templates/exposedsecret-detail.html.j2` - ExposedSecretReport detail
- `plugins/trivy_operator/templates/rbacassessment-detail.html.j2` - RbacAssessmentReport detail

**Not Yet Implemented (Future Enhancements):**
- ⚠️ Vulnerability Dashboard with aggregated statistics (US-TRIVY-004)
- ⚠️ ClusterComplianceReport support (US-TRIVY-020)
- ⚠️ InfraAssessmentReport support (US-TRIVY-011)
- ⚠️ SBOM Report support (US-TRIVY-030)
- ⚠️ Export functionality (CSV/JSON)
- ⚠️ Advanced filtering within findings
- ⚠️ Trend analysis and historical data

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for the KubeDash Trivy Operator Plugin. The plugin provides visibility into security scanning results from Trivy Operator, enabling users to view vulnerability reports, configuration audits, and compliance assessments for their Kubernetes workloads.

### 1.2 Background

Trivy Operator (by Aqua Security) is a Kubernetes-native security scanner that automatically scans container images for vulnerabilities, misconfiguration, and compliance issues. It stores results as Custom Resources, making them accessible via the Kubernetes API. KubeDash can surface this data to provide security visibility without requiring users to run CLI commands.

### 1.3 Goals

1. **Vulnerability Visibility**: View CVEs affecting running workloads
2. **Configuration Security**: Surface misconfigurations in resource specs
3. **Compliance Monitoring**: Track compliance against security standards
4. **Risk Prioritization**: Help teams focus on critical vulnerabilities
5. **Integration**: Seamless integration with workload views

---

## 2. User Personas

### 2.1 Security Engineer

- **Role**: Monitors and remediates security vulnerabilities
- **Technical Level**: Advanced
- **Goals**: Identify high-risk vulnerabilities, track remediation progress
- **Frustrations**: Scattered security data, manual report generation

### 2.2 Application Developer

- **Role**: Develops and maintains containerized applications
- **Technical Level**: Intermediate
- **Goals**: Understand vulnerabilities in their images, prioritize fixes
- **Frustrations**: Security reports hard to understand, too many false positives

### 2.3 Compliance Officer

- **Role**: Ensures regulatory and policy compliance
- **Technical Level**: Basic to intermediate
- **Goals**: Generate compliance reports, demonstrate due diligence
- **Frustrations**: Manual compliance assessment, lack of dashboards

---

## 3. User Stories

### 3.1 Vulnerability Assessment

#### US-TRIVY-001: View Pod Vulnerability Summary
**As a** user  
**I want to** see vulnerability counts for pods  
**So that** I can identify which pods have security issues  

**Acceptance Criteria**:
- Display vulnerability summary in pod list view
- Show counts by severity:
  - Critical (red)
  - High (orange)
  - Medium (yellow)
  - Low (blue)
- Visual indicators for vulnerability presence
- Sort/filter by vulnerability count
- Show "No report" if scan not available
- Support both Trivy Operator v0.x and Aqua Trivy Operator

**Priority**: P0 (Critical)

---

#### US-TRIVY-002: View Pod Vulnerability Details
**As a** user  
**I want to** see detailed vulnerabilities for a pod  
**So that** I can understand and remediate security issues  

**Acceptance Criteria**:
- Display vulnerabilities per container
- Vulnerability information:
  - CVE ID (with link to NVD/vendor)
  - Severity (Critical/High/Medium/Low)
  - CVSS Score
  - Package/Resource affected
  - Installed version
  - Fixed version (if available)
  - Published date
  - Description
- Sort by severity (Critical first)
- Filter by:
  - Severity
  - Fixable (has fixed version)
  - Package name
- Group by container
- Export capability (CSV/JSON)

**Priority**: P0 (Critical)

---

#### US-TRIVY-003: List VulnerabilityReports
**As a** user  
**I want to** see all VulnerabilityReports in a namespace  
**So that** I can get a comprehensive security overview  

**Acceptance Criteria**:
- Display VulnerabilityReport resources
- Information:
  - Name
  - Namespace
  - Resource kind (Pod, ReplicaSet, etc.)
  - Resource name
  - Container name
  - Registry/Repository
  - Image tag/digest
  - Critical/High/Medium/Low counts
  - Scan timestamp
- Filter by:
  - Namespace
  - Severity threshold
  - Resource kind
- Sort by vulnerability count or scan time
- Link to workload view

**Priority**: P1 (High)

---

#### US-TRIVY-004: Vulnerability Dashboard
**As a** security engineer  
**I want** a security overview dashboard  
**So that** I can quickly assess cluster security posture  

**Acceptance Criteria**:
- Summary statistics:
  - Total vulnerabilities by severity
  - Resources scanned vs total
  - Resources with critical vulnerabilities
  - Most vulnerable images
- Trend charts (if historical data)
- Top 10 CVEs across cluster
- Most affected namespaces
- Recently discovered vulnerabilities

**Priority**: P2 (Medium)

---

### 3.2 Configuration Audit

#### US-TRIVY-010: View ConfigAuditReports
**As a** user  
**I want to** see configuration audit results  
**So that** I can fix misconfigurations  

**Acceptance Criteria**:
- Display ConfigAuditReport resources
- Information:
  - Resource name
  - Resource kind
  - Namespace
  - Critical/High/Medium/Low check counts
  - Pass/Fail summary
- Check details:
  - Check ID
  - Severity
  - Title
  - Description
  - Remediation guidance
  - Result (Pass/Fail)
- Group by category (Pod Security, RBAC, etc.)
- Link to affected resource

**Priority**: P2 (Medium)

---

#### US-TRIVY-011: View InfraAssessmentReports
**As a** platform engineer  
**I want to** see infrastructure security assessments  
**So that** I can secure cluster components  

**Acceptance Criteria**:
- Display InfraAssessmentReport resources
- Cover Kubernetes components:
  - API Server
  - Controller Manager
  - Scheduler
  - etcd
  - Kubelet
- Show CIS Benchmark results
- Highlight failing checks

**Priority**: P3 (Future)

---

### 3.3 Compliance

#### US-TRIVY-020: View ClusterComplianceReports
**As a** compliance officer  
**I want to** see compliance assessment results  
**So that** I can demonstrate regulatory compliance  

**Acceptance Criteria**:
- Display ClusterComplianceReport resources
- Supported standards:
  - NSA/CISA Kubernetes Hardening Guide
  - CIS Kubernetes Benchmark
  - PCI-DSS (container relevant controls)
  - Custom compliance specs
- Summary:
  - Total controls
  - Passed/Failed/Manual counts
  - Compliance percentage
- Control details:
  - Control ID and name
  - Description
  - Status
  - Affected resources

**Priority**: P2 (Medium)

---

### 3.4 SBOM (Software Bill of Materials)

#### US-TRIVY-030: View SBOM Reports
**As a** security engineer  
**I want to** see software bill of materials  
**So that** I can inventory all software components  

**Acceptance Criteria**:
- Display SbomReport resources
- SBOM information:
  - Image reference
  - Components list
  - Component type (library, OS package)
  - Version
  - License
- Search components
- Export SBOM (CycloneDX, SPDX formats)

**Priority**: P3 (Future)

---

### 3.5 Secret Detection

#### US-TRIVY-040: View Exposed Secrets
**As a** security engineer  
**I want to** see detected secrets in images  
**So that** I can remediate secret exposure  

**Acceptance Criteria**:
- Display ExposedSecretReport resources
- Secret information:
  - Target (file path)
  - Rule ID
  - Category
  - Severity
  - Title
- Mask actual secret values
- Link to remediation guidance

**Priority**: P3 (Future)

---

## 4. Functional Requirements

### 4.1 Vulnerability Management

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-VULN-01 | Plugin shall display vulnerability summary in pod list | P0 |
| FR-VULN-02 | Plugin shall display detailed CVE information | P0 |
| FR-VULN-03 | Plugin shall list VulnerabilityReport resources | P1 |
| FR-VULN-04 | Plugin shall support severity-based filtering | P1 |
| FR-VULN-05 | Plugin shall show fixed version when available | P1 |
| FR-VULN-06 | Plugin shall link CVEs to external databases | P2 |

### 4.2 Configuration Audit

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-CONF-01 | Plugin shall list ConfigAuditReport resources | P2 |
| FR-CONF-02 | Plugin shall display check pass/fail status | P2 |
| FR-CONF-03 | Plugin shall show remediation guidance | P2 |

### 4.3 Compliance

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-COMP-01 | Plugin shall list ClusterComplianceReport resources | P2 |
| FR-COMP-02 | Plugin shall display compliance percentage | P2 |
| FR-COMP-03 | Plugin shall show control-level details | P2 |

### 4.4 Plugin Behavior

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-PLG-01 | Plugin shall detect Trivy Operator installation | P1 |
| FR-PLG-02 | Plugin shall support both API groups | P0 |
| FR-PLG-03 | Plugin shall cache vulnerability data | P2 |
| FR-PLG-04 | Plugin shall integrate with workload views | P0 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Vulnerability summary load time | < 2 seconds |
| NFR-PERF-02 | Full report load time | < 3 seconds |
| NFR-PERF-03 | Dashboard aggregation time | < 5 seconds |

### 5.2 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | Trivy Operator (Aqua) v0.15+ | Required |
| NFR-COMP-02 | DevOpsTales Trivy Operator | Required |
| NFR-COMP-03 | Both API groups simultaneously | Supported |

### 5.3 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-USE-01 | Find critical vulnerabilities | < 3 clicks |
| NFR-USE-02 | View pod security status | Visible in list |

---

## 6. Technical Considerations

### 6.1 Trivy Operator CRDs (Aqua Security)

| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| VulnerabilityReport | aquasecurity.github.io | v1alpha1 | Namespaced |
| ConfigAuditReport | aquasecurity.github.io | v1alpha1 | Namespaced |
| InfraAssessmentReport | aquasecurity.github.io | v1alpha1 | Namespaced |
| ClusterComplianceReport | aquasecurity.github.io | v1alpha1 | Cluster |
| ClusterConfigAuditReport | aquasecurity.github.io | v1alpha1 | Cluster |
| SbomReport | aquasecurity.github.io | v1alpha1 | Namespaced |
| ExposedSecretReport | aquasecurity.github.io | v1alpha1 | Namespaced |

### 6.2 DevOpsTales Trivy Operator CRDs

| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| VulnerabilityReport | trivy-operator.devopstales.io | v1 | Namespaced |

### 6.3 API Detection Logic

```python
def detect_trivy_operator():
    """
    Detect which Trivy Operator variant is installed.
    Returns the API group to use.
    """
    # Try DevOpsTales API first
    try:
        k8s_client.CustomObjectsApi().list_cluster_custom_object(
            "trivy-operator.devopstales.io", "v1", "vulnerabilityreports",
            _request_timeout=1
        )
        return "trivy-operator.devopstales.io", "v1"
    except ApiException as e:
        if e.status == 404:
            pass  # CRD not found, try Aqua
    
    # Try Aqua Security API
    try:
        k8s_client.CustomObjectsApi().list_cluster_custom_object(
            "aquasecurity.github.io", "v1alpha1", "vulnerabilityreports",
            _request_timeout=1
        )
        return "aquasecurity.github.io", "v1alpha1"
    except ApiException:
        pass
    
    return None, None  # No Trivy Operator found
```

### 6.4 Implementation Files

**Current Implementation (MVP Complete):**
```
lib/k8s/security.py          # Existing - pod vulnerability functions (legacy)
plugins/trivy_operator/      # ✅ IMPLEMENTED - Dedicated plugin
├── __init__.py              # ✅ Blueprint routes (5 routes)
├── functions.py              # ✅ All report type functions
│   ├── check_trivy_operator_installed()
│   ├── TrivyGetVulnerabilityReports()
│   ├── TrivyGetVulnerabilityReport()
│   ├── TrivyGetConfigAuditReports()
│   ├── TrivyGetConfigAuditReport()
│   ├── TrivyGetExposedSecretReports()
│   ├── TrivyGetExposedSecretReport()
│   ├── TrivyGetRbacAssessmentReports()
│   ├── TrivyGetRbacAssessmentReport()
│   └── TrivyGetEvents()
└── templates/
    ├── trivy-operator.html.j2           # ✅ Main dashboard
    ├── vulnerability-detail.html.j2      # ✅ VulnerabilityReport detail
    ├── configaudit-detail.html.j2       # ✅ ConfigAuditReport detail
    ├── exposedsecret-detail.html.j2     # ✅ ExposedSecretReport detail
    └── rbacassessment-detail.html.j2    # ✅ RbacAssessmentReport detail
```

**Planned (Future):**
```
plugins/trivy_operator/
├── compliance.py            # ClusterComplianceReport functions (planned)
├── sbom.py                  # SBOM functions (planned)
└── templates/
    └── dashboard.html.j2    # Aggregated security dashboard (planned)
```

---

## 7. User Interface Guidelines

### 7.1 Pod List with Vulnerabilities

```
+--------------------------------------------------+
| Pods                               [Namespace ▼] |
+--------------------------------------------------+
| Name      | Status | Vulns                       |
|-----------|--------|------------------------------|
| web-abc   | Running| 🔴 2 | 🟠 5 | 🟡 12 | 🔵 30 |
| api-def   | Running| 🔴 0 | 🟠 1 | 🟡 3  | 🔵 8  |
| worker-gh | Running| No scan available            |
+--------------------------------------------------+
```

### 7.2 Vulnerability Details View

```
+--------------------------------------------------+
| Pod: web-abc | Vulnerabilities                    |
+--------------------------------------------------+
| Container: nginx                                  |
| Image: nginx:1.21.0                              |
+--------------------------------------------------+
| [All] [Critical] [High] [Fixable Only]           |
+--------------------------------------------------+
| CVE ID       | Sev  | Package    | Inst  | Fixed |
|--------------|------|------------|-------|-------|
| CVE-2024-001 | 🔴CRIT| openssl   | 1.1.1 | 1.1.2 |
| CVE-2024-002 | 🟠HIGH| libcurl   | 7.80  | 7.81  |
| CVE-2023-045 | 🟡MED | zlib      | 1.2.11| -     |
+--------------------------------------------------+
```

### 7.3 Security Dashboard

```
+--------------------------------------------------+
| Security Overview                                 |
+--------------------------------------------------+
| Vulnerability Summary                             |
| +------------+  +------------+  +------------+   |
| | Critical   |  | High       |  | Medium     |   |
| |    15      |  |    87      |  |    234     |   |
| +------------+  +------------+  +------------+   |
+--------------------------------------------------+
| Top Affected Images            | Top CVEs        |
| +---------------------------+  | +-------------+ |
| | nginx:1.21.0       | 45  |  | | CVE-2024-x  | |
| | postgres:13        | 32  |  | | CVE-2024-y  | |
| | redis:6            | 28  |  | | CVE-2023-z  | |
| +---------------------------+  | +-------------+ |
+--------------------------------------------------+
```

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Kubernetes library (CustomObjects API)
- Workload blueprint (pod views)
- Caching layer

### 8.2 External Dependencies

- Trivy Operator installed in cluster
- Trivy Operator CRDs available
- Vulnerability database updated

### 8.3 RBAC Requirements

```yaml
# Aqua Security Trivy Operator
- apiGroups: ["aquasecurity.github.io"]
  resources: ["vulnerabilityreports", "configauditreports", "infraassessmentreports", 
              "clustercompliancereports", "sbomreports", "exposedsecretreports"]
  verbs: ["get", "list"]
# DevOpsTales Trivy Operator
- apiGroups: ["trivy-operator.devopstales.io"]
  resources: ["vulnerabilityreports"]
  verbs: ["get", "list"]
```

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| No Trivy Operator installed | High | Medium | Show install guidance, graceful disable |
| Large vulnerability datasets | Medium | High | Pagination, caching, efficient queries |
| Stale scan data | Medium | Medium | Show scan timestamp, highlight old scans |
| Multiple API group confusion | Low | Medium | Auto-detect, support both |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Plugin adoption | 70% of Trivy users | Feature analytics |
| Time to find critical CVE | < 30 seconds | User research |
| Vulnerability visibility | 100% coverage | Data accuracy tests |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Vulnerability Trends**: Historical tracking of CVE counts
2. **Remediation Tracking**: Mark CVEs as acknowledged/remediated
3. **JIRA Integration**: Create tickets for vulnerabilities
4. **Policy Enforcement**: Block deployments based on CVE severity
5. **Image Scanning**: Trigger on-demand scans
6. **SBOM Export**: Export SBOM in standard formats

### 11.2 Out of Scope (This Version)

- On-demand scanning
- Image admission control
- Vulnerability remediation
- Integration with external vulnerability databases

---

## 12. Plugin Configuration

```ini
# kubedash.ini
[plugin_settings]
trivy_operator = true  # Enable Trivy Operator plugin
```

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, Security, Compliance*
