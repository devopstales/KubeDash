# Product Requirements Document: Extension API

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Product**: KubeDash  
**Feature Area**: Extension API (Kubernetes API Aggregation Layer)  
**Status**: Active  

---

## Implementation Status

> **Overall Progress: ~95% Complete**

This section tracks the current implementation status against the requirements defined in this PRD.

### Feature Implementation Matrix

| Feature Category | Status | Completion | Notes |
|-----------------|--------|------------|-------|
| **API Discovery** | ✅ Implemented | 100% | Full K8s API discovery endpoints |
| **Projects CRUD** | ✅ Implemented | 100% | Create, Read, Update, Delete |
| **Bearer Token Auth** | ✅ Implemented | 100% | ServiceAccount token validation |
| **Session Auth** | ✅ Implemented | 100% | Cookie-based auth |
| **Table Format** | ✅ Implemented | 100% | kubectl output support |
| **OpenAPI Spec** | ✅ Implemented | 100% | `/apis/openapi/v2` endpoint |
| **Health Check** | ✅ Implemented | 100% | `/apis/healthz` endpoint |
| **RBAC Integration** | ✅ Implemented | 100% | Namespace-based filtering |
| **Watch Support** | ❌ Not Started | 0% | Planned for future |

### User Story Implementation Status

#### API Discovery
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-API-001: Discover API Groups | ✅ Done | `blueprint/extension_api.py` |
| US-API-002: Discover API Resources | ✅ Done | `blueprint/extension_api.py` |
| US-API-003: OpenAPI Specification | ✅ Done | `blueprint/extension_api.py` |

#### Authentication
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-AUTH-001: ServiceAccount Token Auth | ✅ Done | `lib/extension_api.py` |
| US-AUTH-002: Session Cookie Auth | ✅ Done | `lib/extension_api.py` |
| US-AUTH-003: Unauthenticated Rejection | ✅ Done | Returns 401 Status |

#### Projects Resource
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-PROJ-001: List Projects | ✅ Done | `blueprint/extension_api.py` |
| US-PROJ-002: Get Project | ✅ Done | `blueprint/extension_api.py` |
| US-PROJ-003: Create Project | ✅ Done | `blueprint/extension_api.py` |
| US-PROJ-004: Update Project | ✅ Done | `blueprint/extension_api.py` |
| US-PROJ-005: Patch Project | ✅ Done | `blueprint/extension_api.py` |
| US-PROJ-006: Delete Project | ✅ Done | `blueprint/extension_api.py` |

#### kubectl Integration
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-KUBECTL-001: List with kubectl | ✅ Done | Table format support |
| US-KUBECTL-002: Create with kubectl | ✅ Done | POST endpoint |
| US-KUBECTL-003: Delete with kubectl | ✅ Done | DELETE endpoint |

#### Health & Monitoring
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-HEALTH-001: Health Check Endpoint | ✅ Done | `/apis/healthz` |

### Key Implementation Details

- **API Group**: `kubedash.devopstales.github.io`
- **API Version**: `v1`
- **Resource**: `projects` (cluster-scoped)
- **CSRF Exemption**: Blueprint exempt for Bearer token auth
- **Token Validation**: Uses Kubernetes TokenReview API
- **Table Format**: Custom `_build_table_response()` for kubectl

### Endpoints Implemented

| Method | Endpoint | Status |
|--------|----------|--------|
| GET | `/apis/` | ✅ APIGroupList |
| GET | `/apis/kubedash.devopstales.github.io` | ✅ APIGroup |
| GET | `/apis/kubedash.devopstales.github.io/v1` | ✅ APIResourceList |
| GET | `/apis/.../v1/projects` | ✅ ProjectList |
| POST | `/apis/.../v1/projects` | ✅ Create |
| GET | `/apis/.../v1/projects/{name}` | ✅ Get |
| PUT | `/apis/.../v1/projects/{name}` | ✅ Update |
| PATCH | `/apis/.../v1/projects/{name}` | ✅ Patch |
| DELETE | `/apis/.../v1/projects/{name}` | ✅ Delete |
| GET | `/apis/healthz` | ✅ Health |
| GET | `/apis/openapi/v2` | ✅ OpenAPI |

### Technical Debt & Known Issues

1. **Watch support** - Not implemented, no real-time updates
2. **Pagination** - Basic `limit` support, `continue` token not implemented
3. **Field selectors** - Limited support
4. **Subresources** - Status subresource not implemented

### Next Steps

1. Implement Watch/streaming API for real-time updates
2. Add full pagination with continue tokens
3. Implement status subresource for status updates
4. Add admission webhook support

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for KubeDash's Extension API, which implements the Kubernetes API Aggregation Layer pattern. The Extension API exposes custom resources (Projects) through a Kubernetes-native API that can be consumed by kubectl, Kubernetes clients, and GitOps tools.

### 1.2 Background

Kubernetes API Aggregation allows extending the Kubernetes API with custom API servers. By implementing this pattern, KubeDash can expose its functionality through standard Kubernetes tooling. This enables:
- Using kubectl to manage KubeDash resources
- GitOps workflows with ArgoCD, Flux
- Automation via Kubernetes client libraries
- Integration with existing Kubernetes toolchains

### 1.3 Goals

1. **Kubernetes Native**: Full compatibility with kubectl and K8s clients
2. **API Discovery**: Proper API discovery for tooling integration
3. **Authentication**: Support ServiceAccount tokens and session auth
4. **CRUD Operations**: Complete create, read, update, delete for Projects
5. **RBAC Alignment**: Honor Kubernetes RBAC permissions

---

## 2. User Personas

### 2.1 Platform Engineer

- **Role**: Manages platform infrastructure and automation
- **Technical Level**: Expert
- **Goals**: Automate project creation, integrate with GitOps
- **Frustrations**: Non-standard APIs require custom scripting

### 2.2 DevOps Engineer

- **Role**: Manages application deployments
- **Technical Level**: Advanced
- **Goals**: Use familiar kubectl commands
- **Frustrations**: Learning new tools and APIs

### 2.3 CI/CD Pipeline

- **Role**: Automated system
- **Technical Level**: N/A (machine)
- **Goals**: Programmatic resource management
- **Frustrations**: Complex authentication, non-standard APIs

---

## 3. User Stories

### 3.1 API Discovery

#### US-API-001: Discover API Groups
**As a** Kubernetes client  
**I want to** discover available API groups  
**So that** I can understand what resources are available  

**Acceptance Criteria**:
- `GET /apis/` returns APIGroupList
- Response includes `kubedash.devopstales.github.io` group
- Response includes preferred version information
- Format matches Kubernetes API conventions
- Response is cacheable (ETag/Last-Modified)

**Priority**: P0 (Critical)

---

#### US-API-002: Discover API Resources
**As a** Kubernetes client  
**I want to** discover resources in an API group  
**So that** I can understand available operations  

**Acceptance Criteria**:
- `GET /apis/kubedash.devopstales.github.io/v1` returns APIResourceList
- Lists all resources with:
  - Name (plural)
  - Singular name
  - Namespaced (boolean)
  - Kind
  - Verbs (get, list, create, update, patch, delete)
  - Short names
  - Categories
- Format matches Kubernetes conventions

**Priority**: P0 (Critical)

---

#### US-API-003: OpenAPI Specification
**As a** developer  
**I want to** access OpenAPI specification  
**So that** I can generate client code  

**Acceptance Criteria**:
- `GET /apis/openapi/v2` returns OpenAPI spec
- Spec documents all endpoints
- Spec includes request/response schemas
- Compatible with code generators

**Priority**: P2 (Medium)

---

### 3.2 Authentication

#### US-AUTH-001: ServiceAccount Token Authentication
**As an** automation system  
**I want to** authenticate with a ServiceAccount token  
**So that** I can access the API programmatically  

**Acceptance Criteria**:
- Accept `Authorization: Bearer <token>` header
- Validate token against Kubernetes TokenReview API
- Extract user identity from token
- Reject invalid/expired tokens with 401
- Support tokens from any namespace

**Priority**: P0 (Critical)

---

#### US-AUTH-002: Session Cookie Authentication
**As a** logged-in user  
**I want to** use the Extension API from the browser  
**So that** I can test API calls manually  

**Acceptance Criteria**:
- Accept session cookie from KubeDash login
- Bypass CSRF for API endpoints
- Same permissions as web UI
- Return proper JSON errors (not HTML redirects)

**Priority**: P1 (High)

---

#### US-AUTH-003: Unauthenticated Rejection
**As a** system  
**I want to** reject unauthenticated requests  
**So that** the API is secure  

**Acceptance Criteria**:
- Return 401 Unauthorized for missing auth
- Response in Kubernetes Status format
- Include WWW-Authenticate header
- Log authentication failures

**Priority**: P0 (Critical)

---

### 3.3 Projects Resource

#### US-PROJ-001: List Projects
**As a** user  
**I want to** list all projects I have access to  
**So that** I can see available namespaces  

**Acceptance Criteria**:
- `GET /apis/kubedash.devopstales.github.io/v1/projects`
- Returns ProjectList with items
- Filters based on Kubernetes RBAC (namespace access)
- Support query parameters:
  - `labelSelector`: Filter by labels
  - `fieldSelector`: Filter by fields
  - `limit`: Maximum results
  - `continue`: Pagination token
- Support Table format for kubectl output
- Include resourceVersion for caching

**Priority**: P0 (Critical)

---

#### US-PROJ-002: Get Project
**As a** user  
**I want to** retrieve a specific project  
**So that** I can view its details  

**Acceptance Criteria**:
- `GET /apis/kubedash.devopstales.github.io/v1/projects/{name}`
- Returns Project resource
- 404 if project doesn't exist
- 403 if user lacks permission
- Includes all spec and status fields
- Support Table format for kubectl

**Priority**: P0 (Critical)

---

#### US-PROJ-003: Create Project
**As a** user  
**I want to** create a new project  
**So that** I can provision a namespace  

**Acceptance Criteria**:
- `POST /apis/kubedash.devopstales.github.io/v1/projects`
- Request body includes:
  - `apiVersion`: kubedash.devopstales.github.io/v1
  - `kind`: Project
  - `metadata.name`: Project name (required)
  - `metadata.labels`: Optional labels
  - `spec.protected`: Boolean (required)
  - `spec.owner`: Optional, defaults to authenticated user
  - `spec.repository`: Optional git repo URL
  - `spec.pipeline`: Optional CI/CD URL
- Creates corresponding Kubernetes namespace
- Returns 201 Created with Project
- Returns 409 Conflict if exists
- Returns 403 if user lacks permission
- Validates name format (DNS compatible)

**Priority**: P0 (Critical)

---

#### US-PROJ-004: Update Project
**As a** user  
**I want to** update a project  
**So that** I can modify its configuration  

**Acceptance Criteria**:
- `PUT /apis/kubedash.devopstales.github.io/v1/projects/{name}`
- Full replacement of spec
- Updates namespace annotations
- Returns 200 OK with updated Project
- Returns 404 if not found
- Returns 403 if user lacks permission
- Supports resourceVersion for optimistic concurrency

**Priority**: P1 (High)

---

#### US-PROJ-005: Patch Project
**As a** user  
**I want to** partially update a project  
**So that** I can make targeted changes  

**Acceptance Criteria**:
- `PATCH /apis/kubedash.devopstales.github.io/v1/projects/{name}`
- Merge patch of provided fields
- Only updates specified fields
- Returns 200 OK with updated Project
- Returns 404 if not found
- Returns 403 if user lacks permission

**Priority**: P1 (High)

---

#### US-PROJ-006: Delete Project
**As a** user  
**I want to** delete a project  
**So that** I can clean up unused namespaces  

**Acceptance Criteria**:
- `DELETE /apis/kubedash.devopstales.github.io/v1/projects/{name}`
- Deletes corresponding Kubernetes namespace
- Returns 200 OK with Status
- Returns 404 if not found
- Returns 403 if:
  - User lacks permission
  - Project is protected (`spec.protected: true`)
- Log deletion for audit

**Priority**: P1 (High)

---

### 3.4 kubectl Integration

#### US-KUBECTL-001: List with kubectl
**As a** user  
**I want to** list projects using kubectl  
**So that** I can use familiar tooling  

**Acceptance Criteria**:
- `kubectl get projects` works
- Output shows: NAME, PROTECTED, OWNER, STATUS, AGE
- Supports `-o wide`, `-o yaml`, `-o json`
- Supports `-n` flag (ignored, projects are cluster-scoped)
- Supports `--selector` for label filtering

**Example**:
```
$ kubectl get projects
NAME          PROTECTED   OWNER           STATUS   AGE
production    true        platform-team   Active   30d
staging       false       dev-team        Active   25d
development   false       dev-team        Active   20d
```

**Priority**: P0 (Critical)

---

#### US-KUBECTL-002: Create with kubectl
**As a** user  
**I want to** create projects using kubectl  
**So that** I can use declarative configuration  

**Acceptance Criteria**:
- `kubectl apply -f project.yaml` works
- `kubectl create -f project.yaml` works
- Supports stdin: `cat project.yaml | kubectl apply -f -`

**Example YAML**:
```yaml
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: my-project
  labels:
    team: backend
spec:
  protected: false
  owner: john.doe
  repository: https://github.com/company/my-project
  pipeline: https://ci.example.com/my-project
```

**Priority**: P0 (Critical)

---

#### US-KUBECTL-003: Delete with kubectl
**As a** user  
**I want to** delete projects using kubectl  
**So that** I can manage lifecycle declaratively  

**Acceptance Criteria**:
- `kubectl delete project my-project` works
- Respects protected flag (returns error)
- Supports `--force` (does not override protected)
- Clear error message for protected projects

**Priority**: P1 (High)

---

### 3.5 Health & Monitoring

#### US-HEALTH-001: Health Check Endpoint
**As a** Kubernetes API server  
**I want** a health check endpoint  
**So that** I can verify Extension API is healthy  

**Acceptance Criteria**:
- `GET /apis/healthz` returns 'ok' (text/plain)
- Used by APIService health checking
- No authentication required
- Returns 200 when healthy
- Fast response (< 100ms)

**Priority**: P0 (Critical)

---

## 4. Functional Requirements

### 4.1 API Structure

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-API-01 | API shall follow Kubernetes API conventions | P0 |
| FR-API-02 | API shall support API discovery endpoints | P0 |
| FR-API-03 | API shall return JSON responses | P0 |
| FR-API-04 | API shall support Table format for kubectl | P0 |
| FR-API-05 | API shall include resourceVersion in responses | P1 |

### 4.2 Projects Resource

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-PROJ-01 | Projects shall be cluster-scoped (not namespaced) | P0 |
| FR-PROJ-02 | Projects shall map to Kubernetes namespaces | P0 |
| FR-PROJ-03 | Projects shall support protected flag | P0 |
| FR-PROJ-04 | Projects shall support owner, repository, pipeline metadata | P1 |
| FR-PROJ-05 | Projects shall have Active/Terminating status | P1 |

### 4.3 Authentication

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-AUTH-01 | API shall authenticate via Bearer token | P0 |
| FR-AUTH-02 | API shall validate tokens via TokenReview | P0 |
| FR-AUTH-03 | API shall support session cookie auth | P1 |
| FR-AUTH-04 | API shall return 401 for unauthenticated requests | P0 |

### 4.4 Authorization

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-AUTHZ-01 | API shall filter projects by K8s namespace access | P0 |
| FR-AUTHZ-02 | API shall require namespace create permission for project create | P0 |
| FR-AUTHZ-03 | API shall require namespace delete permission for project delete | P0 |
| FR-AUTHZ-04 | API shall prevent deletion of protected projects | P0 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | API response time (list) | < 500ms |
| NFR-PERF-02 | API response time (get) | < 200ms |
| NFR-PERF-03 | API response time (mutate) | < 1 second |
| NFR-PERF-04 | Health check response | < 100ms |

### 5.2 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | kubectl compatibility | v1.25+ |
| NFR-COMP-02 | client-go compatibility | v0.25+ |
| NFR-COMP-03 | Kubernetes API conventions | v1 |

### 5.3 Security

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-SEC-01 | TLS required for APIService | Required |
| NFR-SEC-02 | Token validation | Every request |
| NFR-SEC-03 | Audit logging | All mutations |
| NFR-SEC-04 | CSRF exemption | API only |

---

## 6. Technical Considerations

### 6.1 API Registration

To integrate with Kubernetes API discovery:

```yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1.kubedash.devopstales.github.io
spec:
  group: kubedash.devopstales.github.io
  version: v1
  service:
    name: kubedash-extension-api
    namespace: kubedash
    port: 443
  insecureSkipTLSVerify: true  # Or provide caBundle
  groupPriorityMinimum: 1000
  versionPriority: 100
```

### 6.2 Project Resource Schema

```yaml
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: string              # Required: DNS-compatible name
  uid: string               # Auto-generated
  creationTimestamp: string # Auto-generated
  labels: map[string]string # Optional
  annotations: map[string]string # Optional
spec:
  protected: boolean        # Required: Deletion protection
  owner: string             # Optional: Project owner
  repository: string        # Optional: Git repository URL
  pipeline: string          # Optional: CI/CD pipeline URL
  finalizers:               # System-managed
    - string
status:
  phase: string             # Active | Terminating
  namespace: string         # Linked K8s namespace
```

### 6.3 Token Validation

```python
# Validate ServiceAccount token
def validate_serviceaccount_token(token):
    """Validate token using Kubernetes TokenReview API"""
    api = k8s_client.AuthenticationV1Api()
    review = k8s_client.V1TokenReview(
        spec=k8s_client.V1TokenReviewSpec(token=token)
    )
    result = api.create_token_review(review)
    return result.status.authenticated
```

---

## 7. User Interface Guidelines

### 7.1 API Responses

All responses follow Kubernetes conventions:

**Success (List)**:
```json
{
  "kind": "ProjectList",
  "apiVersion": "kubedash.devopstales.github.io/v1",
  "metadata": {
    "resourceVersion": "12345"
  },
  "items": [...]
}
```

**Error**:
```json
{
  "kind": "Status",
  "apiVersion": "v1",
  "status": "Failure",
  "message": "projects \"foo\" not found",
  "reason": "NotFound",
  "details": {
    "name": "foo",
    "group": "kubedash.devopstales.github.io",
    "kind": "projects"
  },
  "code": 404
}
```

### 7.2 Table Format

For kubectl output:

| Column | Source | Priority |
|--------|--------|----------|
| NAME | metadata.name | 0 |
| PROTECTED | spec.protected | 0 |
| OWNER | spec.owner | 0 |
| STATUS | status.phase | 0 |
| AGE | metadata.creationTimestamp | 0 |

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Authentication system (session validation)
- Kubernetes library (namespace operations)
- Database (optional, for caching)

### 8.2 External Dependencies

- Kubernetes API Server
- TokenReview API
- Namespace API

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| APIService registration complexity | High | Medium | Clear documentation, examples |
| TLS certificate management | High | Medium | Support insecureSkipTLSVerify for dev |
| Token validation overhead | Medium | Low | Caching, efficient API calls |
| Namespace sync failures | High | Low | Retry logic, reconciliation |
| Breaking API changes | High | Low | Versioning, deprecation policy |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| kubectl compatibility | 100% | Integration tests |
| API response time | < 500ms p95 | Monitoring |
| Token validation accuracy | 100% | Security testing |
| GitOps adoption | 30% of projects | Usage analytics |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Watch Support**: Real-time updates via watch streams
2. **Admission Webhooks**: Validate project configurations
3. **Finalizers**: Custom cleanup logic
4. **Subresources**: Status subresource for status updates
5. **Custom Resources**: User-defined resource types
6. **Multi-cluster**: Cross-cluster project federation
7. **Quota Management**: Project resource quotas

### 11.2 Out of Scope (This Version)

- Watch/streaming API
- Admission webhooks
- Custom resource definitions
- Multi-cluster support
- Server-side apply

---

## 12. Appendix

### 12.1 API Endpoints Summary

| Method | Path | Description |
|--------|------|-------------|
| GET | /apis/ | List API groups |
| GET | /apis/kubedash.devopstales.github.io | Get API group |
| GET | /apis/kubedash.devopstales.github.io/v1 | List resources |
| GET | /apis/.../v1/projects | List projects |
| POST | /apis/.../v1/projects | Create project |
| GET | /apis/.../v1/projects/{name} | Get project |
| PUT | /apis/.../v1/projects/{name} | Update project |
| PATCH | /apis/.../v1/projects/{name} | Patch project |
| DELETE | /apis/.../v1/projects/{name} | Delete project |
| GET | /apis/healthz | Health check |
| GET | /apis/openapi/v2 | OpenAPI spec |

### 12.2 HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 409 | Conflict (Already Exists) |
| 500 | Internal Server Error |

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, Platform, DevOps*
