### PRD: Kyverno Policy Plugin

**OpenSpec change**: `openspec/changes/kyverno-plugin/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

Kyverno is a widely used **Kubernetes policy engine**, but:

- Its native interfaces (CLI, raw CRDs, YAML) are not very approachable for many application teams.
- There is no integrated way in KubeDash to:
  - See policy compliance at a glance.
  - Inspect policy reports and failures.
  - Manage exceptions in a guided UI.

We want KubeDash to provide a **first‑class Kyverno policy experience**.

#### Goals

- Visualize Kyverno **policy reports and compliance** across the cluster.
- Provide a dashboard for:
  - Policies.
  - Violations.
  - Affected resources.
- Optionally manage **policy exceptions** from the UI.

#### Functional Requirements

- **Kyverno Plugin UI**
  - New plugin under `plugins/kyverno/` with:
    - Overview dashboard of policy compliance (cluster‑wide and by namespace).
    - Views for:
      - Policy Reports.
      - Individual Policies.
      - Affected resources (Pods, Deployments, etc.).
- **Policy Reports Integration**
  - Read Kyverno `PolicyReport`/`ClusterPolicyReport` resources via `lib/k8s` wrappers.
  - Display:
    - Policy name.
    - Status (pass/warn/fail).
    - Target resource references.
- **Policy Management and Exceptions** (where permitted by RBAC):
  - Allow privileged users to:
    - Inspect policy definitions.
    - Create/manage exception CRDs for specific workloads or namespaces.

#### Non‑Functional Requirements

- **Security**
  - Only users with appropriate RBAC should be allowed to manage policies or exceptions.
  - Read‑only views must not leak sensitive configuration beyond what a user could see via `kubectl`.
- **Performance**
  - Handle clusters with many policies and reports without degrading dashboard performance (pagination, filtering).

---

### Implementation Tasks (from OpenSpec)

#### 1. Plugin Infrastructure Setup

- [ ] 1.1 Create plugin directory structure at `src/kubedash/plugins/kyverno/` with `__init__.py`, `api.py`, `k8s_client.py`, `templates/kyverno/`.
- [ ] 1.2 Implement Flask blueprint registration in `__init__.py` following Flux plugin pattern.
- [ ] 1.3 Implement API blueprint for REST endpoints at `/api/v1/plugins/kyverno/`.
- [ ] 1.4 Add plugin configuration to `kubedash.ini.example` with `kyverno = true` option.
- [ ] 1.5 Update plugin discovery to include `kyverno` in available plugins list.

#### 2. K8s Client Wrappers for Kyverno CRDs

- [ ] 2.1 Implement `k8sClusterPolicyListGet()` function in `k8s_client.py` using `CustomObjectsApi`.
- [ ] 2.2 Implement `k8sPolicyListGet(namespace)` function for namespaced policies.
- [ ] 2.3 Implement `k8sPolicyExceptionListGet(namespace)` and `k8sClusterPolicyExceptionListGet()`.
- [ ] 2.4 Implement `k8sPolicyReportGet(namespace)` and `k8sClusterPolicyReportGet()`.
- [ ] 2.5 Implement `k8sPolicyGet(name, namespace)` for individual policy fetch with error handling.
- [ ] 2.6 Add error handling for 404 (CRD not found), 403 (permission denied), and timeout scenarios.
- [ ] 2.7 Write unit tests for all K8s client wrapper functions with mocked API responses.

#### 3. Kyverno Resource List Views

- [ ] 3.1 Create `cluster-policies.html.j2` template for ClusterPolicy list view with DataTables.
- [ ] 3.2 Create `policies.html.j2` template for namespaced Policy list view.
- [ ] 3.3 Create `exceptions.html.j2` template for PolicyException list with expiration indicators.
- [ ] 3.4 Create `reports.html.j2` template for PolicyReport list with pass/fail columns.
- [ ] 3.5 Implement namespace filter dropdown component (reuse from Flux plugin).
- [ ] 3.6 Implement search functionality for resource name filtering.
- [ ] 3.7 Add status indicator badges (Ready, Error, Suspended) based on conditions.
- [ ] 3.8 Create UI routes in `__init__.py` for all list views.

#### 4. Kyverno Resource Detail Views

- [ ] 4.1 Create `policy-detail.html.j2` with tabs: Overview, Rules, YAML, Violations.
- [ ] 4.2 Create `exception-detail.html.j2` with tabs: Overview, Audit Trail, Related Resources.
- [ ] 4.3 Create `report-detail.html.j2` with tabs: Summary, Policies, Failed Resources.
- [ ] 4.4 Integrate Monaco YAML editor for read‑only YAML view (reuse from existing KubeDash components).
- [ ] 4.5 Implement rules display component showing match/exclude/validation for each rule.
- [ ] 4.6 Implement conditions parser and display (Ready, Synchronized, etc.).
- [ ] 4.7 Create UI routes for all detail views with proper error handling.

#### 5. Compliance Dashboard

- [ ] 5.1 Create `compliance-dashboard.html.j2` with gauge chart, bar chart, pie chart, and hotspot table.
- [ ] 5.2 Implement compliance score calculation: `(pass / (pass + fail)) * 100`.
- [ ] 5.3 Create gauge chart component using Chart.js with color coding (green/yellow/red).
- [ ] 5.4 Implement violations by namespace horizontal bar chart.
- [ ] 5.5 Implement violations by category pie chart (from `kyverno.io/category` label).
- [ ] 5.6 Create violations hotspot table with top 10 most‑violated resources.
- [ ] 5.7 Implement time range selector (24h, 7d, 30d, 90d) with trend chart.
- [ ] 5.8 Add background refresh every 60 seconds using existing SocketIO infrastructure.
- [ ] 5.9 Create API endpoint `/api/v1/plugins/kyverno/compliance-data` for dashboard data.

#### 6. Policy Management – CRUD Operations

- [ ] 6.1 Create `policy-create.html.j2` with template library grid and search.
- [ ] 6.2 Implement 15 built‑in policy templates in `templates/kyverno/templates/` JSON files.
- [ ] 6.3 Create Monaco YAML editor with Kyverno schema validation for policy creation.
- [ ] 6.4 Implement visual form builder component for simple policy patterns.
- [ ] 6.5 Add form‑to‑YAML generator for visual builder output.
- [ ] 6.6 Implement policy create API endpoint with validation before apply.
- [ ] 6.7 Implement policy update API endpoint with diff view before confirmation.
- [ ] 6.8 Implement policy delete with name confirmation dialog.
- [ ] 6.9 Implement policy clone functionality with editable name.
- [ ] 6.10 Add suspend/resume toggle that sets `validationFailureAction` to Audit/Enforce.

#### 7. Policy Reports UI

- [ ] 7.1 Implement PolicyReport aggregation by namespace, policy, and category.
- [ ] 7.2 Create donut chart component for pass/fail/warn/skip distribution.
- [ ] 7.3 Implement resource‑level drill‑down from PolicyReport to individual violations.
- [ ] 7.4 Add navigation to built‑in K8s resources from violation links.
- [ ] 7.5 Implement CSV export for PolicyReport results.
- [ ] 7.6 Implement PDF export with executive summary and charts.
- [ ] 7.7 Create historical trend analysis with 7d/30d/90d line charts.
- [ ] 7.8 Add filtering by namespace, policy name, and status (has failures).

#### 8. Policy Exceptions Management

- [ ] 8.1 Create exception creation form with justification field (min 50 chars).
- [ ] 8.2 Implement policy/rule selector with auto‑population from selected policy.
- [ ] 8.3 Add approver annotation from current user session.
- [ ] 8.4 Implement expiration date handling with warning banners.
- [ ] 8.5 Create impact analysis component showing affected violations.
- [ ] 8.6 Implement audit trail logging for all exception CRUD operations.
- [ ] 8.7 Add full‑text search across justification field.
- [ ] 8.8 Implement combined filters (expiring soon, by policy, by namespace, by approver).
- [ ] 8.9 Create exception renewal workflow with pre‑populated edit form.

#### 9. REST API Endpoints

- [ ] 9.1 Implement `GET /api/v1/plugins/kyverno/cluster-policies` endpoint.
- [ ] 9.2 Implement `GET /api/v1/plugins/kyverno/policies?namespace=` endpoint.
- [ ] 9.3 Implement `GET /api/v1/plugins/kyverno/policies/<name>` endpoint.
- [ ] 9.4 Implement `POST /api/v1/plugins/kyverno/policies` for create.
- [ ] 9.5 Implement `PUT /api/v1/plugins/kyverno/policies/<name>` for update.
- [ ] 9.6 Implement `DELETE /api/v1/plugins/kyverno/policies/<name>` for delete.
- [ ] 9.7 Implement `GET /api/v1/plugins/kyverno/compliance-data` for dashboard.
- [ ] 9.8 Implement `GET /api/v1/plugins/kyverno/reports` for PolicyReport list.
- [ ] 9.9 Implement `GET /api/v1/plugins/kyverno/exceptions` for PolicyException list.
- [ ] 9.10 Add Admin role check for all write operations (POST/PUT/DELETE).
- [ ] 9.11 Add OpenAPI/Swagger documentation for all endpoints.

#### 10. RBAC and Security

- [ ] 10.1 Implement Admin role check for policy create/edit/delete operations.
- [ ] 10.2 Implement read‑only mode for User role (view but no write).
- [ ] 10.3 Add configurable `read_only_for_users` setting in plugin config.
- [ ] 10.4 Integrate audit logging for all policy changes (create, update, delete, suspend, resume).
- [ ] 10.5 Add CSRF protection for all form submissions.
- [ ] 10.6 Implement YAML validation to prevent malicious content.

#### 11. Testing

- [ ] 11.1 Write unit tests for K8s client wrapper functions.
- [ ] 11.2 Write integration tests for API endpoints with mocked K8s API.
- [ ] 11.3 Write functional tests for UI routes and template rendering.
- [ ] 11.4 Write RBAC tests verifying Admin/User role permissions.
- [ ] 11.5 Create E2E test scenario: create policy from template, view in list, edit, delete.
- [ ] 11.6 Create E2E test scenario: view compliance dashboard with mock data.
- [ ] 11.7 Test against Kyverno 1.10+ in development cluster.
- [ ] 11.8 Performance test with 1000+ policies and 10000+ PolicyReport results.

#### 12. Documentation

- [ ] 12.1 Write user guide: viewing policies, creating from templates, managing exceptions.
- [ ] 12.2 Write admin guide: plugin configuration, RBAC setup, Kyverno prerequisites.
- [ ] 12.3 Create policy template reference documentation.
- [ ] 12.4 Add troubleshooting section (CRDs not found, permissions issues).
- [ ] 12.5 Update Helm chart README with kyverno plugin toggle documentation.
- [ ] 12.6 Create screenshot gallery for documentation.

#### 13. Deployment and Release

- [ ] 13.1 Add plugin enable/disable toggle to Helm chart `values.yaml`.
- [ ] 13.2 Update Helm chart README with kyverno plugin documentation.
- [ ] 13.3 Test plugin installation on fresh KubeDash deployment.
- [ ] 13.4 Test plugin upgrade from disabled to enabled state.
- [ ] 13.5 Create release notes for v4.2.0 with kyverno plugin feature.
- [ ] 13.6 Record demo video for release announcement.

