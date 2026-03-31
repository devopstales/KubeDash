### PRD: Cost Optimization Dashboard

**OpenSpec change**: `openspec/changes/cost-optimization-dashboard/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

KubeDash today focuses on **resource and health observability**, but:

- Platform and app teams increasingly need **cost visibility** at the workload and namespace level.
- Existing dashboards require manually correlating metrics with external billing or cost tools.

We want KubeDash to provide **actionable cost insights** directly in the UI.

#### Goals

- Attribute cluster costs to workloads/namespaces with reasonable accuracy.
- Identify **waste** (over‑provisioning, idle workloads).
- Provide **right‑sizing recommendations** that teams can act on.

#### Functional Requirements

- **Cost Dashboard**
  - Cluster‑level view of aggregate costs.
  - Breakdowns by:
    - Namespace.
    - Workload type (Deployment, StatefulSet, etc.).
    - Label‑based groupings (e.g. team, application).
- **Workload Cost Attribution**
  - Derive cost signals from:
    - Resource requests/limits (CPU, memory, storage).
    - Utilization metrics where available.
  - Provide per‑workload and per‑namespace estimated cost.
- **Waste Identification**
  - Highlight workloads with:
    - High request vs. usage ratios.
    - Persistent low utilization or idleness.
- **Right‑Sizing Recommendations**
  - Suggest new request/limit values for CPU/memory based on observed usage.
  - Expose recommendations via a dedicated plugin and API.

#### Non‑Functional Requirements

- **Accuracy**
  - Provide clear caveats that cost numbers are estimates unless integrated with a real billing system.
  - Make assumptions (e.g. price per vCPU/GB‑RAM) configurable.
- **Performance**
  - Cost calculations must be pre‑aggregated and cached to avoid slowing down the UI.

---

### Implementation Tasks (from OpenSpec)

#### 1. Plugin Infrastructure Setup

- [ ] 1.1 Create plugin directory structure at `src/kubedash/plugins/cost_optimization/` with `__init__.py`, `api.py`, `opencost_client.py`, `templates/cost_optimization/`.
- [ ] 1.2 Implement Flask blueprint registration in `__init__.py` following existing plugin patterns.
- [ ] 1.3 Implement API blueprint for REST endpoints at `/api/v1/plugins/cost-optimization/`.
- [ ] 1.4 Add plugin configuration to `kubedash.ini.example` with `cost_optimization = true` option.
- [ ] 1.5 Add `[cost_optimization]` section with `opencost_endpoint`, `api_key` (optional), `viewable_by_users` settings.
- [ ] 1.6 Update plugin discovery to include `cost_optimization` in available plugins list.

#### 2. OpenCost/Kubecost API Client

- [ ] 2.1 Implement `OpenCostClient` class in `opencost_client.py` with base URL and authentication.
- [ ] 2.2 Implement feature detection to identify OpenCost vs Kubecost backend.
- [ ] 2.3 Implement `get_allocation_data(start, end, aggregate_by)` method for cost allocation queries.
- [ ] 2.4 Implement `get_cluster_cost_summary(start, end)` method for total spend.
- [ ] 2.5 Implement `get_namespace_costs(start, end)` method for namespace breakdown.
- [ ] 2.6 Implement `get_workload_costs(namespace, start, end)` method for deployment/pod costs.
- [ ] 2.7 Implement `get_recommendations()` method for Kubecost right‑sizing recommendations.
- [ ] 2.8 Add connection timeout (10s) and retry logic (3 attempts with exponential backoff).
- [ ] 2.9 Add error handling for 401 (auth failure), 404 (backend not found), 503 (unavailable).
- [ ] 2.10 Write unit tests for API client with mocked responses.

#### 3. Caching Implementation

- [ ] 3.1 Implement in‑memory cache decorator with 60s TTL for recent cost queries.
- [ ] 3.2 Implement Redis cache integration with 5 min TTL for aggregated data.
- [ ] 3.3 Create cache key generator that includes namespace and time range parameters.
- [ ] 3.4 Implement cache invalidation when time range changes.
- [ ] 3.5 Add background refresh mechanism for dashboard data.
- [ ] 3.6 Write tests for caching behavior and cache hit/miss scenarios.

#### 4. Cost Dashboard UI

- [ ] 4.1 Create `dashboard.html.j2` template with gauge chart, bar chart, line chart, and summary cards.
- [ ] 4.2 Implement total daily/monthly cost display with USD formatting.
- [ ] 4.3 Create efficiency score gauge chart using Chart.js with color coding (green/yellow/red).
- [ ] 4.4 Implement namespace cost breakdown horizontal bar chart.
- [ ] 4.5 Create cost trend line chart with daily granularity for 30d+ ranges.
- [ ] 4.6 Implement time range selector component (24h, 7d, 30d, 90d).
- [ ] 4.7 Add namespace filter dropdown with “All Namespaces” option.
- [ ] 4.8 Implement period comparison toggle (current vs previous period).
- [ ] 4.9 Add background refresh every 60 seconds using existing SocketIO infrastructure.
- [ ] 4.10 Create UI route `/plugins/cost-optimization/` for main dashboard.

#### 5. Workload Cost Attribution UI

- [ ] 5.1 Create `deployments.html.j2` template showing cost per deployment with sortable columns.
- [ ] 5.2 Create `deployment-detail.html.j2` with tabs: Overview, Pods, Cost Breakdown, Trend.
- [ ] 5.3 Implement pod‑level cost breakdown table with efficiency indicators.
- [ ] 5.4 Create container‑level cost allocation view for multi‑container pods.
- [ ] 5.5 Implement cost per replica calculation and display.
- [ ] 5.6 Add label‑based cost aggregation selector (aggregate by app, team, environment).
- [ ] 5.7 Create historical cost trend chart for individual deployments.
- [ ] 5.8 Implement CSV export for deployment cost data.
- [ ] 5.9 Implement PDF export with formatted cost report.
- [ ] 5.10 Create API endpoints for deployment/pod cost data.

#### 6. Waste Identification Engine

- [ ] 6.1 Implement idle pod detection algorithm (CPU < 5%, memory < 10% for 24h).
- [ ] 6.2 Implement idle LoadBalancer detection (zero connections for 24h).
- [ ] 6.3 Implement orphaned PVC detection (no pod volume reference for 7 days).
- [ ] 6.4 Implement over‑provisioning detection (requests > 3x p95 usage over 7 days).
- [ ] 6.5 Create waste calculation engine with cloud provider pricing.
- [ ] 6.6 Implement savings estimation for each waste category.
- [ ] 6.7 Create `waste.html.j2` template showing all waste items with action buttons.
- [ ] 6.8 Add waste type filter (Idle, Over‑Provisioned, Orphaned).
- [ ] 6.9 Implement waste trend chart showing waste reduction over time.
- [ ] 6.10 Add “Ignore” action to dismiss waste recommendations.

#### 7. Right‑Sizing Recommendations Engine

- [ ] 7.1 Implement p50/p95 calculation from historical usage data.
- [ ] 7.2 Create recommendation engine that generates CPU/memory requests/limits.
- [ ] 7.3 Implement confidence score calculation (based on data age, variance, stability).
- [ ] 7.4 Create potential savings calculation with pricing integration.
- [ ] 7.5 Implement impact analysis (performance risk, affected pods count).
- [ ] 7.6 Create `recommendations.html.j2` template with sortable recommendation table.
- [ ] 7.7 Add recommendation detail view with before/after comparison.
- [ ] 7.8 Implement “Apply” action that opens resource editor with pre‑filled values.
- [ ] 7.9 Implement “Dismiss” action with reason selection.
- [ ] 7.10 Add bulk selection and bulk actions (Apply Selected, Dismiss Selected).
- [ ] 7.11 Create API endpoint for recommendations with filtering.

#### 8. REST API Endpoints

- [ ] 8.1 Implement `GET /api/v1/plugins/cost-optimization/cluster-summary` endpoint.
- [ ] 8.2 Implement `GET /api/v1/plugins/cost-optimization/namespaces` endpoint.
- [ ] 8.3 Implement `GET /api/v1/plugins/cost-optimization/deployments?namespace=` endpoint.
- [ ] 8.4 Implement `GET /api/v1/plugins/cost-optimization/deployments/<name>` endpoint.
- [ ] 8.5 Implement `GET /api/v1/plugins/cost-optimization/pods/<namespace>/<name>` endpoint.
- [ ] 8.6 Implement `GET /api/v1/plugins/cost-optimization/waste` endpoint.
- [ ] 8.7 Implement `GET /api/v1/plugins/cost-optimization/recommendations` endpoint.
- [ ] 8.8 Implement `POST /api/v1/plugins/cost-optimization/recommendations/<id>/apply` endpoint.
- [ ] 8.9 Implement `POST /api/v1/plugins/cost-optimization/recommendations/<id>/dismiss` endpoint.
- [ ] 8.10 Add Admin role check for all endpoints (configurable for User role access).
- [ ] 8.11 Add OpenAPI/Swagger documentation for all endpoints.

#### 9. RBAC and Security

- [ ] 9.1 Implement Admin role requirement for all cost data endpoints by default.
- [ ] 9.2 Implement configurable `viewable_by_users` setting for User role access.
- [ ] 9.3 Add audit logging for all cost data queries (user, timestamp, endpoint).
- [ ] 9.4 Implement API key authentication for Kubecost Enterprise.
- [ ] 9.5 Add CSRF protection for all form submissions.
- [ ] 9.6 Implement rate limiting for API endpoints (60 requests/minute per user).

#### 10. Pricing Model Integration

- [ ] 10.1 Implement cloud provider pricing lookup (AWS, GCP, Azure rates).
- [ ] 10.2 Create pricing cache to avoid repeated lookups.
- [ ] 10.3 Implement custom pricing override capability (for enterprise discounts).
- [ ] 10.4 Add pricing source display in tooltips (show calculation details).
- [ ] 10.5 Handle currency conversion if multi‑cloud with different currencies.

#### 11. Testing

- [ ] 11.1 Write unit tests for OpenCost API client with mocked responses.
- [ ] 11.2 Write integration tests for API endpoints with mocked cost backend.
- [ ] 11.3 Write functional tests for UI routes and template rendering.
- [ ] 11.4 Write RBAC tests verifying Admin/User role permissions.
- [ ] 11.5 Create E2E test scenario: view dashboard, filter by namespace, export data.
- [ ] 11.6 Create E2E test scenario: view waste, dismiss recommendation, view recommendations.
- [ ] 11.7 Test against OpenCost 1.100+ in development cluster.
- [ ] 11.8 Test against Kubecost Enterprise (if available).
- [ ] 11.9 Performance test with 1000+ pods and 90 days of historical data.
- [ ] 11.10 Load test API endpoints with concurrent users.

#### 12. Documentation

- [ ] 12.1 Write user guide: viewing costs, understanding recommendations, acting on waste.
- [ ] 12.2 Write admin guide: plugin configuration, OpenCost installation, RBAC setup.
- [ ] 12.3 Create OpenCost installation guide (Helm chart, configuration).
- [ ] 12.4 Add troubleshooting section (API unavailable, data discrepancies, pricing issues).
- [ ] 12.5 Update Helm chart README with cost optimization plugin toggle documentation.
- [ ] 12.6 Create screenshot gallery for documentation.
- [ ] 12.7 Add FAQ: “Why don't costs match my cloud bill?”, “How accurate are recommendations?”.

#### 13. Deployment and Release

- [ ] 13.1 Add plugin enable/disable toggle to Helm chart `values.yaml`.
- [ ] 13.2 Add OpenCost as optional Helm chart dependency (commented out by default).
- [ ] 13.3 Update Helm chart README with cost plugin documentation.
- [ ] 13.4 Test plugin installation on fresh KubeDash deployment.
- [ ] 13.5 Test plugin upgrade from disabled to enabled state.
- [ ] 13.6 Create release notes for v4.3.0 with cost optimization feature.
- [ ] 13.7 Record demo video for release announcement.
- [ ] 13.8 Create blog post “Reduce Kubernetes Costs by 40% with KubeDash Cost Optimization”.

