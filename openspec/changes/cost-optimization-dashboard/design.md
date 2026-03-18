## Context

KubeDash already has cluster metrics infrastructure (CPU/memory usage, requests, limits) via metrics-server integration and a metrics scraper that runs every 300 seconds. The existing metrics system uses SQLAlchemy models (`Nodes`, `Pods` tables) for historical data and Chart.js for visualization. OpenCost (CNCF project since 2023) provides a standardized cost API that has become the de facto standard for Kubernetes cost intelligence, with Kubecost offering a commercial distribution with additional features. Both expose REST APIs with similar structures for cost allocation, efficiency, and recommendations. The target user base includes platform engineers, FinOps practitioners, and development teams needing cost visibility for decision-making.

**Current State:**
- Cluster metrics show CPU/memory usage but no cost data
- Resource allocation visible but no efficiency scoring
- No waste identification or optimization recommendations
- Existing Chart.js integration for visualizations
- Plugin architecture proven with Flux, Trivy, Cert-Manager plugins

**Constraints:**
- Must support both OpenCost (open-source) and Kubecost (commercial) APIs
- Cost data is sensitive - requires appropriate RBAC (Admin role only)
- API calls to cost backend must be cached to avoid performance impact
- Plugin must be optional (enabled via kubedash.ini configuration)
- No breaking changes to existing metrics or dashboards

**Stakeholders:**
- Platform engineers managing cloud budgets
- FinOps teams requiring cost allocation reports
- Development teams optimizing workload costs
- Finance/leadership needing spend visibility

## Goals / Non-Goals

**Goals:**
- Provide cluster-wide cost dashboard with daily/monthly spend and trends
- Enable cost attribution by namespace, deployment, pod, and container
- Identify waste (idle resources, over-provisioning) with savings estimates
- Generate right-sizing recommendations based on actual usage patterns
- Support both OpenCost and Kubecost APIs with feature detection
- Integrate with existing KubeDash authentication and RBAC

**Non-Goals:**
- Cost backend installation (assume OpenCost/Kubecost pre-installed)
- Multi-cluster cost aggregation (single-cluster scope for v1)
- Custom pricing model configuration (use cost backend defaults)
- Cost forecasting or budget alerts (future enhancement)
- Write operations (read-only cost visibility)
- Cloud provider billing integration (AWS Cost Explorer, etc.)

## Decisions

### 1. Cost API Integration Strategy

**Decision:** Support both OpenCost and Kubecost via unified API client with feature detection. Use OpenCost Allocation API as baseline, detect Kubecost-specific endpoints for recommendations.

**Rationale:** OpenCost is CNCF standard (vendor-neutral), Kubecost has richer features (recommendations). Unified client reduces code duplication, feature detection enables graceful degradation.

**Alternative:** Choose one provider exclusively - rejected because users may have either, and APIs are 90% compatible.

### 2. Caching Strategy for Cost Data

**Decision:** Implement two-tier caching: in-memory cache (60s TTL) for recent cost queries, Redis cache (5min TTL) for aggregated data (daily totals, efficiency scores). Cache keys include namespace and time range parameters.

**Rationale:** Cost data doesn't change frequently, API calls are expensive (aggregate large datasets), two-tier balances performance vs freshness. Matches existing KubeDash caching patterns.

**Alternative:** No caching, direct API calls - rejected because cost queries are slow (5-10s) and would degrade UX.

### 3. Cost Visualization Components

**Decision:** Reuse existing Chart.js integration for all charts: line charts for cost trends, bar charts for cost by namespace, donut charts for cost distribution, gauge charts for efficiency scores. Use DataTables for cost breakdown tables.

**Rationale:** Consistent with existing KubeDash visualizations, no new frontend dependencies, team expertise with Chart.js, responsive and accessible.

**Alternative:** D3.js or custom visualizations - rejected because Chart.js is sufficient and already integrated.

### 4. RBAC for Cost Data

**Decision:** Restrict cost data visibility to Admin role only by default. Configurable `viewable_by_users` setting allows User role access (read-only) for organizations with different policies.

**Rationale:** Cost data is sensitive (budget information, team spend), Admin-only follows least-privilege principle, configurable for flexibility.

**Alternative:** Show cost data to all authenticated users - rejected because cost visibility often restricted to managers/leads.

### 5. Waste Identification Algorithm

**Decision:** Use OpenCost efficiency metrics where available. For generic detection: idle pods (CPU < 5% for 24h), over-provisioned (requests > 3x actual p95 usage), orphaned LoadBalancers/PVCs (no active connections/bound pods).

**Rationale:** Combines standardized metrics with heuristic detection, provides actionable insights even without advanced cost backend features.

**Alternative:** Rely solely on cost backend recommendations - rejected because not all installations have this feature.

### 6. Right-Sizing Recommendation Calculation

**Decision:** Calculate recommendations using percentile-based approach: recommend requests at p50 usage, limits at p95 usage. Show potential savings as `(current_request - recommended) * price_per_unit`. Require 7 days of historical data for recommendations.

**Rationale:** P50/P95 balances performance headroom with efficiency, matches industry best practices (Google Kubernetes Engine recommendations use similar approach), provides clear savings estimate.

**Alternative:** Use average usage - rejected because average doesn't account for spikes, could cause OOM issues.

### 7. Time Range Handling

**Decision:** Support standard time ranges: 24h, 7d, 30d, 90d. Default to 7d for dashboard. All cost data queries include start/end timestamps in ISO 8601 format. Historical trend data aggregated daily for 30d+, hourly for 24h.

**Rationale:** Matches OpenCost API conventions, provides meaningful granularity (hourly for recent, daily for historical), consistent with existing KubeDash time range selectors.

**Alternative:** Custom date range picker - rejected because adds complexity, standard ranges cover 95% of use cases.

### 8. Error Handling for Cost Backend Unavailable

**Decision:** Graceful degradation: if cost backend unreachable, show friendly message "Cost data unavailable - ensure OpenCost/Kubecost is installed and accessible" with setup documentation link. Do not show partial data or fallback to estimates.

**Rationale:** Clear communication prevents confusion, avoids misleading estimates, encourages proper setup.

**Alternative:** Show cached data regardless of age - rejected because stale cost data could lead to bad decisions.

## Risks / Trade-offs

### [Cost Backend API Performance]
OpenCost queries can take 10-30s for large clusters (1000+ pods). **Mitigation:** Implement aggressive caching, show loading indicators, use background refresh for dashboard data, paginate large result sets.

### [Data Accuracy vs Cloud Bills]
Cost allocations may not match cloud provider bills exactly (different pricing models, reserved instances, spot discounts). **Mitigation:** Show disclaimer "Estimates based on on-demand pricing, actual costs may vary", link to cloud provider billing for reconciliation.

### [Sensitive Data Exposure]
Cost data reveals team priorities, project budgets, potentially sensitive business information. **Mitigation:** Admin-only by default, audit all cost queries, no export functionality in v1, configurable RBAC.

### [Multi-Cloud Pricing Complexity]
Different cloud providers have different pricing for compute/memory/storage. **Mitigation:** Rely on cost backend for pricing (OpenCost maintains provider-specific rates), don't implement pricing logic in KubeDash.

### [OpenCost Installation Requirement]
Users must install OpenCost/Kubecost separately (not part of KubeDash Helm chart). **Mitigation:** Provide installation guide, Helm chart dependency (optional), clear error messages when backend missing.

## Migration Plan

### Phase 1: Plugin Infrastructure (Week 1-2)
1. Create plugin directory structure following existing patterns
2. Implement OpenCost/Kubecost API client with authentication
3. Build basic cost dashboard with total spend and namespace breakdown
4. Test against OpenCost 1.100+ in development cluster

### Phase 2: Workload Cost Attribution (Week 3-4)
1. Implement per-deployment and per-pod cost breakdown
2. Add container-level cost allocation
3. Build historical cost trend charts
4. Performance optimization with caching

### Phase 3: Waste Identification (Week 5-6)
1. Implement idle resource detection algorithms
2. Build over-provisioning detection with usage percentiles
3. Create savings estimation calculations
4. Add waste dashboard with actionable recommendations

### Phase 4: Right-Sizing Recommendations (Week 7-8)
1. Implement p50/p95-based recommendation engine
2. Build recommendation UI with apply actions
3. Add potential savings calculator
4. User testing and documentation

### Phase 5: Polish & Release (Week 9-10)
1. Integration testing with Kubecost Enterprise
2. Documentation (user guide + admin setup)
3. Helm chart plugin toggle
4. Release in v4.3.0

**Rollback Strategy:**
- Plugin is isolated - disable via `cost_optimization = false` in kubedash.ini
- No database migrations required
- No changes to cluster state or cost backend
- Revert: Remove plugin directory, restart KubeDash

## Open Questions

1. **Kubecost Enterprise features:** Should we support Kubecost-specific features (forecasting, budgets, anomalies) or stick to OpenCost-compatible API only? Impacts commercial vs open-source user experience.

2. **Custom pricing models:** Allow users to override cloud provider pricing (e.g., for reserved instances, enterprise discounts)? Adds complexity but improves accuracy.

3. **Export functionality:** Should v1 include CSV/PDF export for cost reports, or defer to v2? Finance teams often require exports for month-end reporting.

4. **Real-time updates:** Use existing SocketIO for cost data refresh notifications, or rely on manual refresh? Real-time adds complexity but improves monitoring experience.

5. **Multi-cluster roadmap:** Future requirement for aggregated cost view across multiple clusters. Should we design aggregation APIs now or defer to avoid rework?
