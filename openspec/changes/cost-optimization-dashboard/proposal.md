## Why

Cloud cost optimization is a top priority for Kubernetes teams, with 78% of organizations citing cost management as their #1 cloud challenge (Flexera 2025 State of the Cloud Report). KubeDash currently provides resource metrics (CPU/memory) but lacks cost visibility - users cannot see how much their workloads cost, identify waste, or get optimization recommendations. This change integrates OpenCost (CNCF project) and Kubecost APIs to provide comprehensive cost intelligence directly in the dashboard, enabling FinOps practices and reducing cloud spend by 20-40% through actionable insights.

## What Changes

- **Cost Optimization Plugin**: New plugin providing cost dashboards, workload cost breakdowns, and efficiency metrics integrated with OpenCost/Kubecost APIs
- **Cost Dashboard**: Cluster-wide cost view showing daily/monthly spend, cost by namespace, cost trends, and efficiency scores
- **Workload Cost Attribution**: Per-deployment, per-pod, and per-container cost breakdown with CPU/memory/storage cost allocation
- **Waste Identification**: Automated detection of idle resources, over-provisioned workloads, and optimization opportunities with estimated savings
- **Right-Sizing Recommendations**: Data-driven recommendations for resource requests/limits based on actual usage patterns
- **REST API Endpoints**: API endpoints for cost queries, efficiency metrics, and recommendations
- **No breaking changes**: Existing functionality remains unchanged; plugin is opt-in via configuration

## Capabilities

### New Capabilities

- `cost-optimization-plugin`: Core plugin infrastructure with Flask blueprint, API routes, templates, and OpenCost/Kubecost API client wrappers for cost and efficiency data
- `cost-dashboard`: Cluster-wide cost visualization showing total spend, cost by namespace, cost trends over time, and efficiency scores with filtering by time range and namespace
- `workload-cost-attribution`: Per-resource cost breakdown for deployments, pods, and containers with CPU/memory/storage cost allocation and historical cost tracking
- `waste-identification`: Automated detection of idle resources (zero-traffic pods, underutilized nodes), over-provisioned workloads, and orphaned resources with estimated monthly savings
- `right-sizing-recommendations`: Data-driven recommendations for resource requests/limits based on actual usage percentiles (p50/p90/p95) with potential savings calculation

### Modified Capabilities

- None (this is a new plugin; no existing capability requirements are changing)

## Impact

- **Affected code**: New `plugins/cost_optimization/` directory with Python plugin code, no changes to core KubeDash blueprints or existing plugins
- **APIs**: New REST endpoints under `/api/v1/plugins/cost-optimization/` for cost queries, efficiency data, and recommendations; new UI routes under `/plugins/cost-optimization/`
- **Dependencies**: OpenCost or Kubecost installation required in target clusters (CNCF project with standard API); Python `requests` library for API calls (already available)
- **Security**: Read-only access to cost data (no write operations); API key configuration for Kubecost Enterprise (optional); all cost queries logged to audit trail
- **Configuration**: Plugin enabled/disabled via `[plugin_settings]` section in `kubedash.ini`; OpenCost/Kubecost API endpoint and authentication configured in `[cost_optimization]` section
