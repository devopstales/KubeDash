## Why

Kubernetes policy-as-Code is critical for enterprise governance, security compliance, and operational best practices. Kyverno is a CNCF-graduated policy engine specifically designed for Kubernetes, with widespread adoption for validation, mutation, and generation policies. KubeDash currently lacks policy management capabilities - users cannot view, create, or manage Kyverno policies from the dashboard, forcing them to switch between kubectl and the UI. This change adds a comprehensive Kyverno plugin to close this gap and complete KubeDash's governance story alongside Trivy Operator (security scanning) and Flux (GitOps).

## What Changes

- **Kyverno Plugin**: New plugin providing visualization and management of Kyverno policy resources including ClusterPolicies, Policies, PolicyExceptions, and PolicyReports
- **Policy Dashboard**: Centralized view showing policy compliance status across the cluster with violation reports and trends
- **Policy Detail Views**: Deep-dive into individual policies with rules, conditions, and affected resources
- **Policy Reports UI**: Visualization of PolicyReport and ClusterPolicyReport CRDs showing pass/fail/warn/skip counts
- **Policy Application Flow**: UI wizard to create and apply new policies from templates or YAML
- **REST API Endpoints**: API endpoints for policy CRUD operations and compliance queries
- **No breaking changes**: Existing functionality remains unchanged; plugin is opt-in via configuration

## Capabilities

### New Capabilities

- `kyverno-plugin`: Core plugin infrastructure with blueprint, API routes, templates, and K8s client wrappers for Kyverno CRDs (ClusterPolicy, Policy, PolicyException, ClusterPolicyReport, PolicyReport)
- `policy-compliance-dashboard`: Cluster-wide compliance visualization showing policy violations by namespace, severity trends, top violated resources, and compliance score over time
- `policy-management`: Policy CRUD operations including create from template, edit YAML, clone policy, suspend/resume enforcement, and delete with confirmation
- `policy-reports-ui`: PolicyReport and ClusterPolicyReport visualization with resource-level drill-down, historical trends, and export capabilities
- `policy-exceptions`: PolicyException management to view, create, and audit policy exemptions with justification tracking

### Modified Capabilities

- None (this is a new plugin; no existing capability requirements are changing)

## Impact

- **Affected code**: New `plugins/kyverno/` directory with Python plugin code, Go kdlogin changes not required, no changes to core KubeDash blueprints
- **APIs**: New REST endpoints under `/api/v1/plugins/kyverno/` for policy CRUD, compliance data, and policy reports; new UI routes under `/plugins/kyverno/`
- **Dependencies**: Kyverno CRDs must be installed in target clusters (ClusterPolicy, Policy, PolicyException, PolicyReport, ClusterPolicyReport); Python kubernetes client already supports CRDs via CustomObjectsApi
- **Security**: Policy write operations require Admin role; read-only mode configurable for User role; all policy changes logged to audit trail
- **Configuration**: Plugin enabled/disabled via `[plugin_settings]` section in `kubedash.ini`; optional Kyverno API server integration for advanced features
