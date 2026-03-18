## Context

KubeDash has a mature plugin architecture demonstrated by the Flux plugin (GitOps), Trivy Operator (security scanning), and Cert-Manager plugins. These plugins follow a consistent pattern: Python Flask blueprint for UI routes, optional API blueprint for REST endpoints, K8s client wrapper functions, and Jinja2 templates using CoreUI components. Kyverno is a CNCF-graduated policy engine with ~70% market share in Kubernetes policy management. The target clusters already have Kyverno installed (common in enterprise), exposing CRDs via the standard Kubernetes API server. No separate Kyverno API server integration is required for basic functionality.

**Current State:**
- Network policies exist in Security section (K8s native NetworkPolicy only)
- No admission policy management (Kyverno, OPA Gatekeeper, JS Policy)
- Trivy Operator shows vulnerability/misconfiguration scan results but not policy definitions
- Plugin system supports discovery-based registration with optional API blueprints

**Constraints:**
- Must work with Kyverno CRDs via Kubernetes API server (CustomObjectsApi)
- Follow existing plugin conventions (Flux plugin as reference)
- Support both Admin (read-write) and User (read-only) roles
- Plugin must be optional (enabled via kubedash.ini configuration)
- No breaking changes to existing security/policy views

**Stakeholders:**
- Platform engineers managing cluster governance
- Security teams requiring compliance visibility
- Developers needing policy feedback during deployment
- Auditors requiring policy exception tracking

## Goals / Non-Goals

**Goals:**
- Provide comprehensive Kyverno resource visualization (ClusterPolicy, Policy, PolicyException, PolicyReport, ClusterPolicyReport)
- Enable policy CRUD operations with template library and YAML editor
- Show cluster-wide compliance dashboard with violation trends and hotspots
- Integrate with existing audit logging for policy changes
- Maintain plugin architecture consistency with Flux/Cert-Manager patterns
- Support multi-namespace views and filtering

**Non-Goals:**
- Kyverno installation/management (assume pre-installed)
- Policy testing/simulation engine (future enhancement)
- OPA Gatekeeper or other policy engine support (Kyverno-only for v1)
- Real-time policy violation webhooks (use periodic refresh)
- Policy recommendation engine (future enhancement)
- Cross-cluster policy synchronization (single-cluster scope)

## Decisions

### 1. Plugin Architecture Pattern

**Decision:** Follow Flux plugin architecture exactly - Flask blueprint at `/plugins/kyverno`, API blueprint at `/api/v1/plugins/kyverno/`, K8s client wrappers in `plugins/kyverno/k8s_client.py`.

**Rationale:** Proven pattern, reduces cognitive load for maintainers, consistent UX with other plugins, reuses existing plugin registration infrastructure.

**Alternative:** Create separate microservice for policy management - rejected due to operational complexity and unnecessary coupling.

### 2. Kyverno CRD Access Strategy

**Decision:** Use Kubernetes CustomObjectsApi exclusively (no Kyverno API server dependency).

**Rationale:** All Kyverno CRDs are accessible via standard K8s API, existing kubernetes-python client supports CRDs, reduces external dependencies, works with existing authentication/authorization.

**Alternative:** Integrate Kyverno REST API directly - rejected because it requires additional network configuration, authentication setup, and provides minimal benefit over CustomObjectsApi for read operations.

### 3. Policy Editor Implementation

**Decision:** Dual-mode editor - visual form builder for simple policies + Monaco YAML editor for advanced users (same editor as existing KubeDash YAML views).

**Rationale:** Visual builder lowers barrier for common policies, Monaco editor supports complex policies with full YAML syntax highlighting/validation, follows existing KubeDash patterns.

**Alternative:** YAML-only editor - rejected because visual builder significantly improves UX for common use cases (require/forbid patterns).

### 4. Compliance Dashboard Metrics

**Decision:** Show compliance score (pass/(pass+fail)*100), violations by namespace (bar chart), violations by category (pie chart), trend over time (line chart with 7d/30d views).

**Rationale:** Matches industry-standard compliance dashboards (OpenPolicyAgent, Kyverno dashboard), provides actionable insights, leverages existing Chart.js integration.

**Alternative:** Raw violation list only - rejected because trends and aggregations provide better operational visibility.

### 5. Policy Exception Audit Trail

**Decision:** Log all PolicyException creations/modifications to KubeDash audit log with justification text, approver (from session), and affected policy reference.

**Rationale:** Compliance requirement for policy exceptions, integrates with existing audit infrastructure, provides accountability without external systems.

**Alternative:** Store exceptions in separate database table - rejected because audit log already provides immutable trail and search capabilities.

### 6. Read-Only Mode for User Role

**Decision:** User role sees all policy resources but cannot create/edit/delete; Admin role has full CRUD. Configurable via `read_only_for_users` plugin setting.

**Rationale:** Least-privilege principle, matches existing KubeDash RBAC patterns, prevents accidental policy changes while maintaining visibility.

**Alternative:** Hide policies from User role entirely - rejected because developers need policy visibility for debugging.

### 7. Template Library Strategy

**Decision:** Include 10-15 built-in policy templates (require-labels, forbid-privileged-containers, require-resource-limits, etc.) loaded from JSON files in plugin directory.

**Rationale:** Accelerates policy adoption, provides best-practice examples, reduces YAML writing errors, similar to Flux template approach.

**Alternative:** Fetch templates from Kyverno GitHub repo - rejected because offline clusters need local templates and we want curated set.

### 8. Policy Report Aggregation

**Decision:** Aggregate PolicyReport results by namespace, resource kind, and policy; show pass/fail/warn/skip counts; drill-down to individual resource violations.

**Rationale:** PolicyReports are the standard output of Kyverno enforcement/audit, provides actionable remediation targets, matches Kyverno CLI output structure.

**Alternative:** Show only policy-level summary - rejected because users need to know which specific resources violate policies.

## Risks / Trade-offs

### [CRD Version Compatibility]
Kyverno CRDs evolve between versions (v1 vs v2beta1). **Mitigation:** Detect CRD version at runtime, use appropriate API version, test against Kyverno 1.10+ (current LTS).

### [Performance with Large Clusters]
PolicyReport aggregation across 1000s of resources could be slow. **Mitigation:** Implement server-side pagination, cache aggregated results for 60s, use background refresh for detail views.

### [Policy Complexity]
Kyverno policies can be extremely complex (JMESPath expressions, variables). **Mitigation:** Visual builder handles common patterns only, complex policies require YAML mode, provide validation before apply.

### [Namespace Filtering]
ClusterPolicies apply cluster-wide but reports are namespaced. **Mitigation:** Show ClusterPolicy violations aggregated by namespace, provide "all namespaces" filter option.

### [User Confusion: Network vs Admission Policies]
Users may confuse K8s NetworkPolicy with Kyverno admission policies. **Mitigation:** Clear UI separation, "Admission Policies" naming, help text explaining difference.

## Migration Plan

### Phase 1: Plugin Installation (Week 1-2)
1. Create plugin directory structure following Flux pattern
2. Implement K8s client wrappers for Kyverno CRDs
3. Build basic list/detail views for ClusterPolicy and Policy
4. Test against Kyverno 1.10+ in development cluster

### Phase 2: Dashboard & Reports (Week 3-4)
1. Implement compliance dashboard with charts
2. Build PolicyReport aggregation and drill-down
3. Add namespace filtering and search
4. Performance optimization for large clusters

### Phase 3: CRUD Operations (Week 5-6)
1. Build policy editor (visual + YAML modes)
2. Implement template library
3. Add create/edit/delete with confirmation
4. Audit logging integration

### Phase 4: Polish & Release (Week 7-8)
1. User testing with platform team
2. Documentation (user guide + admin setup)
3. Helm chart plugin toggle
4. Release in v4.2.0

**Rollback Strategy:**
- Plugin is isolated - disable via `kyverno = false` in kubedash.ini
- No database migrations required
- No changes to existing policies or cluster state
- Revert: Remove plugin directory, restart KubeDash

## Open Questions

1. **Kyverno version support minimum:** Should we support Kyverno 1.9 (older LTS) or require 1.10+? Impacts CRD API versions used.

2. **Template count:** How many built-in templates to include? 10-15 seems reasonable but may overwhelm. Should we categorize (security, operations, governance)?

3. **Real-time updates:** Use existing SocketIO infrastructure for policy violation notifications, or rely on manual refresh? Adds complexity but improves UX.

4. **Policy validation:** Integrate `kyverno-cli` validation server-side before apply, or rely on K8s API validation? CLI provides better error messages but requires binary installation.

5. **Multi-cluster:** Future requirement for policy dashboards across multiple clusters from single KubeDash instance. Should we design aggregation APIs now or defer?
