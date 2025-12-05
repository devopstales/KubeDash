# Custom Resource Definitions

KubeDash provides a browser for Custom Resource Definitions (CRDs) and their instances, allowing you to explore any custom resources installed in your cluster.

## What are CRDs?

Custom Resource Definitions extend Kubernetes with custom resources. Common examples include:

- **Cert-Manager**: Certificates, Issuers, ClusterIssuers
- **Prometheus**: ServiceMonitors, PrometheusRules
- **Istio**: VirtualServices, DestinationRules
- **ArgoCD**: Applications, AppProjects
- **Flux**: GitRepositories, Kustomizations

## Viewing CRDs

Navigate to `Cluster > Custom Resource Definitions` to see all CRDs in the cluster:

![CRD List](../img/cluster/crd-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Full CRD name (e.g., certificates.cert-manager.io) |
| Group | API group (e.g., cert-manager.io) |
| Kind | Resource kind (e.g., Certificate) |
| Version | API version(s) (e.g., v1) |
| Scope | Namespaced or Cluster |
| Age | Time since CRD was created |

## CRD Details

Click on a CRD to view its instances and details:

### CRD Metadata

- **Group**: API group the resource belongs to
- **Kind**: Resource type name
- **Plural**: Plural name for API paths
- **Scope**: Namespaced or Cluster-scoped
- **Versions**: Available API versions

### Custom Resource Instances

When you select a CRD, KubeDash displays all instances:

| Column | Description |
|--------|-------------|
| Name | Resource name |
| Namespace | Namespace (if namespaced) |
| Age | Time since creation |
| Status | Resource-specific status |

### Instance Details

Click on an instance to view:

- **Metadata**: Name, namespace, labels, annotations
- **Spec**: Resource specification
- **Status**: Current status (if applicable)

## Common CRD Examples

### Cert-Manager CRDs

| CRD | Description |
|-----|-------------|
| `certificates.cert-manager.io` | TLS certificates |
| `issuers.cert-manager.io` | Namespace certificate issuers |
| `clusterissuers.cert-manager.io` | Cluster-wide issuers |
| `certificaterequests.cert-manager.io` | Certificate requests |

### Prometheus Operator CRDs

| CRD | Description |
|-----|-------------|
| `servicemonitors.monitoring.coreos.com` | Service scrape configs |
| `prometheusrules.monitoring.coreos.com` | Alerting rules |
| `podmonitors.monitoring.coreos.com` | Pod scrape configs |
| `alertmanagerconfigs.monitoring.coreos.com` | AlertManager configs |

### Istio CRDs

| CRD | Description |
|-----|-------------|
| `virtualservices.networking.istio.io` | Traffic routing |
| `destinationrules.networking.istio.io` | Traffic policies |
| `gateways.networking.istio.io` | Ingress gateways |
| `serviceentries.networking.istio.io` | External services |

### Flux CRDs

| CRD | Description |
|-----|-------------|
| `gitrepositories.source.toolkit.fluxcd.io` | Git sources |
| `kustomizations.kustomize.toolkit.fluxcd.io` | Kustomize deployments |
| `helmreleases.helm.toolkit.fluxcd.io` | Helm deployments |
| `helmrepositories.source.toolkit.fluxcd.io` | Helm repositories |

## Filtering CRDs

### By API Group

CRDs are organized by API group. Common groups include:

| Group | Description |
|-------|-------------|
| `cert-manager.io` | Cert-Manager resources |
| `monitoring.coreos.com` | Prometheus Operator |
| `networking.istio.io` | Istio networking |
| `argoproj.io` | Argo CD/Workflows |
| `kustomize.toolkit.fluxcd.io` | Flux Kustomize |

### By Scope

- **Namespaced**: Resources exist within a namespace
- **Cluster**: Resources are cluster-wide

## Working with Custom Resources

### Namespaced Resources

For namespaced CRDs:

1. Select the CRD from the list
2. Choose a namespace from the dropdown
3. View instances in that namespace

### Cluster Resources

For cluster-scoped CRDs:

1. Select the CRD from the list
2. All instances are shown (no namespace filter)

## Best Practices

### CRD Discovery

- Use the CRD browser to discover what's installed
- Check CRD versions for compatibility
- Review CRD scope before creating resources

### Resource Management

- Use appropriate namespaces for namespaced CRDs
- Follow naming conventions
- Apply labels for organization

### Version Compatibility

- Check which versions are served
- Use the storage version when creating resources
- Plan for CRD upgrades

## Troubleshooting

### CRD Not Appearing

1. Verify CRD is installed: `kubectl get crd <name>`
2. Check for API registration issues
3. Verify RBAC permissions

### Resources Not Showing

1. Check namespace selection (for namespaced CRDs)
2. Verify resources exist: `kubectl get <kind>`
3. Check RBAC permissions for listing

### Permission Issues

Required permissions to view CRDs:

```yaml
rules:
  - apiGroups: ["apiextensions.k8s.io"]
    resources: ["customresourcedefinitions"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["<crd-group>"]
    resources: ["<crd-plural>"]
    verbs: ["get", "list", "watch"]
```

## Dedicated Plugins

KubeDash includes dedicated plugins for common CRDs with enhanced visualization:

- **[Cert-Manager](../integrations/cert-manager.md)**: Certificate status, issuer health
- **[Helm](../integrations/helm.md)**: Release history, chart details
- **[External LoadBalancer](../integrations/external-load-balancer.md)**: MetalLB, Cilium LB

These plugins provide specialized views beyond the generic CRD browser.
