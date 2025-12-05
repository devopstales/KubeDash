# Features

KubeDash provides comprehensive Kubernetes cluster management capabilities through an intuitive web interface.

## Dashboard & Monitoring

* **Cluster Metrics Dashboard** - Real-time CPU and memory utilization across the cluster
* **Cluster Events** - View and monitor Kubernetes events
* **Resource Map** - Visual representation of resources and their connections in a namespace
* **Node Metrics** - Individual node resource usage and health

## Workload Management

* **Pods**
    - List pods across namespaces
    - View pod details, containers, volumes
    - Delete pods
    - Real-time log streaming
    - Interactive terminal access (exec)
* **Deployments**
    - List and view deployments
    - Scale replica counts
    - View rollout status
* **StatefulSets**
    - List and view StatefulSets
    - Scale replica counts
    - View volume claim templates
* **DaemonSets**
    - List and view DaemonSets
    - Scale up/down operations
* **ReplicaSets**
    - List and view ReplicaSets

## Cluster Resources

* **Namespaces**
    - Create and delete namespaces
    - Scale all workloads in a namespace up/down
    - View namespace metadata and annotations
* **Nodes**
    - List and view node details
    - View node conditions and taints
    - Monitor node resource metrics
* **Custom Resource Definitions**
    - Browse all installed CRDs
    - View CRD instances
    - Support for any custom resource

## Network Resources

* **Services**
    - List services by namespace
    - View service details and endpoints
    - See pod selectors and matching pods
* **Ingresses**
    - List ingresses by namespace
    - View routing rules and backends
    - TLS configuration visibility
* **Ingress Classes**
    - List available ingress classes
    - View controller information

## Storage Resources

* **Storage Classes**
    - List available storage classes
    - View provisioner and parameters
* **Persistent Volumes**
    - List cluster-wide PVs
    - View capacity and access modes
* **Persistent Volume Claims**
    - List PVCs by namespace
    - View bound volumes and usage metrics
* **ConfigMaps**
    - List ConfigMaps by namespace
    - View key-value data
* **Volume Snapshots**
    - List volume snapshots
* **Snapshot Classes**
    - List snapshot classes

## Security Resources

* **Secrets**
    - List secrets by namespace
    - View secret types and metadata
* **Network Policies**
    - List network policies by namespace
    - View ingress/egress rules
* **Priority Classes**
    - List priority classes
    - View scheduling priorities

## Autoscaling & Resource Management

* **Horizontal Pod Autoscaler (HPA)**
    - List HPAs by namespace
    - View scaling metrics and targets
* **Vertical Pod Autoscaler (VPA)**
    - List VPAs by namespace
    - View resource recommendations
* **Pod Disruption Budgets**
    - List PDBs by namespace
    - View availability requirements
* **Resource Quotas**
    - List quotas by namespace
    - View usage vs limits
* **Limit Ranges**
    - List limit ranges by namespace
    - View default and max limits

## Cluster Permissions (RBAC)

* **Service Accounts**
    - List service accounts by namespace
* **Roles & Role Bindings**
    - List roles and bindings by namespace
    - View role permissions
* **Cluster Roles & Cluster Role Bindings**
    - List cluster-wide roles and bindings
    - View permissions and subjects

## User Management

* **User Types**
    - Local users (database)
    - Kubernetes users (certificate-based)
    - OpenID/SSO users
* **Dashboard Roles**
    - Admin role (full dashboard access)
    - User role (limited dashboard access)
* **Role Templates**
    - Predefined Kubernetes role templates
    - Easy RBAC assignment via UI
* **Group Management**
    - SSO group synchronization
    - Group-based RBAC mapping

## Authentication

* Local username/password authentication
* OIDC/OAuth2 single sign-on
* Automatic SSO group synchronization
* Password reset via CLI

## Kubectl Configuration

* SSO-based kubectl config (OIDC tokens)
* Certificate-based kubectl config (for local users)
* kubectl plugin for easy config download
* Automatic config generation

## Plugins

* **Docker Registry UI**
    - Browse multiple registries
    - View images and tags
    - Tag management
    - SBOM visualization
    - Registry events
* **Helm Dashboard**
    - View installed Helm releases
    - Release history
    - Chart information
* **Cert-Manager**
    - Certificate status
    - Issuer health
    - Certificate requests
* **External LoadBalancer**
    - MetalLB support
    - Cilium LB support
    - IP pool management
* **Trivy Operator**
    - Vulnerability reports
    - Container security scanning

## Extension API

* Kubernetes-style API server
* Projects resource (namespace view by permissions)
* Bearer token authentication
* Full CRUD operations
* API discovery endpoints

## Coming Soon

* Gateway API Plugin for object visualization
* FluxCD Plugin for GitOps visualization
