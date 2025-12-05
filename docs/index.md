# What is KubeDash?

KubeDash is a general purpose, web-based UI for Kubernetes clusters. It allows users to observe applications running in the cluster and troubleshoot them, as well as manage the cluster itself.

KubeDash was created to be a Kubernetes web UI that has the traditional functionality of other web UIs/dashboards available (i.e. to list and view resources) as well as other features.

## Features

### Dashboard & Monitoring

* **Dark mode** support
* **Cluster Metrics Dashboard** - CPU and memory visualization
* **Cluster Events** - Real-time event monitoring
* **Resource Map** - Visual representation of Kubernetes resources and their connections

### Workload Management

* **Pods** - List, view details, delete
* **Pod Debugging** - Real-time log streaming and interactive terminal (exec)
* **Deployments** - List, view, scale replicas
* **StatefulSets** - List, view, scale replicas
* **DaemonSets** - List, view, scale up/down
* **ReplicaSets** - List, view

### Cluster Resources

* **Namespaces** - Create, delete, scale all workloads up/down
* **Nodes** - List, view details and metrics
* **Custom Resource Definitions (CRDs)** - Browse any CRD and its instances

### Network Resources

* **Services** - List, view details with pod selectors
* **Ingresses** - List, view routing rules
* **Ingress Classes** - List, view controllers

### Storage Resources

* **Storage Classes** - List, view provisioners
* **Persistent Volumes (PV)** - List, view
* **Persistent Volume Claims (PVC)** - List, view with usage metrics
* **ConfigMaps** - List, view key-value data
* **Volume Snapshots** - List
* **Snapshot Classes** - List

### Security Resources

* **Secrets** - List, view (metadata only)
* **Network Policies** - List, view rules
* **Priority Classes** - List, view scheduling priorities

### Autoscaling & Resource Management

* **Horizontal Pod Autoscaler (HPA)** - List, view
* **Vertical Pod Autoscaler (VPA)** - List, view
* **Pod Disruption Budgets (PDB)** - List, view
* **Resource Quotas** - List, view
* **Limit Ranges** - List, view

### Cluster Permissions (RBAC)

* **Service Accounts** - List
* **Roles** - List, view permissions
* **Role Bindings** - List
* **Cluster Roles** - List, view permissions
* **Cluster Role Bindings** - List

### User Management

* **Local Users** - Create and manage local users
* **Kubernetes Users** - Certificate-based authentication
* **SSO/OIDC Users** - Single sign-on integration
* **User Roles** - Admin and User dashboard roles
* **User Groups** - SSO group management
* **Role Templates** - Simplified RBAC assignment

### Authentication & Authorization

* Local user authentication
* **Single sign-on (OIDC)** integration
* Role-based dashboard access (Admin/User)
* Kubernetes RBAC integration

### Kubectl Configuration

* **Kubectl config generation** for SSO users (OIDC-based)
* **Kubectl config generation** for local users (certificate-based)
* **kubectl plugin** for easier config download

### Plugins & Integrations

* **Docker Registry UI** - Browse images, tags, manage registries
* **Helm Chart Dashboard** - View installed releases and history
* **Cert-Manager Plugin** - Certificate and issuer visualization
* **External LoadBalancer Plugin** - MetalLB and Cilium support
* **Extension API** - Kubernetes-style API for Projects

### Extension API (NEW)

* Kubernetes-style aggregated API server
* **Projects resource** - Namespace management via API
* Bearer token authentication (ServiceAccount tokens)
* Full CRUD operations
* Compatible with kubectl and other Kubernetes clients

## Getting Started

See the [Installation Guide](installation/installation.md) to get started with KubeDash.

The default login credentials are:

| Username | Password |
|----------|----------|
| admin | admin |

!!! warning
    Please change the default password after your first login!
