# Kubernetes Extension API Server

This document describes the KubeDash Kubernetes Extension API Server implementation.

## Overview

KubeDash implements a [Kubernetes Extension API Server](https://kubernetes.io/docs/tasks/extend-kubernetes/setup-extension-api-server/) that serves custom resources like Projects. This allows KubeDash to integrate with `kubectl` and the Kubernetes API aggregation layer.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         kubectl                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ kubectl get projects
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Kubernetes API Server                         │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │              APIService Registration                        │ │
│  │  name: v1.kubedash.devopstales.github.io                   │ │
│  │  service: kubedash-extension-api:443                       │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTPS (aggregated API)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    KubeDash Extension API                        │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ Authentication  │  │  Authorization  │  │    Projects     │ │
│  │                 │  │                 │  │                 │ │
│  │ - Front-proxy   │  │ - RBAC checks   │  │ - CRUD ops      │ │
│  │ - TokenReview   │  │ - Namespace     │  │ - List/Get      │ │
│  │ - Session       │  │   filtering     │  │ - Status        │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Authentication (`lib/extension_api/authentication.py`)

Handles authentication for the extension API server:

1. **Front-Proxy Authentication**: Uses `X-Remote-User` headers from Kubernetes API server
2. **Bearer Token Authentication**: Uses TokenReview API for service account tokens
3. **Session Authentication**: For Web UI requests

```python
from lib.extension_api import authenticate_request, AuthenticatedUser

# Authenticate incoming request
user: AuthenticatedUser = authenticate_request(flask_request)
print(f"Authenticated user: {user.username}, groups: {user.groups}")
```

### Authorization (`lib/extension_api/authorization.py`)

Handles authorization checks:

1. **Namespace Access**: Check if user can access specific namespaces
2. **Self-Subject Access Review**: Use Kubernetes RBAC for permission checks
3. **Permission Filtering**: Filter resources based on user permissions

```python
from lib.extension_api import check_namespace_access, filter_namespaces_by_permission

# Check if user can access a namespace
allowed = check_namespace_access(user, "default")

# Filter namespaces by permission
allowed_namespaces = filter_namespaces_by_permission(user, all_namespaces)
```

### Projects (`lib/extension_api/projects.py`)

Implements Project custom resource operations:

- `list_projects()` - List all projects user has access to
- `get_project(name)` - Get a specific project
- `create_project(project)` - Create a new project
- `update_project(name, project)` - Update a project
- `delete_project(name)` - Delete a project

### Errors (`lib/extension_api/errors.py`)

Provides Kubernetes-compatible error responses:

- `handle_bad_request()` - 400 Bad Request
- `handle_unauthorized()` - 401 Unauthorized
- `handle_forbidden()` - 403 Forbidden
- `handle_not_found()` - 404 Not Found
- `handle_internal_error()` - 500 Internal Server Error

### Helpers (`lib/extension_api/helpers.py`)

Utility functions for building Kubernetes API responses:

- `build_project_object()` - Build Project resource object
- `build_project_list()` - Build ProjectList response
- `build_status_response()` - Build status response
- `build_error_response()` - Build Kubernetes error format

## API Group Information

| Property | Value |
|----------|-------|
| API Group | `kubedash.devopstales.github.io` |
| API Version | `v1` |
| Full Group Version | `kubedash.devopstales.github.io/v1` |

## Deployment

### 1. Create Service and Endpoints

```yaml
---
# Service without selector - requires manual Endpoints
apiVersion: v1
kind: Service
metadata:
  name: kubedash-extension-api
  namespace: kubedash
  labels:
    app: kubedash
spec:
  ports:
    - name: https
      port: 443
      targetPort: 8000
      protocol: TCP
  # No selector - traffic routed via Endpoints
---
# Endpoints pointing to KubeDash pod
apiVersion: v1
kind: Endpoints
metadata:
  name: kubedash-extension-api
  namespace: kubedash
subsets:
  - addresses:
      - ip: 192.168.0.51  # KubeDash pod IP
    ports:
      - name: https
        port: 8000
        protocol: TCP
```

### 2. Register APIService

```yaml
---
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
  # Option 1: Provide CA bundle (recommended for production)
  # caBundle: <base64-encoded-ca-cert>
  # Option 2: Skip TLS verification (development only)
  insecureSkipTLSVerify: true
  groupPriorityMinimum: 1000
  versionPriority: 100
```

### 3. Verify Registration

```bash
# Check APIService status
kubectl get apiservice v1.kubedash.devopstales.github.io

# Should show:
# NAME                                 SERVICE                     AVAILABLE   AGE
# v1.kubedash.devopstales.github.io   kubedash/kubedash-extension-api   True      1m

# Verify API resources are available
kubectl api-resources | grep kubedash
```

## Usage Examples

### Using kubectl

```bash
# List all projects
kubectl get projects.kubedash.devopstales.github.io

# Get a specific project
kubectl get project my-project.kubedash.devopstales.github.io

# Create a project
kubectl apply -f - <<EOF
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: my-project
spec:
  owner: devopstales
  protected: true
EOF

# Delete a project
kubectl delete project my-project.kubedash.devopstales.github.io
```

### Using curl

```bash
# Get token
TOKEN=$(kubectl create token default -n default)

# List projects
curl -X GET http://localhost:8000/apis/kubedash.devopstales.github.io/v1/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Get a specific project
curl -X GET http://localhost:8000/apis/kubedash.devopstales.github.io/v1/projects/my-project \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"

# Create a project
curl -X POST http://localhost:8000/apis/kubedash.devopstales.github.io/v1/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "kubedash.devopstales.github.io/v1",
    "kind": "Project",
    "metadata": {
      "name": "test-project"
    },
    "spec": {
      "owner": "devopstales",
      "protected": true
    }
  }'
```

### Using Python Client

```python
from kubernetes import client, config

# Load kubeconfig
config.load_kube_config()

# Create API client
api_client = client.ApiClient()

# List projects
api_response = api_client.call_api(
    '/apis/kubedash.devopstales.github.io/v1/projects',
    'GET',
    response_type='object'
)
print(f"Projects: {api_response}")

# Get a specific project
api_response = api_client.call_api(
    '/apis/kubedash.devopstales.github.io/v1/projects/my-project',
    'GET',
    response_type='object'
)
print(f"Project: {api_response}")
```

## Project Resource Schema

```yaml
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: string        # Project name (required)
  namespace: string   # Optional, defaults to cluster-scoped
  labels:
    key: string       # Optional labels
  annotations:
    key: string       # Optional annotations
spec:
  owner: string       # Project owner (required)
  protected: boolean  # If true, requires elevated permissions to delete
  description: string # Optional description
status:
  phase: string       # Current phase (e.g., "Active", "Terminating")
  conditions:         # Status conditions
    - type: string
      status: string  # "True", "False", "Unknown"
      reason: string
      message: string
      lastTransitionTime: string
```

## Security Considerations

### TLS Configuration

For production deployments, always use proper TLS:

1. Generate or obtain a TLS certificate for the extension API server
2. Configure KubeDash to serve HTTPS on port 8000
3. Include the CA bundle in the APIService registration:

```yaml
apiVersion: apiregistration.k8s.io/v1
kind: APIService
metadata:
  name: v1.kubedash.devopstales.github.io
spec:
  # ...
  caBundle: <base64-encoded-ca-cert>  # Required for production
```

### RBAC Permissions

Create appropriate RBAC rules for accessing Projects:

```yaml
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: project-viewer
rules:
  - apiGroups: ["kubedash.devopstales.github.io"]
    resources: ["projects"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: project-viewer-binding
subjects:
  - kind: Group
    name: developers
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: project-viewer
  apiGroup: rbac.authorization.k8s.io
```

## Testing

Run extension API tests with Poetry:

```bash
cd src/kubedash
poetry run pytest tests/integration/test_extension_api.py -v
```

## Troubleshooting

### APIService Not Available

```bash
# Check APIService status
kubectl get apiservice v1.kubedash.devopstales.github.io -o yaml

# Look for conditions - should show "Available: True"
# If not available, check:
# 1. Service exists and has correct name/namespace
# 2. Endpoints point to running KubeDash pod
# 3. TLS certificate is valid (if using caBundle)
# 4. KubeDash is listening on the correct port
```

### Permission Denied

```bash
# Check user permissions
kubectl auth can-i get projects.kubedash.devopstales.github.io --as <username>

# Check RBAC bindings
kubectl get clusterrolebindings -o wide | grep kubedash
```

### Connection Refused

```bash
# Verify KubeDash is running
kubectl get pods -n kubedash

# Check service endpoints
kubectl get endpoints kubedash-extension-api -n kubedash

# Verify port configuration
kubectl describe service kubedash-extension-api -n kubedash
```

## References

- [Kubernetes Extension API Server](https://kubernetes.io/docs/tasks/extend-kubernetes/setup-extension-api-server/)
- [Kubernetes API Aggregation](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/apiserver-aggregation/)
- [APIService Registration](https://kubernetes.io/docs/reference/kubernetes-api/cluster-resources/api-service-v1/)
