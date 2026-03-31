# Extension API

KubeDash provides a Kubernetes-style API server that exposes custom resources following the Kubernetes API conventions. This allows you to interact with KubeDash resources using standard Kubernetes tools like `kubectl`.

KubeDash can be registered as a Kubernetes API Extension Server using the API Aggregation Layer, making it appear as a native Kubernetes API endpoint.

## Overview

The Extension API implements the Kubernetes API Aggregation Layer pattern, providing:

- **API Discovery**: Standard Kubernetes API discovery endpoints
- **Custom Resources**: Project resources for namespace management
- **Bearer Token Auth**: Authentication using Kubernetes ServiceAccount tokens
- **RBAC Integration**: Authorization based on Kubernetes RBAC permissions
- **Native kubectl Integration**: Works seamlessly with `kubectl` and other Kubernetes clients

## API Group

| Property | Value |
|----------|-------|
| API Group | `kubedash.devopstales.github.io` |
| Version | `v1` |
| Full Path | `/apis/kubedash.devopstales.github.io/v1` |

## Available Resources

### Projects

Projects represent Kubernetes namespaces filtered by user permissions. They provide a user-scoped view of namespaces based on RBAC.

| Property | Value |
|----------|-------|
| Kind | `Project` |
| Plural | `projects` |
| Short Name | `proj` |
| Scope | Cluster |
| Verbs | get, list, watch, create, update, patch, delete |

## Registering KubeDash as an API Extension Server

To integrate KubeDash with Kubernetes API discovery and enable native `kubectl` support, you need to register it as an APIService.

### Prerequisites

1. **KubeDash must be accessible via HTTPS** (required for API aggregation)
2. **Service and Endpoints** must be created in Kubernetes
3. **APIService** resource must be created to register the extension

### Step 1: Create Service and Endpoints

Create a Service that points to your KubeDash instance:

```yaml
---
apiVersion: v1
kind: Service
metadata:
  name: kubedash-extension-api
  namespace: kubedash  # Adjust namespace as needed
  labels:
    app: kubedash
spec:
  ports:
    - name: https
      port: 443
      targetPort: 8000  # Adjust to your KubeDash port
      protocol: TCP
  # No selector - we'll use Endpoints below
---
apiVersion: v1
kind: Endpoints
metadata:
  name: kubedash-extension-api  # Must match Service name
  namespace: kubedash
subsets:
  - addresses:
      - ip: 10.0.0.100  # IP address of your KubeDash instance
    ports:
      - name: https
        port: 8000  # KubeDash port
        protocol: TCP
```

!!! note
    If KubeDash is running inside the cluster, you can use a regular Service with selectors instead of Endpoints.

### Step 2: Create APIService Resource

Register KubeDash as an API extension:

```yaml
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
  caBundle: <base64-encoded-ca-certificate>
  # Option 2: Skip TLS verification (development only, still requires HTTPS!)
  # insecureSkipTLSVerify: true
  groupPriorityMinimum: 1000
  versionPriority: 100
```

### Step 3: Verify Registration

Check that the APIService is registered:

```bash
# Check APIService status
kubectl get apiservice v1.kubedash.devopstales.github.io

# Verify API discovery
kubectl api-resources | grep kubedash

# Test with kubectl
kubectl get projects
```

### APIService Configuration Options

| Field | Description | Required |
|-------|-------------|----------|
| `group` | API group name | Yes |
| `version` | API version | Yes |
| `service.name` | Service name | Yes |
| `service.namespace` | Service namespace | Yes |
| `service.port` | Service port | Yes |
| `caBundle` | Base64-encoded CA certificate | Recommended |
| `insecureSkipTLSVerify` | Skip TLS verification | Dev only |
| `groupPriorityMinimum` | Priority for API group | Recommended |
| `versionPriority` | Priority for API version | Recommended |

### TLS Configuration

Kubernetes API aggregation **requires HTTPS**. You have two options:

#### Option 1: CA Bundle (Recommended)

Provide the CA certificate that signed KubeDash's TLS certificate:

```yaml
spec:
  caBundle: LS0tLS1CRUdJTi...  # Base64-encoded CA cert
```

#### Option 2: Skip TLS Verification (Development Only)

For development/testing only:

```yaml
spec:
  insecureSkipTLSVerify: true
```

!!! warning
    `insecureSkipTLSVerify: true` should **never** be used in production. It bypasses TLS certificate validation.

### Troubleshooting

#### APIService Not Available

```bash
# Check APIService status
kubectl get apiservice v1.kubedash.devopstales.github.io -o yaml

# Check for conditions
kubectl describe apiservice v1.kubedash.devopstales.github.io
```

Common issues:
- **Service not found**: Verify Service and Endpoints exist
- **TLS errors**: Ensure HTTPS is enabled and CA bundle is correct
- **Connection refused**: Verify KubeDash is accessible at the specified IP/port

#### Verify API Discovery

```bash
# Check if API group is discovered
kubectl get --raw /apis/kubedash.devopstales.github.io/v1

# List API resources
kubectl api-resources --api-group=kubedash.devopstales.github.io
```

### Using with kubectl

Once registered, you can use `kubectl` directly:

```bash
# List projects
kubectl get projects
kubectl get proj  # Short name

# Get specific project
kubectl get project my-project

# Create project
kubectl create -f project.yaml

# Delete project
kubectl delete project my-project
```

### Example: Complete Setup

Here's a complete example for registering KubeDash:

```yaml
---
# Service (if KubeDash is in-cluster)
apiVersion: v1
kind: Service
metadata:
  name: kubedash-extension-api
  namespace: kubedash
spec:
  selector:
    app: kubedash
  ports:
    - name: https
      port: 443
      targetPort: 8000
---
# APIService
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
  caBundle: <your-ca-bundle>
  groupPriorityMinimum: 1000
  versionPriority: 100
```

Apply with:

```bash
kubectl apply -f kubedash-apiservice.yaml
```

## Authentication

The Extension API uses Bearer token authentication with Kubernetes ServiceAccount tokens.

### Getting a Token

Create a token for a ServiceAccount:

```bash
# Create a token for the default service account
TOKEN=$(kubectl create token default -n default)

# Or for a specific service account
TOKEN=$(kubectl create token my-service-account -n my-namespace)
```

### Using the Token

Include the token in the `Authorization` header:

```bash
curl -X GET http://kubedash.example.com/apis/kubedash.devopstales.github.io/v1/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

## API Endpoints

### API Discovery

#### List API Groups

```http
GET /apis
```

Returns all available API groups.

**Response:**
```json
{
  "kind": "APIGroupList",
  "apiVersion": "v1",
  "groups": [
    {
      "name": "kubedash.devopstales.github.io",
      "versions": [
        {
          "groupVersion": "kubedash.devopstales.github.io/v1",
          "version": "v1"
        }
      ],
      "preferredVersion": {
        "groupVersion": "kubedash.devopstales.github.io/v1",
        "version": "v1"
      }
    }
  ]
}
```

#### Get API Group

```http
GET /apis/kubedash.devopstales.github.io
```

Returns information about the KubeDash API group.

#### List API Resources

```http
GET /apis/kubedash.devopstales.github.io/v1
```

Returns all resources available in the v1 version.

**Response:**
```json
{
  "kind": "APIResourceList",
  "apiVersion": "v1",
  "groupVersion": "kubedash.devopstales.github.io/v1",
  "resources": [
    {
      "name": "projects",
      "singularName": "project",
      "namespaced": false,
      "kind": "Project",
      "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"],
      "shortNames": ["proj"],
      "categories": ["all"]
    }
  ]
}
```

### Projects API

#### List Projects

```http
GET /apis/kubedash.devopstales.github.io/v1/projects
```

Returns all projects (namespaces) the user has access to.

**Query Parameters:**

| Parameter | Description |
|-----------|-------------|
| `labelSelector` | Filter by labels |
| `fieldSelector` | Filter by fields |
| `limit` | Maximum results |
| `continue` | Continuation token |
| `watch` | Enable watch mode |

**Example:**

```bash
curl -X GET "http://kubedash.example.com/apis/kubedash.devopstales.github.io/v1/projects" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "apiVersion": "kubedash.devopstales.github.io/v1",
  "kind": "ProjectList",
  "metadata": {
    "resourceVersion": "12345"
  },
  "items": [
    {
      "apiVersion": "kubedash.devopstales.github.io/v1",
      "kind": "Project",
      "metadata": {
        "name": "default",
        "uid": "abc123",
        "resourceVersion": "100",
        "creationTimestamp": "2025-01-01T00:00:00Z"
      },
      "spec": {
        "owner": "admin",
        "protected": false
      },
      "status": {
        "phase": "Active"
      }
    }
  ]
}
```

#### Get Project

```http
GET /apis/kubedash.devopstales.github.io/v1/projects/{name}
```

Returns a specific project by name.

**Example:**

```bash
curl -X GET "http://kubedash.example.com/apis/kubedash.devopstales.github.io/v1/projects/my-project" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

#### Create Project

```http
POST /apis/kubedash.devopstales.github.io/v1/projects
```

Creates a new project (namespace).

**Request Body:**
```json
{
  "apiVersion": "kubedash.devopstales.github.io/v1",
  "kind": "Project",
  "metadata": {
    "name": "my-new-project"
  },
  "spec": {
    "owner": "username",
    "protected": false
  }
}
```

**Example:**

```bash
curl -X POST "http://kubedash.example.com/apis/kubedash.devopstales.github.io/v1/projects" \
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

#### Update Project

```http
PUT /apis/kubedash.devopstales.github.io/v1/projects/{name}
```

Updates an existing project.

**Example:**

```bash
curl -X PUT "http://kubedash.example.com/apis/kubedash.devopstales.github.io/v1/projects/my-project" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "apiVersion": "kubedash.devopstales.github.io/v1",
    "kind": "Project",
    "metadata": {
      "name": "my-project"
    },
    "spec": {
      "owner": "new-owner",
      "protected": true
    }
  }'
```

#### Delete Project

```http
DELETE /apis/kubedash.devopstales.github.io/v1/projects/{name}
```

Deletes a project (namespace).

**Example:**

```bash
curl -X DELETE "http://kubedash.example.com/apis/kubedash.devopstales.github.io/v1/projects/my-project" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json"
```

## Project Resource Schema

### Metadata

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Project name (namespace name) |
| `uid` | string | Unique identifier |
| `resourceVersion` | string | Resource version for optimistic locking |
| `creationTimestamp` | string | ISO 8601 creation timestamp |
| `labels` | object | Key-value labels |
| `annotations` | object | Key-value annotations |

### Spec

| Field | Type | Description |
|-------|------|-------------|
| `owner` | string | Project owner username |
| `protected` | boolean | Whether the project is protected from deletion |

### Status

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current phase (Active, Terminating) |

## Authorization

The Extension API respects Kubernetes RBAC permissions:

### Listing Projects

Users can only see projects (namespaces) where they have permission to list pods. This ensures users only see namespaces relevant to them.

### Admin Access

Users with cluster-admin or ability to list all namespaces see all projects.

### Required RBAC

To access the Extension API, users need:

```yaml
# For listing projects the user has access to
rules:
  - apiGroups: [""]
    resources: ["namespaces"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]  # Used to check namespace access
```

## Usage Examples

### List Projects with Python

```python
import requests

TOKEN = "your-service-account-token"
BASE_URL = "http://kubedash.example.com"

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}

# List all projects
response = requests.get(
    f"{BASE_URL}/apis/kubedash.devopstales.github.io/v1/projects",
    headers=headers
)

projects = response.json()
for project in projects.get("items", []):
    print(f"Project: {project['metadata']['name']}")
    print(f"  Owner: {project['spec'].get('owner', 'N/A')}")
    print(f"  Status: {project['status']['phase']}")
```

### Display Projects in Table Format

```python
import json

with open('projects.json', 'r') as f:
    data = json.load(f)

print('NAME' + ' ' * 46 + 'PROTECTED   OWNER' + ' ' * 23 + 'STATUS   AGE')

for item in data.get('items', [])[:25]:
    name = item['metadata']['name'][:48]
    spec = item.get('spec', {})
    protected = 'true' if spec.get('protected', False) else 'false'
    owner = spec.get('owner', '')[:35] if spec.get('owner') else '<none>'
    status = item.get('status', {}).get('phase', 'Unknown')
    
    print(f'{name:<50} {protected:<11} {owner:<40} {status:<8}')
```

## Error Responses

The API returns Kubernetes-style error responses:

### 401 Unauthorized

```json
{
  "apiVersion": "v1",
  "kind": "Status",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401
}
```

### 404 Not Found

```json
{
  "apiVersion": "v1",
  "kind": "Status",
  "metadata": {},
  "status": "Failure",
  "message": "projects \"my-project\" not found",
  "reason": "NotFound",
  "details": {
    "name": "my-project",
    "kind": "projects"
  },
  "code": 404
}
```

### 403 Forbidden

```json
{
  "apiVersion": "v1",
  "kind": "Status",
  "metadata": {},
  "status": "Failure",
  "message": "User does not have access to project",
  "reason": "Forbidden",
  "code": 403
}
```

## Best Practices

### Token Management

- Use short-lived tokens when possible
- Create dedicated ServiceAccounts for API access
- Apply least-privilege RBAC to ServiceAccounts

### Error Handling

- Check response status codes
- Parse error responses for detailed information
- Implement retry logic for transient errors

### Performance

- Use `limit` parameter for large result sets
- Cache results when appropriate
- Use `watch` for real-time updates instead of polling
