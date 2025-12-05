# Extension API

KubeDash provides a Kubernetes-style API server that exposes custom resources following the Kubernetes API conventions. This allows you to interact with KubeDash resources using standard Kubernetes tools like `kubectl`.

## Overview

The Extension API implements the Kubernetes API Aggregation Layer pattern, providing:

- **API Discovery**: Standard Kubernetes API discovery endpoints
- **Custom Resources**: Project resources for namespace management
- **Bearer Token Auth**: Authentication using Kubernetes ServiceAccount tokens
- **RBAC Integration**: Authorization based on Kubernetes RBAC permissions

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
        "creationTimestamp": "2024-01-01T00:00:00Z"
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
