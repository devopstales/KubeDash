# Extension API: Testing After Install on Kubernetes

This guide describes how to test the KubeDash **Extension API** after it is installed on a Kubernetes cluster. The Extension API exposes KubeDash Projects as a Kubernetes-style API so you can use `kubectl` and other Kubernetes clients.

For setup and registration (APIService, TLS, RBAC), see [Extension API](../integrations/extension-api.md).

## Prerequisites

- KubeDash is installed on the cluster (e.g. via Helm).
- Extension API is enabled. With the Helm chart, set in `values.yaml`:

  ```yaml
  extensionApi:
    enabled: true
  ```

- Your `kubectl` context targets the same cluster where KubeDash is running.
- Your user or ServiceAccount has RBAC permissions to use the Extension API and to manage Projects (see [Extension API - RBAC](../integrations/extension-api.md#rbac)).

## 1. Verify APIService registration

Check that the Extension API is registered:

```bash
# Default APIService name when using Helm with default values
kubectl get apiservice v1.kubedash.devopstales.github.io
```

Expected: `AVAILABLE` should be `True`. If it is `False`, inspect the APIService and the extension API Service/Endpoints:

```bash
# Inspect APIService details
kubectl get apiservice v1.kubedash.devopstales.github.io -o yaml

# Check the Extension API Service (default name: <release>-extension-api)
kubectl get svc -l app.kubernetes.io/component=extension-api

# If the Service has no selector, check Endpoints
kubectl get endpoints -l app.kubernetes.io/component=extension-api
```

## 2. Verify API discovery

Confirm that the API group and resources are discoverable:

```bash
# List API resources for the KubeDash group
kubectl api-resources | grep kubedash

# Expected output includes:
# NAME       SHORTNAMES   APIVERSION                           NAMESPACED   KIND
# projects   proj         kubedash.devopstales.github.io/v1   false        Project
```

## 3. Test with kubectl

### List projects

```bash
kubectl get projects
```

Alternative (explicit API group/version):

```bash
kubectl get projects.kubedash.devopstales.github.io
```

### Get a single project

```bash
# Replace <project-name> with an existing namespace/project name
kubectl get project <project-name> -o yaml
```

### Create a project (from manifest)

```bash
kubectl apply -f - <<EOF
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: my-test-project
spec:
  protected: false
EOF
```

### Create a project (imperative)

```bash
kubectl create -f - <<EOF
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: my-test-project
spec:
  protected: false
EOF
```

### Delete a project

```bash
kubectl delete project my-test-project
```

### Watch projects (if supported)

```bash
kubectl get projects --watch
```

## 4. Troubleshooting

### APIService not available

- Ensure the Extension API Service is reachable from the API server (correct namespace, port 443, and TLS).
- Check KubeDash logs for errors on the extension API port.
- For Helm installs, confirm `extensionApi.enabled: true` and that the release is in the expected namespace.

### 401 Unauthorized

- Extension API uses Bearer token authentication. When using `kubectl`, your kubeconfig credentials (e.g. token or client certificate) are sent automatically.
- Ensure the user or ServiceAccount has the right RBAC permissions; see [Extension API - RBAC](../integrations/extension-api.md#rbac).

### 403 Forbidden

- Your identity is authenticated but not allowed to perform the action (e.g. list/create/delete projects). Adjust RBAC (Role/ClusterRole and bindings) as needed.

### No resources found / empty list

- Listing projects returns only namespaces the authenticated user can see. If the list is empty, check namespace access and RBAC for the current context.

## 5. Optional: test with curl (outside cluster)

To call the Extension API directly (e.g. from your machine), you need the cluster API URL, a valid Bearer token, and (if applicable) TLS verification settings.

```bash
# Create a token (example: default ServiceAccount in default namespace)
TOKEN=$(kubectl create token default -n default)

# Replace with your cluster's KubeDash Extension API base URL
# (e.g. via kubectl proxy or an ingress that routes to the extension API)
BASE_URL="https://<kubedash-host>/apis/kubedash.devopstales.github.io/v1"

# List projects
curl -s -k -H "Authorization: Bearer $TOKEN" "$BASE_URL/projects" | jq .

# Get one project
curl -s -k -H "Authorization: Bearer $TOKEN" "$BASE_URL/projects/<project-name>" | jq .
```

Use `-k` only for development (skip TLS verification). In production, use a proper CA and remove `-k`.

## See also

- [Extension API](../integrations/extension-api.md) — Registration, TLS, RBAC, and architecture.
- [API Reference — Extension API](api-reference.md#extension-api) — Full API reference and OpenAPI.
