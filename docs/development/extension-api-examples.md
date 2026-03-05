# Extension API Example Client

This document provides example client code for interacting with the KubeDash Extension API Server.

## Python Client Examples

### Basic Client Class

```python
#!/usr/bin/env python3
"""
Example client for KubeDash Extension API Server.

This client demonstrates how to interact with the Projects API
using the Kubernetes Python client library.
"""

import json
from typing import List, Optional, Dict, Any
from kubernetes import client, config
from kubernetes.client.rest import ApiException


class KubeDashProjectClient:
    """Client for KubeDash Project resources via Extension API."""
    
    API_GROUP = "kubedash.devopstales.github.io"
    API_VERSION = "v1"
    API_PATH = f"/apis/{API_GROUP}/{API_VERSION}"
    
    def __init__(self, kubeconfig: str = None):
        """
        Initialize the client.
        
        Args:
            kubeconfig: Path to kubeconfig file (uses default if None)
        """
        if kubeconfig:
            config.load_kube_config(config_file=kubeconfig)
        else:
            config.load_kube_config()
        
        self.api_client = client.ApiClient()
    
    def list_projects(self, namespace: str = None) -> List[Dict[str, Any]]:
        """
        List all projects.
        
        Args:
            namespace: Optional namespace filter
            
        Returns:
            List of project objects
        """
        path = f"{self.API_PATH}/projects"
        if namespace:
            path = f"{self.API_PATH}/namespaces/{namespace}/projects"
        
        try:
            response = self.api_client.call_api(
                path,
                'GET',
                response_type='object',
                _request_timeout=10
            )
            return response.get('items', [])
        except ApiException as e:
            print(f"Error listing projects: {e.reason}")
            return []
    
    def get_project(self, name: str, namespace: str = None) -> Optional[Dict[str, Any]]:
        """
        Get a specific project.
        
        Args:
            name: Project name
            namespace: Optional namespace
            
        Returns:
            Project object or None if not found
        """
        path = f"{self.API_PATH}/projects/{name}"
        if namespace:
            path = f"{self.API_PATH}/namespaces/{namespace}/projects/{name}"
        
        try:
            response = self.api_client.call_api(
                path,
                'GET',
                response_type='object',
                _request_timeout=10
            )
            return response
        except ApiException as e:
            if e.status == 404:
                return None
            print(f"Error getting project: {e.reason}")
            return None
    
    def create_project(self, name: str, owner: str, protected: bool = False, 
                       namespace: str = None) -> Optional[Dict[str, Any]]:
        """
        Create a new project.
        
        Args:
            name: Project name
            owner: Project owner
            protected: Whether the project is protected
            namespace: Optional namespace
            
        Returns:
            Created project object or None if failed
        """
        path = f"{self.API_PATH}/projects"
        if namespace:
            path = f"{self.API_PATH}/namespaces/{namespace}/projects"
        
        project = {
            "apiVersion": self.API_GROUP + "/" + self.API_VERSION,
            "kind": "Project",
            "metadata": {
                "name": name
            },
            "spec": {
                "owner": owner,
                "protected": protected
            }
        }
        
        try:
            response = self.api_client.call_api(
                path,
                'POST',
                body=project,
                response_type='object',
                _request_timeout=10
            )
            return response
        except ApiException as e:
            print(f"Error creating project: {e.reason}")
            return None
    
    def update_project(self, name: str, spec: Dict[str, Any], 
                       namespace: str = None) -> Optional[Dict[str, Any]]:
        """
        Update a project.
        
        Args:
            name: Project name
            spec: New spec values
            namespace: Optional namespace
            
        Returns:
            Updated project object or None if failed
        """
        path = f"{self.API_PATH}/projects/{name}"
        if namespace:
            path = f"{self.API_PATH}/namespaces/{namespace}/projects/{name}"
        
        try:
            # First get the current project
            current = self.get_project(name, namespace)
            if not current:
                print(f"Project {name} not found")
                return None
            
            # Update spec
            current['spec'] = spec
            
            response = self.api_client.call_api(
                path,
                'PUT',
                body=current,
                response_type='object',
                _request_timeout=10
            )
            return response
        except ApiException as e:
            print(f"Error updating project: {e.reason}")
            return None
    
    def delete_project(self, name: str, namespace: str = None) -> bool:
        """
        Delete a project.
        
        Args:
            name: Project name
            namespace: Optional namespace
            
        Returns:
            True if deleted, False otherwise
        """
        path = f"{self.API_PATH}/projects/{name}"
        if namespace:
            path = f"{self.API_PATH}/namespaces/{namespace}/projects/{name}"
        
        try:
            self.api_client.call_api(
                path,
                'DELETE',
                response_type='object',
                _request_timeout=10
            )
            return True
        except ApiException as e:
            print(f"Error deleting project: {e.reason}")
            return False


# Example usage
if __name__ == "__main__":
    # Initialize client
    client = KubeDashProjectClient()
    
    # List all projects
    print("Listing projects...")
    projects = client.list_projects()
    print(f"Found {len(projects)} projects")
    
    for project in projects[:5]:  # Show first 5
        name = project['metadata']['name']
        spec = project.get('spec', {})
        owner = spec.get('owner', 'unknown')
        protected = spec.get('protected', False)
        print(f"  - {name} (owner: {owner}, protected: {protected})")
    
    # Create a new project
    print("\nCreating test-project...")
    new_project = client.create_project(
        name="test-project",
        owner="test-user",
        protected=False
    )
    if new_project:
        print(f"Created project: {new_project['metadata']['name']}")
    
    # Get a specific project
    print("\nGetting test-project details...")
    project = client.get_project("test-project")
    if project:
        print(json.dumps(project, indent=2))
    
    # Update the project
    print("\nUpdating test-project...")
    updated = client.update_project(
        name="test-project",
        spec={"owner": "new-owner", "protected": True}
    )
    if updated:
        print(f"Updated project owner to: {updated['spec']['owner']}")
    
    # Delete the project
    print("\nDeleting test-project...")
    if client.delete_project("test-project"):
        print("Project deleted successfully")
```

### Using Requests Library

```python
#!/usr/bin/env python3
"""
Example client using requests library with bearer token authentication.
"""

import requests
import subprocess
import json
from typing import List, Optional, Dict, Any


class KubeDashRequestsClient:
    """Client for KubeDash Extension API using requests library."""
    
    API_GROUP = "kubedash.devopstales.github.io"
    API_VERSION = "v1"
    
    def __init__(self, base_url: str, token: str = None):
        """
        Initialize the client.
        
        Args:
            base_url: Base URL of the extension API (e.g., http://localhost:8000)
            token: Bearer token for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.token = token or self._get_kubectl_token()
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        })
    
    def _get_kubectl_token(self) -> str:
        """Get a token using kubectl."""
        result = subprocess.run(
            ['kubectl', 'create', 'token', 'default', '-n', 'default'],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to get token: {result.stderr}")
        return result.stdout.strip()
    
    def list_projects(self) -> List[Dict[str, Any]]:
        """List all projects."""
        url = f"{self.base_url}/apis/{self.API_GROUP}/{self.API_VERSION}/projects"
        response = self.session.get(url)
        response.raise_for_status()
        return response.json().get('items', [])
    
    def get_project(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a specific project."""
        url = f"{self.base_url}/apis/{self.API_GROUP}/{self.API_VERSION}/projects/{name}"
        response = self.session.get(url)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        return response.json()
    
    def create_project(self, name: str, owner: str, protected: bool = False) -> Dict[str, Any]:
        """Create a new project."""
        url = f"{self.base_url}/apis/{self.API_GROUP}/{self.API_VERSION}/projects"
        project = {
            "apiVersion": f"{self.API_GROUP}/{self.API_VERSION}",
            "kind": "Project",
            "metadata": {"name": name},
            "spec": {"owner": owner, "protected": protected}
        }
        response = self.session.post(url, json=project)
        response.raise_for_status()
        return response.json()
    
    def delete_project(self, name: str) -> bool:
        """Delete a project."""
        url = f"{self.base_url}/apis/{self.API_GROUP}/{self.API_VERSION}/projects/{name}"
        response = self.session.delete(url)
        if response.status_code == 404:
            return False
        response.raise_for_status()
        return True


# Example usage
if __name__ == "__main__":
    # Initialize client
    client = KubeDashRequestsClient("http://localhost:8000")
    
    # List projects
    projects = client.list_projects()
    print(f"Found {len(projects)} projects")
    
    # Create a project
    new_project = client.create_project("my-project", "my-user")
    print(f"Created: {new_project['metadata']['name']}")
```

## Bash/Shell Examples

### Using curl

```bash
#!/bin/bash
# Example bash script for interacting with Extension API

set -e

BASE_URL="${KUBEDASH_URL:-http://localhost:8000}"
TOKEN="${KUBEDASH_TOKEN:-$(kubectl create token default -n default)}"
API_PATH="apis/kubedash.devopstales.github.io/v1"

# Function to make authenticated requests
api_request() {
    local method=$1
    local path=$2
    local data=$3
    
    if [ -n "$data" ]; then
        curl -s -X "$method" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE_URL/$path"
    else
        curl -s -X "$method" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            "$BASE_URL/$path"
    fi
}

# List projects
echo "Listing projects..."
api_request GET "$API_PATH/projects" | jq '.items | length'

# Create a project
echo "Creating test-project..."
PROJECT_DATA='{
    "apiVersion": "kubedash.devopstales.github.io/v1",
    "kind": "Project",
    "metadata": {"name": "test-project"},
    "spec": {"owner": "test-user", "protected": false}
}'
api_request POST "$API_PATH/projects" "$PROJECT_DATA" | jq '.metadata.name'

# Get project
echo "Getting test-project..."
api_request GET "$API_PATH/projects/test-project" | jq '.spec'

# Delete project
echo "Deleting test-project..."
api_request DELETE "$API_PATH/projects/test-project" > /dev/null && echo "Deleted"
```

## kubectl Examples

### Using kubectl directly

```bash
# List all projects
kubectl get projects.kubedash.devopstales.github.io

# Get detailed output
kubectl get projects.kubedash.devopstales.github.io -o wide

# Get as YAML
kubectl get projects.kubedash.devopstales.github.io -o yaml

# Watch for changes
kubectl get projects.kubedash.devopstales.github.io -w

# Create a project from file
cat <<EOF | kubectl apply -f -
apiVersion: kubedash.devopstales.github.io/v1
kind: Project
metadata:
  name: my-project
spec:
  owner: devopstales
  protected: true
  description: "My test project"
EOF

# Delete a project
kubectl delete project my-project.kubedash.devopstales.github.io

# Describe a project
kubectl describe project my-project.kubedash.devopstales.github.io
```

### Using kubectl with custom columns

```bash
# Custom columns output
kubectl get projects.kubedash.devopstales.github.io \
    -o custom-columns='NAME:.metadata.name,OWNER:.spec.owner,PROTECTED:.spec.protected,STATUS:.status.phase'

# Show only name and owner
kubectl get projects.kubedash.devopstales.github.io \
    -o custom-columns='NAME:.metadata.name,OWNER:.spec.owner'
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Create Project

on:
  workflow_dispatch:
    inputs:
      project_name:
        description: 'Project name'
        required: true

jobs:
  create-project:
    runs-on: ubuntu-latest
    steps:
      - name: Set up kubectl
        uses: azure/setup-kubectl@v3
      
      - name: Configure kubeconfig
        run: |
          echo "${{ secrets.KUBECONFIG }}" | base64 -d > kubeconfig
          export KUBECONFIG=kubeconfig
      
      - name: Create project
        run: |
          kubectl apply -f - <<EOF
          apiVersion: kubedash.devopstales.github.io/v1
          kind: Project
          metadata:
            name: ${{ github.event.inputs.project_name }}
          spec:
            owner: ${{ github.actor }}
            protected: false
          EOF
      
      - name: Verify project
        run: |
          kubectl get project ${{ github.event.inputs.project_name }}.kubedash.devopstales.github.io
```
