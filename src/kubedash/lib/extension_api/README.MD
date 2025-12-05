```bash
TOKEN=$(kubectl create token default -n default)

curl -X GET http://localhost:8000/apis/kubedash.devopstales.github.io/v1/projects \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" > /tmp/projects.json

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

```python
cd /tmp && python3 -c "
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
    
    created = item['metadata'].get('creationTimestamp', '')
    if created:
        from datetime import datetime
        try:
            created_dt = datetime.fromisoformat(created.replace('+00:00', '+00:00').split('+')[0])
            now = datetime.now()
            diff = now - created_dt
            days = diff.days
            if days > 365:
                age = str(days // 365) + 'y' + str((days % 365) // 30) + 'd'
            elif days > 30:
                age = str(days // 30) + 'mo'
            else:
                age = str(days) + 'd'
        except Exception as e:
            age = 'Unknown'
    else:
        age = 'Unknown'
    
    print(f'{name:<50} {protected:<11} {owner:<40} {status:<8} {age}')

print()
print('... showing 25 of ' + str(len(data.get('items', []))) + ' projects')
"
```

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
  # No selector - traffic routed via Endpoints below
---
# Endpoints pointing to external IP
apiVersion: v1
kind: Endpoints
metadata:
  name: kubedash-api  # Must match Service name
  namespace: kubedash
subsets:
  - addresses:
      - ip: 192.168.0.51 # node IP
    ports:
      - name: https
        port: 8000
        protocol: TCP

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
  # Option 1: Provide CA bundle (recommended)
  # caBundle: <base64-encoded-ca-cert>
  # Option 2: Skip TLS verification (dev only, still requires HTTPS!)
  insecureSkipTLSVerify: true
  groupPriorityMinimum: 1000
  versionPriority: 100
```

```
kubectl get APIService
kubectl api-resources
```