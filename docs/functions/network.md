# Network Resources

KubeDash provides visibility into your cluster's network configuration including Services, Ingresses, and Ingress Classes.

## Services

Services expose your applications to network traffic, providing stable endpoints for pods.

### Viewing Services

Navigate to `Network > Services` to see all services in the selected namespace:

![Service List](../img/network/service-list.png)

The service list shows:

| Column | Description |
|--------|-------------|
| Name | Service name |
| Type | ClusterIP, NodePort, LoadBalancer, or ExternalName |
| Cluster IP | Internal cluster IP address |
| External IP | External IP (for LoadBalancer type) |
| Ports | Exposed ports and protocols |
| Age | Time since creation |

### Service Details

Click on a service to view its details:

- **Spec**: Type, cluster IP, ports, selector
- **Endpoints**: Pods currently backing the service
- **Labels & Annotations**: Metadata

### Service Types

| Type | Description |
|------|-------------|
| **ClusterIP** | Internal-only IP, default type |
| **NodePort** | Exposes on each node's IP at a static port |
| **LoadBalancer** | Provisions external load balancer |
| **ExternalName** | Maps to external DNS name |

### Viewing Service Endpoints

KubeDash shows which pods are backing a service based on its selector:

1. Click on a service
2. View the "Pods" section to see all matching pods
3. Click on a pod to navigate to its details

## Ingresses

Ingresses manage external access to services, typically HTTP/HTTPS routing.

### Viewing Ingresses

Navigate to `Network > Ingresses` to see all ingresses in the selected namespace:

![Ingress List](../img/network/ingress-list.png)

The ingress list shows:

| Column | Description |
|--------|-------------|
| Name | Ingress name |
| Class | Ingress class (controller) |
| Hosts | Configured hostnames |
| Address | Load balancer address |
| Ports | HTTP (80) and/or HTTPS (443) |
| Age | Time since creation |

### Ingress Details

Click on an ingress to view its details:

- **Spec**: Ingress class, default backend
- **Rules**: Host-based routing rules
- **TLS**: TLS configuration and secrets
- **Status**: Load balancer ingress points

### Ingress Rules

Each ingress can have multiple rules:

```yaml
rules:
  - host: app.example.com
    http:
      paths:
        - path: /api
          pathType: Prefix
          backend:
            service:
              name: api-service
              port:
                number: 8080
        - path: /
          pathType: Prefix
          backend:
            service:
              name: frontend-service
              port:
                number: 80
```

KubeDash displays these rules in an easy-to-read format.

## Ingress Classes

Ingress Classes define which controller should handle ingress resources.

### Viewing Ingress Classes

Navigate to `Network > Ingress Classes` to see all ingress classes:

![Ingress Class List](../img/network/ingress-class-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Ingress class name |
| Controller | Controller implementation |
| Default | Whether this is the default class |
| Age | Time since creation |

### Ingress Class Details

Click on an ingress class to view:

- **Controller**: The ingress controller (e.g., `k8s.io/ingress-nginx`)
- **Parameters**: Optional configuration parameters
- **Default**: Whether new ingresses use this class by default

### Common Ingress Controllers

| Controller | Description |
|------------|-------------|
| `k8s.io/ingress-nginx` | NGINX Ingress Controller |
| `traefik.io/ingress-controller` | Traefik |
| `haproxy.org/ingress-controller` | HAProxy |
| `istio.io/ingress-controller` | Istio Gateway |

## Best Practices

### Service Design

- Use meaningful service names
- Prefer ClusterIP for internal services
- Use LoadBalancer only when external access is needed
- Consider using Ingress for HTTP services instead of LoadBalancer

### Ingress Configuration

- Use TLS for all external-facing services
- Configure appropriate path types (Prefix, Exact, ImplementationSpecific)
- Set up health check annotations for your ingress controller
- Use annotations for controller-specific features

### Network Security

- Apply Network Policies to restrict traffic
- Use internal-only services where possible
- Regularly audit exposed services

See [Network Policies](security.md#network-policies) for more information on securing network traffic.
