# Security Resources

KubeDash provides visibility into your cluster's security configuration including Secrets, Network Policies, and Priority Classes.

## Secrets

Secrets store sensitive data such as passwords, OAuth tokens, and SSH keys.

### Viewing Secrets

Navigate to `Security > Secrets` to see all secrets in the selected namespace:

![Secret List](../img/security/secret-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Secret name |
| Type | Secret type (Opaque, kubernetes.io/tls, etc.) |
| Data | Number of data keys |
| Age | Time since creation |

### Secret Types

| Type | Description |
|------|-------------|
| `Opaque` | Generic secret data |
| `kubernetes.io/tls` | TLS certificates |
| `kubernetes.io/dockerconfigjson` | Docker registry credentials |
| `kubernetes.io/service-account-token` | Service account token |
| `kubernetes.io/basic-auth` | Basic authentication |
| `kubernetes.io/ssh-auth` | SSH authentication |

### Secret Details

Click on a secret to view its details:

- **Type**: Secret type
- **Data Keys**: List of keys in the secret
- **Metadata**: Labels, annotations, creation timestamp

!!! warning "Security"
    Secret values are base64 encoded but not encrypted at rest by default. KubeDash displays secret metadata but protects the actual values.

### Best Practices for Secrets

- Enable encryption at rest in your cluster
- Use RBAC to restrict secret access
- Rotate secrets regularly
- Consider external secret management (HashiCorp Vault, AWS Secrets Manager)
- Never commit secrets to version control

## Network Policies

Network Policies control traffic flow between pods and external endpoints.

### Viewing Network Policies

Navigate to `Security > Network Policies` to see all policies in the selected namespace:

![Network Policy List](../img/security/network-policy-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Policy name |
| Pod Selector | Pods the policy applies to |
| Policy Types | Ingress, Egress, or both |
| Age | Time since creation |

### Network Policy Details

Click on a policy to view:

- **Pod Selector**: Which pods this policy applies to
- **Policy Types**: Ingress and/or Egress
- **Ingress Rules**: Allowed incoming traffic
- **Egress Rules**: Allowed outgoing traffic

### Policy Rules

Each rule can specify:

| Field | Description |
|-------|-------------|
| **from/to** | Source/destination selectors |
| **podSelector** | Match pods by labels |
| **namespaceSelector** | Match namespaces by labels |
| **ipBlock** | Match IP CIDR ranges |
| **ports** | Allowed ports and protocols |

### Example Policy Visualization

```
┌─────────────────────────────────────────┐
│ Network Policy: api-policy              │
├─────────────────────────────────────────┤
│ Applies to: app=api                     │
├─────────────────────────────────────────┤
│ INGRESS                                 │
│ ├─ From: namespace=frontend             │
│ │  └─ Ports: TCP/8080                   │
│ └─ From: app=monitoring                 │
│    └─ Ports: TCP/9090                   │
├─────────────────────────────────────────┤
│ EGRESS                                  │
│ ├─ To: app=database                     │
│ │  └─ Ports: TCP/5432                   │
│ └─ To: 0.0.0.0/0                        │
│    └─ Ports: TCP/443                    │
└─────────────────────────────────────────┘
```

### Network Policy Best Practices

- Start with a deny-all policy
- Explicitly allow required traffic
- Use namespace selectors for cross-namespace traffic
- Test policies in non-production first
- Document policy purposes in annotations

## Priority Classes

Priority Classes define scheduling priority for pods.

### Viewing Priority Classes

Navigate to `Security > Priority Classes` to see all priority classes:

![Priority Class List](../img/security/priority-class-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Priority class name |
| Value | Priority value (higher = more important) |
| Global Default | Whether this is the default |
| Preemption Policy | PreemptLowerPriority or Never |
| Description | Human-readable description |

### Priority Class Details

Click on a priority class to view:

- **Value**: Integer priority value
- **Global Default**: Whether applied to pods without explicit priority
- **Preemption Policy**: Whether lower priority pods can be evicted
- **Description**: Purpose of this priority class

### Priority Values

| Range | Typical Use |
|-------|-------------|
| 1,000,000,000+ | System critical (e.g., kube-system) |
| 100,000 - 999,999,999 | Cluster services |
| 1,000 - 99,999 | Production workloads |
| 1 - 999 | Development/testing |
| 0 | Default priority |
| Negative | Best-effort workloads |

### Built-in Priority Classes

| Name | Value | Description |
|------|-------|-------------|
| `system-cluster-critical` | 2000000000 | Critical cluster components |
| `system-node-critical` | 2000001000 | Critical node components |

### Priority Class Best Practices

- Define clear priority tiers for your organization
- Reserve high priorities for critical workloads
- Use preemption carefully to avoid disruption
- Set appropriate default priority class
- Document priority class purposes

## Security Best Practices

### Defense in Depth

1. **Authentication**: Use OIDC or certificate-based auth
2. **Authorization**: Apply least-privilege RBAC
3. **Network**: Implement network policies
4. **Secrets**: Enable encryption at rest
5. **Pods**: Use security contexts and pod security policies

### Audit and Monitoring

- Enable Kubernetes audit logging
- Monitor for policy violations
- Review RBAC permissions regularly
- Track secret access patterns

### Compliance

- Document security configurations
- Maintain compliance evidence
- Regular security assessments
- Incident response procedures
