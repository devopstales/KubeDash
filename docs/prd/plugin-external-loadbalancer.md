# Product Requirements Document: External LoadBalancer Plugin

**Document Version**: 1.0  
**Last Updated**: December 2025  
**Product**: KubeDash  
**Feature Area**: External LoadBalancer Plugin (MetalLB / Cilium)  
**Status**: Active  

---

## Implementation Status

> **Overall Progress: ~85% Complete**

| Feature | Status | Completion | Notes |
|---------|--------|------------|-------|
| **MetalLB IP Pools** | ✅ Implemented | 100% | IPAddressPool listing |
| **MetalLB L2Advertisements** | ✅ Implemented | 90% | Advertisement config |
| **Cilium IP Pools** | ✅ Implemented | 80% | CiliumLoadBalancerIPPool |
| **Service Allocation** | ✅ Implemented | 90% | LoadBalancer services |
| **Pool Utilization** | ⚠️ Partial | 60% | Basic calculation |
| **BGP Configuration** | ❌ Not Started | 0% | Planned |

### User Story Status
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-LB-001: View IP Address Pools | ✅ Done | `plugins/external_loadbalancer/metallb.py` |
| US-LB-002: View IP Allocations | ✅ Done | Service list with IPs |
| US-LB-003: View L2Advertisements | ✅ Done | `plugins/external_loadbalancer/metallb.py` |
| US-LB-004: View BGPAdvertisements | ❌ Not Done | Planned |
| US-CILIUM-001: View Cilium IP Pools | ✅ Done | `plugins/external_loadbalancer/cilium.py` |

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for the KubeDash External LoadBalancer Plugin. The plugin provides visibility into LoadBalancer IP allocation and configuration for bare-metal Kubernetes clusters using MetalLB or Cilium's LoadBalancer IPAM.

### 1.2 Background

In cloud environments, Kubernetes Services of type LoadBalancer automatically receive external IPs from the cloud provider. In bare-metal or on-premises environments, operators must deploy solutions like MetalLB or use Cilium's built-in LoadBalancer IPAM. This plugin provides visibility into these systems.

### 1.3 Goals

1. **IP Pool Visibility**: View configured IP address pools
2. **Allocation Tracking**: See which services have allocated IPs
3. **Utilization Monitoring**: Track pool usage and availability
4. **Configuration Review**: Verify advertisement configurations
5. **Multi-Provider Support**: Support both MetalLB and Cilium

---

## 2. User Personas

### 2.1 Network Administrator

- **Role**: Manages cluster networking and IP allocation
- **Technical Level**: Expert in networking
- **Goals**: Monitor IP pool usage, plan capacity, troubleshoot connectivity
- **Frustrations**: No visibility into LoadBalancer status without CLI

### 2.2 Application Operator

- **Role**: Deploys services requiring external access
- **Technical Level**: Intermediate
- **Goals**: Verify IP assignment, troubleshoot service connectivity
- **Frustrations**: Unclear why IP allocation fails

### 2.3 Platform Engineer

- **Role**: Manages Kubernetes platform infrastructure
- **Technical Level**: Advanced
- **Goals**: Configure and maintain LoadBalancer infrastructure
- **Frustrations**: Scattered configuration across multiple resources

---

## 3. User Stories

### 3.1 MetalLB Integration

#### US-LB-001: View IP Address Pools
**As a** network administrator  
**I want to** see configured IP address pools  
**So that** I can manage IP allocation  

**Acceptance Criteria**:
- Display IPAddressPool resources
- Pool information:
  - Name
  - Address ranges (CIDR or range format)
  - Auto-assign enabled/disabled
  - Avoid buggy IPs setting
  - Service selectors (if any)
- Calculate pool utilization:
  - Total IPs available
  - IPs currently allocated
  - IPs remaining
  - Utilization percentage
- Visual utilization indicator (progress bar)
- Sort by name or utilization

**Priority**: P0 (Critical)

---

#### US-LB-002: View IP Allocations
**As a** user  
**I want to** see which services have LoadBalancer IPs  
**So that** I can manage external access  

**Acceptance Criteria**:
- List services with type LoadBalancer
- Display:
  - Service name
  - Namespace
  - External IP (or "Pending")
  - Pool name (if MetalLB)
  - Port mappings
  - Creation timestamp
- Filter by:
  - Namespace
  - Pool
  - Status (allocated/pending)
- Link to service details
- Show pending allocations with reason

**Priority**: P1 (High)

---

#### US-LB-003: View L2Advertisements
**As a** network administrator  
**I want to** see L2 advertisement configuration  
**So that** I can verify Layer 2 ARP/NDP setup  

**Acceptance Criteria**:
- Display L2Advertisement resources
- Configuration details:
  - Name
  - IP address pools referenced
  - Node selectors (which nodes announce)
  - Interfaces (which network interfaces)
- Status information
- Show which pools are advertised via L2
- Identify pools without L2 advertisements

**Priority**: P2 (Medium)

---

#### US-LB-004: View BGPAdvertisements
**As a** network administrator  
**I want to** see BGP advertisement configuration  
**So that** I can verify BGP routing setup  

**Acceptance Criteria**:
- Display BGPAdvertisement resources
- Configuration details:
  - Name
  - IP address pools referenced
  - Aggregation length
  - Localpref
  - Communities
  - Peers
- BGPPeer status
- Show BGP session health

**Priority**: P2 (Medium)

---

#### US-LB-005: View Pool Utilization Dashboard
**As a** network administrator  
**I want** a summary dashboard of all pools  
**So that** I can quickly assess capacity  

**Acceptance Criteria**:
- Summary view showing all pools
- Per-pool:
  - Name
  - Total IPs
  - Used IPs
  - Utilization gauge
- Aggregate totals
- Alert indicators for high utilization (>80%)
- Trend over time (if historical data available)

**Priority**: P2 (Medium)

---

### 3.2 Cilium LoadBalancer Integration

#### US-CILIUM-001: View Cilium IP Pools
**As a** network administrator  
**I want to** see Cilium LoadBalancer IP pools  
**So that** I can manage Cilium-based IP allocation  

**Acceptance Criteria**:
- Display CiliumLoadBalancerIPPool resources
- Pool configuration:
  - Name
  - CIDR blocks
  - Service selector (namespace/labels)
  - Disabled status
- Pool utilization metrics
- Show allocated vs available IPs

**Priority**: P2 (Medium)

---

#### US-CILIUM-002: View Cilium Service Allocations
**As a** user  
**I want to** see Cilium LB service allocations  
**So that** I can verify IP assignment  

**Acceptance Criteria**:
- List LoadBalancer services using Cilium
- Show assigned IPs and pools
- Display BGP announcement status (if BGP enabled)
- Link to service details

**Priority**: P2 (Medium)

---

## 4. Functional Requirements

### 4.1 MetalLB Support

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-MLB-01 | Plugin shall list IPAddressPool resources | P0 |
| FR-MLB-02 | Plugin shall calculate pool utilization | P1 |
| FR-MLB-03 | Plugin shall list L2Advertisement resources | P2 |
| FR-MLB-04 | Plugin shall list BGPAdvertisement resources | P2 |
| FR-MLB-05 | Plugin shall list BGPPeer resources | P2 |
| FR-MLB-06 | Plugin shall show services with LoadBalancer IPs | P1 |

### 4.2 Cilium Support

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-CIL-01 | Plugin shall list CiliumLoadBalancerIPPool resources | P2 |
| FR-CIL-02 | Plugin shall calculate Cilium pool utilization | P2 |
| FR-CIL-03 | Plugin shall show Cilium BGP status | P3 |

### 4.3 Plugin Behavior

| ID | Requirement | Priority |
|----|-------------|----------|
| FR-PLG-01 | Plugin shall auto-detect MetalLB vs Cilium | P1 |
| FR-PLG-02 | Plugin shall support both simultaneously | P2 |
| FR-PLG-03 | Plugin shall be disabled if no LB CRDs present | P1 |
| FR-PLG-04 | Plugin shall cache pool data for performance | P2 |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Pool list load time | < 2 seconds |
| NFR-PERF-02 | Utilization calculation | < 1 second |
| NFR-PERF-03 | Service list load time | < 3 seconds |

### 5.2 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | MetalLB v0.13+ (IPAddressPool API) | Required |
| NFR-COMP-02 | MetalLB v0.12 (AddressPool API) | Not supported |
| NFR-COMP-03 | Cilium v1.14+ LB IPAM | Supported |

### 5.3 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-USE-01 | View pool utilization | < 2 clicks |
| NFR-USE-02 | Find service IP | < 3 clicks |

---

## 6. Technical Considerations

### 6.1 MetalLB CRDs (v0.13+)

| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| IPAddressPool | metallb.io | v1beta1 | Cluster |
| L2Advertisement | metallb.io | v1beta1 | Cluster |
| BGPAdvertisement | metallb.io | v1beta1 | Cluster |
| BGPPeer | metallb.io | v1beta1 | Cluster |
| Community | metallb.io | v1beta1 | Cluster |
| BFDProfile | metallb.io | v1beta1 | Cluster |

### 6.2 Cilium CRDs

| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| CiliumLoadBalancerIPPool | cilium.io | v2alpha1 | Cluster |
| CiliumBGPPeeringPolicy | cilium.io | v2alpha1 | Cluster |

### 6.3 IP Pool Utilization Calculation

```python
def calculate_pool_utilization(pool):
    """
    Calculate IP pool utilization.
    
    Pool addresses can be:
    - CIDR: 192.168.1.0/24 (256 IPs)
    - Range: 192.168.1.100-192.168.1.200 (101 IPs)
    """
    total_ips = 0
    for address in pool.spec.addresses:
        if '/' in address:
            # CIDR notation
            network = ipaddress.ip_network(address)
            total_ips += network.num_addresses
        elif '-' in address:
            # Range notation
            start, end = address.split('-')
            start_ip = ipaddress.ip_address(start)
            end_ip = ipaddress.ip_address(end)
            total_ips += int(end_ip) - int(start_ip) + 1
    
    # Count allocated IPs from Services
    allocated_ips = count_services_with_pool(pool.name)
    
    return {
        'total': total_ips,
        'allocated': allocated_ips,
        'available': total_ips - allocated_ips,
        'utilization': (allocated_ips / total_ips) * 100
    }
```

### 6.4 Implementation Files

```
plugins/external_loadbalancer/
├── __init__.py          # Blueprint routes
├── metallb.py           # MetalLB API functions
├── cilium.py            # Cilium API functions
├── helper.py            # Shared utilities
└── templates/
    ├── external-loadbalancer.html.j2
    └── external-loadbalancer-data.html.j2
```

---

## 7. User Interface Guidelines

### 7.1 IP Pool List View

```
+--------------------------------------------------+
| External LoadBalancer                             |
+--------------------------------------------------+
| Provider: MetalLB v0.13.10                        |
+--------------------------------------------------+
| IP Address Pools                                  |
+--------------------------------------------------+
| Pool Name | Range              | Used/Total | %  |
|-----------|--------------------| -----------|----|
| default   | 192.168.1.50-99    | 15/50      | 30%|
|           | [============      ]             |    |
| dmz       | 10.0.0.100-110     | 3/11       | 27%|
|           | [=========         ]             |    |
| internal  | 172.16.0.0/28      | 10/16      | 63%|
|           | [=================  ]            |    |
+--------------------------------------------------+
| Total: 28/77 IPs allocated (36%)                 |
+--------------------------------------------------+
```

### 7.2 Service Allocations View

```
+--------------------------------------------------+
| LoadBalancer Services              [Namespace ▼] |
+--------------------------------------------------+
| Service    | Namespace | External IP  | Pool    |
|------------|-----------|--------------|---------|
| nginx-lb   | default   | 192.168.1.50 | default |
| api-gateway| prod      | 192.168.1.51 | default |
| grafana    | monitoring| 10.0.0.100   | dmz     |
| pending-svc| test      | <pending>    | -       |
+--------------------------------------------------+
```

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Kubernetes library (CustomObjects API, CoreV1 API)
- Plugin framework
- Caching layer

### 8.2 External Dependencies

- MetalLB and/or Cilium installed in cluster
- Respective CRDs available

### 8.3 RBAC Requirements

```yaml
# MetalLB
- apiGroups: ["metallb.io"]
  resources: ["ipaddresspools", "l2advertisements", "bgpadvertisements", "bgppeers"]
  verbs: ["get", "list"]
# Cilium
- apiGroups: ["cilium.io"]
  resources: ["ciliumloadbalancerippools", "ciliumbgppeeringpolicies"]
  verbs: ["get", "list"]
# Services
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get", "list"]
```

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Neither MetalLB nor Cilium installed | Medium | Medium | Show helpful message, disable plugin |
| MetalLB version mismatch (v0.12) | Medium | Low | Detect API version, show upgrade note |
| Large IP pools slow calculation | Low | Low | Caching, efficient IP math |
| BGP configuration complexity | Medium | Medium | Focus on viewing, not editing |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Plugin adoption | 50% of bare-metal users | Feature analytics |
| Pool utilization visibility | 100% accuracy | Verification tests |
| IP allocation debugging | -60% time | User research |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Pool Management**: Create/modify IP pools via UI
2. **IP Reservation**: Reserve IPs for specific services
3. **BGP Session Monitoring**: Real-time BGP session status
4. **Failover Visualization**: Show active/standby for HA
5. **Historical Trends**: Pool utilization over time

### 11.2 Out of Scope (This Version)

- Pool creation/modification
- BGP peer configuration
- IP assignment/unassignment
- MetalLB v0.12 support

---

## 12. Plugin Configuration

```ini
# kubedash.ini
[plugin_settings]
external_loadbalancer = true  # Enable External LoadBalancer plugin
```

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, Network Operations, Platform*
