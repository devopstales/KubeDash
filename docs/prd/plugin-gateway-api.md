# Product Requirements Document: Gateway API Plugin

**Document Version**: 2.0  
**Last Updated**: December 2025  
**Product**: KubeDash  
**Feature Area**: Gateway API Plugin  
**Status**: ✅ MVP Complete (In Production)  

---

## Implementation Status

> **Overall Progress: ~85% Complete (MVP Fully Implemented)**  
> **MVP Completion Date**: December 2025  
> **Status**: ✅ Production Ready

### MVP Completion Summary

The Gateway API Plugin MVP has been fully implemented and is production-ready. All core features for viewing and managing Gateway API resources are complete, including:

**✅ Fully Implemented:**
- Complete GatewayClass management (list + detail views with events)
- Complete Gateway management (list + detail views with listeners, addresses, conditions, events)
- Complete HTTPRoute management (list + detail views with rules, matches, filters, backends, events)
- Experimental route types (GRPCRoute, TCPRoute, TLSRoute) - list views
- ReferenceGrant and BackendTLSPolicy support - list views
- Kubernetes Events integration for all detail views
- CRD detection with graceful handling
- Standard (v1) and Experimental (v1alpha2) API support
- Namespace filtering
- Status indicators and condition display
- Annotations filtering
- Menu integration

**❌ Not Implemented (Future Enhancements):**
- Route visualization/graph view
- UDPRoute support
- Route creation/modification via UI
- Gateway provisioning via UI

| Feature | Status | Completion | Notes |
|---------|--------|------------|-------|
| **GatewayClass Listing** | ✅ Complete | 100% | List view + Detail view with events |
| **Gateway Listing** | ✅ Complete | 100% | List view + Detail view with events |
| **HTTPRoute Listing** | ✅ Complete | 100% | List view + Detail view with events |
| **GRPCRoute Listing** | ✅ Complete | 90% | List view implemented (experimental) |
| **TCPRoute Listing** | ✅ Complete | 90% | List view implemented (experimental) |
| **TLSRoute Listing** | ✅ Complete | 90% | List view implemented (experimental) |
| **ReferenceGrant** | ✅ Complete | 90% | List view implemented |
| **BackendTLSPolicy** | ✅ Complete | 90% | List view implemented (experimental) |
| **Events Support** | ✅ Complete | 100% | Events tab in all detail views |
| **Route Visualization** | ❌ Not Started | 0% | Future enhancement |

### Implementation Notes
- ✅ Plugin fully enabled as `gateway_api` (no `__` prefix)
- ✅ All core functions implemented in `plugins/gateway_api/functions.py`
- ✅ Complete templates created in `plugins/gateway_api/templates/`
- ✅ Routes fully integrated with menu system
- ✅ CRD detection and graceful handling
- ✅ Standard (v1) and Experimental (v1alpha2) API support
- ✅ Namespace filtering support
- ✅ Events integration for troubleshooting
- ✅ Annotations filtering (removes unnecessary system annotations)

### User Story Status
| User Story | Status | Implementation File |
|------------|--------|---------------------|
| US-GW-001: List GatewayClasses | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-002: List Gateways | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-003: View Gateway Details | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-detail.html.j2` |
| US-GW-010: List HTTPRoutes | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-011: View HTTPRoute Details | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/httproute-detail.html.j2` |
| US-GW-012: List GRPCRoutes | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-013: List TCPRoutes | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-014: List TLSRoutes | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-020: List ReferenceGrants | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-030: View BackendTLSPolicies | ✅ Complete | `plugins/gateway_api/functions.py`, `templates/gateway-api.html.j2` |
| US-GW-040: Route Visualization | ❌ Not Done | Future enhancement |

---

## 1. Executive Summary

### 1.1 Purpose

This PRD defines the requirements for the KubeDash Gateway API Plugin. The plugin provides visibility into Kubernetes Gateway API resources, enabling users to view and manage gateways, routes, and policies through a web interface.

### 1.2 Background

The Kubernetes Gateway API is the next-generation ingress API, designed to be more expressive, extensible, and role-oriented than the Ingress resource. It introduces concepts like GatewayClass, Gateway, HTTPRoute, and various other route types. As adoption grows, visibility into these resources becomes essential.

### 1.3 Goals

1. **Gateway Visibility**: View all Gateway API resources
2. **Route Management**: Understand routing configurations
3. **Policy Overview**: View attached policies
4. **Traffic Flow**: Visualize traffic routing paths
5. **Compatibility**: Support for standard and experimental resources

---

## 2. User Personas

### 2.1 Platform Engineer

- **Role**: Manages Gateway infrastructure
- **Technical Level**: Expert
- **Goals**: Configure gateways, monitor status, troubleshoot routing
- **Frustrations**: Complex YAML, scattered configurations

### 2.2 Application Developer

- **Role**: Exposes applications via routes
- **Technical Level**: Intermediate
- **Goals**: Create routes, verify traffic flow, debug connectivity
- **Frustrations**: Understanding Gateway vs Ingress differences

### 2.3 Network Administrator

- **Role**: Manages network policies and security
- **Technical Level**: Advanced
- **Goals**: Ensure proper TLS configuration, review routing rules
- **Frustrations**: Lack of visibility into traffic policies

---

## 3. User Stories

### 3.1 Gateway Infrastructure

#### US-GW-001: List GatewayClasses
**As a** platform engineer  
**I want to** see all GatewayClasses  
**So that** I can understand available gateway implementations  

**Acceptance Criteria**:
- Display GatewayClass resources (cluster-scoped)
- Information:
  - Name
  - Controller name
  - Description (from spec)
  - Status (Accepted/Pending)
  - Parameters reference (if any)
  - Age
- Visual status indicators
- Show supported features (if available)

**Priority**: P0 (Critical)

---

#### US-GW-002: List Gateways
**As a** user  
**I want to** see all Gateways  
**So that** I can manage ingress points  

**Acceptance Criteria**:
- Display Gateway resources
- Information:
  - Name
  - Namespace
  - GatewayClass reference
  - Listeners (name, protocol, port)
  - Addresses (IPs assigned)
  - Status (Programmed, Accepted)
  - Attached routes count
- Filter by namespace
- Filter by GatewayClass
- Show listener details

**Priority**: P0 (Critical)

---

#### US-GW-003: View Gateway Details
**As a** user  
**I want to** see detailed Gateway configuration  
**So that** I can verify and troubleshoot  

**Acceptance Criteria**:
- Display full spec:
  - GatewayClass name
  - All listeners with:
    - Name
    - Protocol (HTTP, HTTPS, TLS, TCP, UDP)
    - Port
    - Hostname
    - TLS configuration
    - Allowed routes
- Display status:
  - Conditions
  - Addresses
  - Listener statuses
- Display attached routes
- Display Kubernetes events

**Priority**: P1 (High)

---

### 3.2 Route Management

#### US-GW-010: List HTTPRoutes
**As a** user  
**I want to** see all HTTPRoutes  
**So that** I can understand HTTP routing  

**Acceptance Criteria**:
- Display HTTPRoute resources
- Information:
  - Name
  - Namespace
  - Hostnames
  - Parent gateways
  - Rules count
  - Backend services
  - Status
- Filter by:
  - Namespace
  - Gateway
  - Hostname
- Visual route path representation

**Priority**: P0 (Critical)

---

#### US-GW-011: View HTTPRoute Details
**As a** user  
**I want to** see HTTPRoute configuration  
**So that** I can verify routing rules  

**Acceptance Criteria**:
- Display full spec:
  - Parent references (gateways)
  - Hostnames
  - Rules:
    - Matches (path, headers, query params, method)
    - Filters (request/response modification)
    - Backend references
    - Timeouts
- Display status:
  - Parent statuses
  - Conditions
- Visual rule representation

**Priority**: P1 (High)

---

#### US-GW-012: List GRPCRoutes
**As a** user  
**I want to** see all GRPCRoutes  
**So that** I can understand gRPC routing  

**Acceptance Criteria**:
- Display GRPCRoute resources
- Information:
  - Name
  - Namespace
  - Parent gateways
  - Services (gRPC services/methods)
  - Backend services
  - Status
- Note: Experimental API

**Priority**: P2 (Medium)

---

#### US-GW-013: List TCPRoutes
**As a** user  
**I want to** see all TCPRoutes  
**So that** I can understand TCP routing  

**Acceptance Criteria**:
- Display TCPRoute resources
- Information:
  - Name
  - Namespace
  - Parent gateways
  - Backend services
  - Status
- Note: Experimental API

**Priority**: P2 (Medium)

---

#### US-GW-014: List TLSRoutes
**As a** user  
**I want to** see all TLSRoutes  
**So that** I can understand TLS passthrough routing  

**Acceptance Criteria**:
- Display TLSRoute resources
- Information:
  - Name
  - Namespace
  - Hostnames (SNI)
  - Parent gateways
  - Backend services
  - Status
- Note: Experimental API

**Priority**: P2 (Medium)

---

#### US-GW-015: List UDPRoutes
**As a** user  
**I want to** see all UDPRoutes  
**So that** I can understand UDP routing  

**Acceptance Criteria**:
- Display UDPRoute resources
- Information:
  - Name
  - Namespace
  - Parent gateways
  - Backend services
  - Status
- Note: Experimental API

**Priority**: P3 (Future)

---

### 3.3 Cross-Namespace References

#### US-GW-020: List ReferenceGrants
**As a** user  
**I want to** see ReferenceGrants  
**So that** I can understand cross-namespace permissions  

**Acceptance Criteria**:
- Display ReferenceGrant resources
- Information:
  - Name
  - Namespace
  - From (allowed referencing resources)
  - To (allowed referenced resources)
- Highlight which routes use this grant

**Priority**: P2 (Medium)

---

### 3.4 Policies

#### US-GW-030: View BackendTLSPolicies
**As a** user  
**I want to** see backend TLS configurations  
**So that** I can verify backend encryption  

**Acceptance Criteria**:
- Display BackendTLSPolicy resources
- Information:
  - Name
  - Target reference
  - TLS configuration
  - CA certificates
  - Status
- Note: Experimental API

**Priority**: P3 (Future)

---

### 3.5 Visualization

#### US-GW-040: Route Visualization
**As a** user  
**I want** a visual representation of routing  
**So that** I can understand traffic flow  

**Acceptance Criteria**:
- Interactive graph showing:
  - GatewayClasses
  - Gateways
  - Routes (HTTP, gRPC, TCP, TLS)
  - Backend Services
  - Pods
- Edge annotations:
  - Hostnames
  - Paths
  - Ports
- Click to navigate to details
- Filter by namespace
- Highlight selected route's path

**Priority**: P2 (Medium)

---

## 4. Functional Requirements

### 4.1 Gateway Infrastructure

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-GW-01 | Plugin shall list GatewayClass resources | P0 | ✅ Complete |
| FR-GW-02 | Plugin shall list Gateway resources | P0 | ✅ Complete |
| FR-GW-03 | Plugin shall display listener configurations | P1 | ✅ Complete |
| FR-GW-04 | Plugin shall show gateway addresses | P1 | ✅ Complete |
| FR-GW-05 | Plugin shall display gateway conditions | P1 | ✅ Complete |
| FR-GW-06 | Plugin shall display GatewayClass details | P1 | ✅ Complete |
| FR-GW-07 | Plugin shall display Gateway details | P1 | ✅ Complete |
| FR-GW-08 | Plugin shall display Kubernetes events | P1 | ✅ Complete |

### 4.2 Route Management

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-RT-01 | Plugin shall list HTTPRoute resources | P0 | ✅ Complete |
| FR-RT-02 | Plugin shall display route rules and matches | P1 | ✅ Complete |
| FR-RT-03 | Plugin shall show backend references | P1 | ✅ Complete |
| FR-RT-04 | Plugin shall list GRPCRoute resources | P2 | ✅ Complete |
| FR-RT-05 | Plugin shall list TCPRoute resources | P2 | ✅ Complete |
| FR-RT-06 | Plugin shall list TLSRoute resources | P2 | ✅ Complete |
| FR-RT-07 | Plugin shall display HTTPRoute details | P1 | ✅ Complete |
| FR-RT-08 | Plugin shall display route filters | P1 | ✅ Complete |
| FR-RT-09 | Plugin shall display route timeouts | P1 | ✅ Complete |

### 4.3 Plugin Behavior

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-PLG-01 | Plugin shall detect Gateway API CRDs | P0 | ✅ Complete |
| FR-PLG-02 | Plugin shall distinguish standard vs experimental | P1 | ✅ Complete |
| FR-PLG-03 | Plugin shall gracefully handle missing CRDs | P1 | ✅ Complete |
| FR-PLG-04 | Plugin shall support namespace filtering | P0 | ✅ Complete |
| FR-PLG-05 | Plugin shall filter unnecessary annotations | P1 | ✅ Complete |

### 4.4 Policies and Cross-Namespace

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-POL-01 | Plugin shall list ReferenceGrant resources | P2 | ✅ Complete |
| FR-POL-02 | Plugin shall list BackendTLSPolicy resources | P3 | ✅ Complete |

---

## 5. Non-Functional Requirements

### 5.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-PERF-01 | Gateway list load time | < 2 seconds |
| NFR-PERF-02 | Route list load time | < 2 seconds |
| NFR-PERF-03 | Visualization render time | < 3 seconds |

### 5.2 Compatibility

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-COMP-01 | Gateway API v1 (standard) | Required |
| NFR-COMP-02 | Gateway API v1beta1 | Required |
| NFR-COMP-03 | Gateway API v1alpha2 (experimental) | Supported |

### 5.3 Usability

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-USE-01 | Find route for hostname | < 3 clicks |
| NFR-USE-02 | View gateway listeners | < 2 clicks |

---

## 6. Technical Considerations

### 6.1 Gateway API CRDs

#### Standard Channel (v1)
| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| GatewayClass | gateway.networking.k8s.io | v1 | Cluster |
| Gateway | gateway.networking.k8s.io | v1 | Namespaced |
| HTTPRoute | gateway.networking.k8s.io | v1 | Namespaced |
| ReferenceGrant | gateway.networking.k8s.io | v1 | Namespaced |

#### Experimental Channel (v1alpha2/v1beta1)
| Resource | API Group | API Version | Scope |
|----------|-----------|-------------|-------|
| GRPCRoute | gateway.networking.k8s.io | v1alpha2 | Namespaced |
| TCPRoute | gateway.networking.k8s.io | v1alpha2 | Namespaced |
| TLSRoute | gateway.networking.k8s.io | v1alpha2 | Namespaced |
| UDPRoute | gateway.networking.k8s.io | v1alpha2 | Namespaced |
| BackendTLSPolicy | gateway.networking.k8s.io | v1alpha2 | Namespaced |

### 6.2 Gateway Controllers

Common Gateway API implementations:
- **Istio**: istio.io/gateway-controller
- **Envoy Gateway**: gateway.envoyproxy.io/gatewayclass-controller
- **Contour**: projectcontour.io/gateway-controller
- **Traefik**: traefik.io/gateway-controller
- **NGINX Gateway Fabric**: gateway.nginx.org/nginx-gateway-controller
- **Cilium**: io.cilium/gateway-controller

### 6.3 Implementation Files

```
plugins/gateway_api/           # ✅ Fully implemented
├── __init__.py               # ✅ Blueprint routes with detail views
├── functions.py              # ✅ Complete API functions
│   ├── GatewayClass functions (list + detail)
│   ├── Gateway functions (list + detail)
│   ├── HTTPRoute functions (list + detail)
│   ├── GRPCRoute functions (list)
│   ├── TCPRoute functions (list)
│   ├── TLSRoute functions (list)
│   ├── ReferenceGrant functions (list)
│   ├── BackendTLSPolicy functions (list)
│   └── Events functions (for all resources)
└── templates/
    ├── gateway-api.html.j2           # ✅ Main view with tabs
    ├── gatewayclass-detail.html.j2   # ✅ GatewayClass detail view
    ├── gateway-detail.html.j2        # ✅ Gateway detail view
    └── httproute-detail.html.j2     # ✅ HTTPRoute detail view
```

### 6.4 Route Matching Logic

```python
def get_route_match_summary(match):
    """
    Summarize an HTTPRoute match for display.
    """
    parts = []
    
    if match.get('path'):
        path = match['path']
        path_type = path.get('type', 'PathPrefix')
        value = path.get('value', '/')
        parts.append(f"{path_type}: {value}")
    
    if match.get('headers'):
        for header in match['headers']:
            parts.append(f"Header: {header['name']}={header['value']}")
    
    if match.get('queryParams'):
        for qp in match['queryParams']:
            parts.append(f"Query: {qp['name']}={qp['value']}")
    
    if match.get('method'):
        parts.append(f"Method: {match['method']}")
    
    return " AND ".join(parts) if parts else "Match All"
```

---

## 7. User Interface Guidelines

### 7.1 GatewayClass List View

```
+--------------------------------------------------+
| Gateway API                                       |
+--------------------------------------------------+
| [GatewayClasses] [Gateways] [Routes] [Policies]  |
+--------------------------------------------------+
| GatewayClasses                                    |
+--------------------------------------------------+
| Name      | Controller                | Status   |
|-----------|---------------------------|----------|
| istio     | istio.io/gateway-ctrl    | ✅ Accepted|
| envoy     | gateway.envoyproxy.io/.. | ✅ Accepted|
+--------------------------------------------------+
```

### 7.2 Gateway List View

```
+--------------------------------------------------+
| Gateways                          [Namespace ▼]  |
+--------------------------------------------------+
| Name      | Class | Listeners        | Address   |
|-----------|-------|------------------|-----------|
| web-gw    | istio | http:80, https:443| 10.0.0.5 |
| api-gw    | envoy | https:443        | 10.0.0.6 |
+--------------------------------------------------+
```

### 7.3 HTTPRoute Detail View

```
+--------------------------------------------------+
| ← Back | HTTPRoute: api-route                    |
+--------------------------------------------------+
| Namespace: production                             |
| Gateways: web-gw, api-gw                         |
| Hostnames: api.example.com, www.example.com      |
+--------------------------------------------------+
| Rules:                                            |
+--------------------------------------------------+
| Rule 1                                            |
| Match: PathPrefix: /api/v1                        |
| Backends:                                         |
|   - api-service:8080 (weight: 100)               |
+--------------------------------------------------+
| Rule 2                                            |
| Match: PathPrefix: /api/v2                        |
| Backends:                                         |
|   - api-v2-service:8080 (weight: 90)             |
|   - api-v2-canary:8080 (weight: 10)              |
+--------------------------------------------------+
```

### 7.4 Route Visualization

```
+--------------------------------------------------+
| Route Visualization                [Namespace ▼] |
+--------------------------------------------------+
|                                                  |
|  [GatewayClass: istio]                          |
|         |                                        |
|         v                                        |
|  +-------------+                                 |
|  | Gateway:    |                                 |
|  | web-gw      |                                 |
|  | :80, :443   |                                 |
|  +-------------+                                 |
|    |         |                                   |
|    v         v                                   |
| /api/*    /web/*                                 |
|    |         |                                   |
|    v         v                                   |
| [api-svc] [web-svc]                             |
|                                                  |
+--------------------------------------------------+
```

---

## 8. Dependencies

### 8.1 Internal Dependencies

- Kubernetes library (CustomObjects API)
- Plugin framework
- Visualization library (Cytoscape.js)

### 8.2 External Dependencies

- Gateway API CRDs installed
- Gateway controller deployed (Istio, Envoy, etc.)

### 8.3 RBAC Requirements

```yaml
- apiGroups: ["gateway.networking.k8s.io"]
  resources: ["gatewayclasses", "gateways", "httproutes", "grpcroutes", 
              "tcproutes", "tlsroutes", "udproutes", "referencegrants",
              "backendtlspolicies"]
  verbs: ["get", "list"]
```

---

## 9. Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Gateway API not installed | High | Medium | Detect CRDs, disable plugin gracefully |
| API version differences | Medium | High | Support multiple versions |
| Controller-specific features | Medium | Medium | Focus on standard resources |
| Complex route configurations | Low | Medium | Clear visualization, simplification |

---

## 10. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Plugin adoption | 60% of Gateway API users | Feature analytics |
| Route debugging time | -50% vs kubectl | User research |
| Feature completeness | 80% of standard resources | Feature coverage |

---

## 11. Future Considerations

### 11.1 Potential Enhancements

1. **Route Creation**: Create HTTPRoutes via UI
2. **Traffic Splitting**: Visual canary/A-B testing configuration
3. **Policy Management**: Create and apply policies
4. **Metrics Integration**: Show route-level traffic metrics
5. **Certificate Management**: Manage TLS certificates for gateways
6. **Multi-Gateway**: Cross-gateway route management

### 11.2 Out of Scope (This Version)

- Route creation/modification
- Gateway provisioning
- Certificate management
- Policy creation
- Traffic metrics (requires Prometheus)
- Route visualization/graph view
- UDPRoute support (low priority)

### 11.3 MVP Implementation Summary (Completed December 2025)

**Core Features Delivered:**
- ✅ Complete GatewayClass management (list + detail views)
- ✅ Complete Gateway management (list + detail views with listeners)
- ✅ Complete HTTPRoute management (list + detail views with rules)
- ✅ Experimental route types support (GRPCRoute, TCPRoute, TLSRoute)
- ✅ ReferenceGrant and BackendTLSPolicy support
- ✅ Kubernetes Events integration for all detail views
- ✅ CRD detection and graceful degradation
- ✅ Namespace filtering
- ✅ Status indicators and condition display
- ✅ Annotations filtering (removes system annotations)
- ✅ Menu integration

**Technical Implementation:**
- ✅ Standard Gateway API v1 support
- ✅ Experimental Gateway API v1alpha2 support
- ✅ DataTables integration for sorting/searching
- ✅ Responsive UI with Bootstrap 5
- ✅ Error handling and empty state management
- ✅ UID-based event matching for accuracy

---

## 12. Plugin Configuration

```ini
# kubedash.ini
[plugin_settings]
gateway_api = true  # Enable Gateway API plugin
```

---

*Document Owner: Product Management*  
*Stakeholders: Engineering, Network, Platform*
