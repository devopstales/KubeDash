---
id: TASK-069
title: >-
  Build Ingress + Gateway API views at /network/ingress + /network/gateway-api
  (4.1 port + converter + apply, nav leaf added, ingress stub removed)
status: In Progress
assignee:
  - '@paladm'
created_date: '2026-11-06 12:14'
updated_date: '2026-11-06 12:15'
labels: []
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-ingress-gateway-api-views/
ordinal: 65000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
User report 2026-11-06: the Network sidebar is incomplete. Spec 2026-10-28-ingress-gateway-api-views was executed 2026-11-05 backend-only (1b2214bf ingresses + gateway api kinds, b29f97ac convert endpoint + apply_objects service); the frontend was never built and the POST /resources/apply API route (blueprint Task 6) was never committed. Execute the remaining frontend tasks (blueprint Tasks 3, 4, 7) + the apply route (Task 6 step 4 + tests) against the ADR-0040 session-object-navigation contract (supersedes the blueprint query-param shape per the spec NAVIGATION-SUPERSEDED.md): one route per kind, no /data routes, ObjectRoute + openObject; the four-tab Gateway API page uses a multi-kind dispatcher (NetworkPolicyRoute pattern) and its GatewayClasses tab links to the standalone /network/gateway-class route.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Ingress list view at /network/ingress: card title EXACTLY "Ingress List", columns Name/IngressClass/Hostname (hosts joined with ", "), ADR-0040 name cell; /network/ingress removed from Stub/routes.ts and added to Stub.test.tsx viewPaths
- [ ] #2 Ingress data view: CTable (Name/IngressClass/Created/Labels/Annotations) + Rules table (Host/Path/PathType/Service/Port/TLS) + JSON block + "Convert to Gateway API" entry point; miss renders "No Ingress '<name>' found"
- [ ] #3 Gateway API tabbed page at /network/gateway-api: four CTab KubeDataTables (GatewayClasses Name/Controller/Age; Gateways Name/GatewayClass/Listeners; HTTPRoutes Name/Hostnames/ParentRefs; ReferenceGrants Name/From/To); CRD-absent per-tab empty state; GatewayClasses name cell opens the standalone /network/gateway-class route detail
- [ ] #4 Gateway API data view: kind-dispatched CTable + Labels/Annotations + JSON block; bad kind renders an error line; not-found pinned states
- [ ] #5 Converter UI on the Ingress data page: provider select (envoy/traefik), Convert calls POST /gateway-api/convert (resources rendered as YAML + warnings line), Apply calls POST /resources/apply (per-object result; Gateway API tab queries invalidated)
- [ ] #6 POST /api/v1/clusters/<id>/resources/apply route added (SAR create per object, all-or-nothing SAR phase, 200 with errors array on partial failure) + API tests
- [ ] #7 "Gateway API" leaf added to _nav.tsx Network group after the Ingress leaf; vitest green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Backend: POST /resources/apply route (apply_objects exists; SAR per object atomic; 200 partial-failure) + tests. 2. Types (IngressItem, GatewayItem, HTTPRouteItem, ReferenceGrantItem, ConvertedResource). 3. Ingress list + data (4.1 port, Rules table, trim annotations per 2026-11-05 T2 override). 4. Gateway API 4-tab page + kind-dispatched data (NetworkPolicyRoute dispatcher pattern). 5. GatewayConverter modal (convert endpoint, YAML tabs, warnings, apply, query invalidation). 6. Routes + nav leaf + stub removal + viewPaths. 7. Tests. 8. Verify: backend unit, vitest, fe-build, fe-check.
<!-- SECTION:PLAN:END -->
