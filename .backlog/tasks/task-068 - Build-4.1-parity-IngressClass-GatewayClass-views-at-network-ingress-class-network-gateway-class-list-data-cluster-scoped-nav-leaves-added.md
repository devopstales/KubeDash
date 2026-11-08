---
id: TASK-068
title: >-
  Build 4.1-parity IngressClass + GatewayClass views at /network/ingress-class +
  /network/gateway-class (list + data, cluster-scoped, nav leaves added)
status: Done
assignee:
  - '@paladm'
created_date: '2026-11-06 12:14'
updated_date: '2026-11-06 15:02'
labels: []
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-ingressclass-gatewayclass-views/
ordinal: 64000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
User report 2026-11-06: the Network sidebar is missing the Ingress Class (ingress controller) menu. Spec 2026-10-28-ingressclass-gatewayclass-views was executed 2026-11-05 backend-only (f6e0d56f); the frontend was never built. Execute the frontend tasks (blueprint Tasks 2-4) against the ADR-0040 session-object-navigation contract (supersedes the blueprint query-param shape per the spec NAVIGATION-SUPERSEDED.md): one route per kind, no /data routes, ObjectRoute + openObject.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 IngressClass list view at /network/ingress-class: card title EXACTLY "IngressClass List", columns Name/Controller/Created, name cell opens detail via ADR-0040 object ref (no query string)
- [x] #2 IngressClass data view: CTable (Name/Created/Controller/Labels/Annotations) + Parameters table (Kind/Name/API Version, "No parameters" when absent) + full-object JSON block; miss renders "No IngressClass '<name>' found" (state, not error)
- [x] #3 GatewayClass list view at /network/gateway-class: card title EXACTLY "GatewayClass List", columns Name/Controller/Age; CRD-absent renders "No gateway classes found"
- [x] #4 GatewayClass data view: CTable (Name/Controller/Created/Labels/Annotations) + JSON block; miss/CRD-absent renders "No GatewayClass '<name>' found"
- [x] #5 Both leaves added to _nav.tsx Network group after the Ingress leaf; both paths in Stub.test.tsx viewPaths; vitest green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read spec (briefing/blueprint/adr + NAVIGATION-SUPERSEDED) + ADR-0040 contract. 2. Types (IngressClassItem, GatewayClassItem) in lib/types.ts. 3. Views cloned from Storage/StorageClass.tsx + StorageClassData.tsx patterns (cluster-scoped, no namespace). 4. App.tsx ObjectRoute wiring (one clean route per kind, no /data). 5. _nav.tsx two leaves after Ingress. 6. Stub.test.tsx viewPaths. 7. Tests cloned from storage test patterns. 8. Verify: vitest targeted, fe-build, fe-check.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Verification 2026-11-06: targeted vitest 19/19 (ingressclasses, ingressclass_data, gatewayclasses, gatewayclass_data); fe-build (tsc+eslint+vite) green; fe-check (air-gap) green; backend unit floor 677/677. Nav leaves present (_nav.tsx Network group); Stub.test viewPaths carry both paths.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Frontend for the 2026-10-28-ingressclass-gatewayclass-views spec completed (commit 9af4eeb9): IngressClass + GatewayClass list/data views (cluster-scoped, ADR-0040 ObjectRoute, no /data routes), _nav.tsx leaves + Stub.test viewPaths. Verified: targeted vitest 19/19, fe-build, fe-check, backend unit 677/677.
<!-- SECTION:FINAL_SUMMARY:END -->
