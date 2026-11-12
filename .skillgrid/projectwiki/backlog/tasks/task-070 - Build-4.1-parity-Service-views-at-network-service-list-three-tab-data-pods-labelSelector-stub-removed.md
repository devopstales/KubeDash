---
id: TASK-070
title: >-
  Build 4.1-parity Service views at /network/service (list + three-tab data,
  pods labelSelector, stub removed)
status: In Progress
assignee:
  - '@paladm'
created_date: '2026-11-06 15:38'
labels:
  - feature
dependencies: []
references:
  - .skillgrid/specs/2026-10-28-service-views/
ordinal: 66000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
User request 2026-11-06: execute the /network specs. Spec 2026-10-28-service-views executed 2026-11-06: backend (services kind + pods labelSelector param) by a dedicated agent; this task owns the frontend (blueprint Tasks 2-4) executed against the ADR-0040 session-object-navigation contract (supersedes the blueprint query-param shape per the spec NAVIGATION-SUPERSEDED.md): one route per kind, no /data routes, ObjectRoute + openObject.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 #1 Service list view at /network/service: card title EXACTLY 'Service List', columns Name/Type/Cluster IP/External IP; External IP is LoadBalancer-only (status.load_balancer.ingress[0].ip else —); name cell opens detail via ADR-0040 object ref (no query string); /network/service removed from Stub/routes.ts and added to Stub.test.tsx viewPaths
- [ ] #2 #2 Service data view (three CTabs): Service tab CTable (Name/Type/Created/Annotations verbatim/Labels/Cluster IP/External IP) + full-object JSON block; Ports tab per-port rows (Name/Port/Protocol/Target/Node Port, 'No ports' when absent)
- [ ] #3 #3 Pods tab: SECOND fetch on the pods route with ?labelSelector= built from spec.selector ONLY when non-empty (no fetch on empty selector); rows Status badge/Name/IP/Node/Owner (kind lowercase + / + name); 'No pods match this service's selector' muted state
- [ ] #4 #4 Pinned states: 'No Service \'<name>\' found' (state, not error), 'No cluster selected.', 'No services found'; backend ?labelSelector= pass-through verified by API tests
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
1. Read spec + ADR-0040 contract + in-tree patterns (Secret/SecretData, IngressClass). 2. Types (ServicePort, ServiceItem, Pod extension) in lib/types.ts. 3. Service list view (openObject name cell). 4. ServiceData three-tab view (props from ObjectRoute; conditional pods query). 5. App.tsx ObjectRoute wiring (no /data route) + stub removal + viewPaths. 6. Tests cloned from secrets patterns. 7. Verify: vitest targeted + full (12 baseline failures only), fe-build, fe-check, backend unit.
<!-- SECTION:PLAN:END -->
