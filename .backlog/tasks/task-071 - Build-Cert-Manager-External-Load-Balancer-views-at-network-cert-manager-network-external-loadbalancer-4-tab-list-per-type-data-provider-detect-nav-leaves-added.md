---
id: TASK-071
title: >-
  Build Cert-Manager + External Load Balancer views at /network/cert-manager +
  /network/external-loadbalancer (4-tab list + per-type data, provider-detect,
  nav leaves added)
status: In Progress
assignee:
  - '@paladm'
created_date: '2026-11-06 15:43'
labels:
  - feature
dependencies: []
references:
  - .skillgrid/specs/2026-10-29-certmanager-external-loadbalancer-views/
ordinal: 67000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
User request 2026-11-06: execute the /network specs. Spec 2026-10-29-certmanager-external-loadbalancer-views: backend (8 CRD kinds, provider-detection) executed 2026-11-06 by a dedicated agent; this task owns the frontend (blueprint Tasks 3-5) executed against the ADR-0040 session-object-navigation contract (the spec predates its supersedure; query-param ?type=&name= navigation maps to the multi-kind dispatcher: registry kinds clusterissuer/issuer/certificaterequest/certificate + ipaddresspool/l2advertisement/bgppeer/bgpadvertisement; no /data routes).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 #1 /network/cert-manager: four CTabs (Cluster Issuer/Issuer/Certificate Request/Certificates), card title EXACTLY 'Cert-Manager Objects'; Status badge (last status.conditions[] reason, green when status==True else red); name cells open per-type detail via ADR-0040 object refs (multi-kind dispatcher route, no /data route); CRD-absent per-tab empty state; Certificates Secret cell deep-links to /security/secret
- [ ] #2 #2 Cert-Manager data view: per-type metadata CTable (the 4.1 row set per type) + full-object JSON block; 'No <type> \'<name>\' found' not-found state
- [ ] #3 #3 /network/external-loadbalancer: four CTabs (IP Address Pools/L2 Advertisements/BGP Peers/BGP Advertisements), card title 'LoadBalancer Objects'; Type column = the provider field (metallb/cilium); name cells open per-type detail via ADR-0040 refs; both-providers-absent empty state
- [ ] #4 #4 External LB data view: per-type + provider-specific metadata CTable + JSON block; not-found pinned states
- [ ] #5 #5 Nav: 'Cert-Manager' + 'External Load Balancer' leaves ADDED to the Network group (Beta badge, no Plugins group); both paths in Stub.test.tsx viewPaths; floor green (vitest 12 baseline failures only, fe-build, fe-check, backend unit)
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
1. Read spec + ADR-0040 dispatcher pattern (NetworkPolicyRoute) + VPA tabbed-page patterns. 2. Types (4 cert-manager + 4 external-LB with provider) in lib/types.ts. 3. CertManager 4-tab list + per-type data (dispatcher). 4. ExternalLoadBalancer 4-tab list + per-type data (dispatcher). 5. App.tsx two dispatcher routes + nav leaves + viewPaths. 6. Tests cloned from VPA/Gateway-API tabbed patterns. 7. Verify: vitest targeted + full (12 baseline failures only), fe-build, fe-check, backend unit.
<!-- SECTION:PLAN:END -->
