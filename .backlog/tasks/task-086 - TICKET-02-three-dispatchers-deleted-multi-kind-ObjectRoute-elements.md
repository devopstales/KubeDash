---
id: TASK-086
title: 'TICKET-02: three dispatchers deleted: multi-kind ObjectRoute elements'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-6
dependencies:
  - TASK-085
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/briefing.md
priority: high
type: refactor
ordinal: 82000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Navigation Seam (2026-11-07-navigation-seam): in `App.tsx`, the three route blocks become single `ObjectRoute` elements — `/security/network-policy` → `kinds={['NetworkPolicy','CiliumNetworkPolicy','CiliumClusterwideNetworkPolicy']}` with `detail` switching on `p.kind`; `/network/ingress` → `kinds={['ingress','gateway','httproute','referencegrant']}` with `detail` switching ingress vs GatewayApi; `/network/ingress-class` → `kinds={['ingressclass','gatewayclass']}` with `detail` switching — the three dispatcher components deleted, `listRoute` sourced from B's `KINDS` route data; the cert-manager/external-LB components untouched (B's scope decision); regression tests per converted route (the tabbed list renders once, a ref of each kind renders the right detail, a foreign-kind ref renders the list) + the relay-consumption delta mount test (seed the relay + one-shot meta, mount a converted route element, assert the detail renders AND the relay self-deletes — mirroring `object_route.test.tsx:64-89`) + one `OldDataRedirect` `kindFromParam` unit test (fallback kind → detail; foreign `?kind=` → list).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test && task fe-build && task fe-check` exit 0 and `grep -rln "NetworkPolicyRoute\|IngressRoute\b\|IngressClassRoute" frontend/src` → zero hits (the components are gone; the cert-manager/ELB test mirrors are untouched).
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: the three in-scope dispatchers collapse into single ObjectRoute elements; a ref of each converted kind renders the right detail; cert-manager and external-LB dispatchers stay hand-rolled after the conversion; the kindFromParam legacy redirect is unchanged; a foreign kind param on the legacy redirect renders the list; a deep link to a converted multi-kind route consumes the relay on mount
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: in `App.tsx`, the three route blocks become single `ObjectRoute` elements — `/security/network-policy` → `kinds={['NetworkPolicy','CiliumNetworkPolicy','CiliumClusterwideNetworkPolicy']}` with `detail` switching on `p.kind`; `/network/ingress` → `kinds={['ingress','gateway','httproute','referencegrant']}` with `detail` switching ingress vs GatewayApi; `/network/ingress-class` → `kinds={['ingressclass','gatewayclass']}` with `detail` switching — the three dispatcher components deleted, `listRoute` sourced from B's `KINDS` route data; the cert-manager/external-LB components untouched (B's scope . 2: verify per Acceptance: `corepack pnpm test && task fe-build && task fe-check` exit 0 and `grep -rln "NetworkPolicyRoute\|IngressRoute\b\|IngressClassRoute" frontend/src` → zero hits (the components are gone; the cert-manager/ELB test mirrors are untouched).. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
