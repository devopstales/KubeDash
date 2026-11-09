---
id: TASK-101
title: >-
  Rename registry kind bgppeers to bgppeer (glossary singular-slug, review
  2026-11-09)
status: To Do
assignee: []
created_date: '2026-11-09 08:21'
updated_date: '2026-11-09 09:51'
labels: []
dependencies: []
ordinal: 97000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Parked from the 2026-11-09 network-views review: the ref/tab kind 'bgppeers' (plural) drifts from the glossary Registry-kind singular-slug convention; siblings are singular (ipaddresspool, l2advertisement, bgpadvertisement). Files: frontend/src/App.tsx:333, views/Network/ExternalLoadBalancer.tsx:149,240,283, ExternalLoadBalancerData.tsx:59-65. REST route key 'bgppeers' stays. Parked: files carry in-flight WIP. Review record: same review.md.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
