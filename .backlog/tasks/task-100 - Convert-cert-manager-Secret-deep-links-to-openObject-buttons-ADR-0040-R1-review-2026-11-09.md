---
id: TASK-100
title: >-
  Convert cert-manager Secret deep-links to openObject buttons (ADR-0040 R1,
  review 2026-11-09)
status: To Do
assignee: []
created_date: '2026-11-09 08:21'
updated_date: '2026-11-09 09:51'
labels: []
dependencies: []
ordinal: 96000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Parked from the 2026-11-09 three-axis review of the network views (xarchive): CertManager.tsx:353-357 and CertManagerData.tsx:270-274 render <Link to='/security/secret/data?name=...&namespace=...'> — object identity in the URL, the superseded contract. House pattern: openObject button (ServiceAccounts.tsx:93). Parked because both files carry uncommitted in-flight kind-registry WIP; fix after that lands. Review record: .skillgrid/xarchive/2026-10-29-certmanager-external-loadbalancer-views/review.md
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
