---
id: TASK-102
title: >-
  Write audit rows for POST /resources/apply (first generic cluster write path,
  review 2026-11-09)
status: To Do
assignee: []
created_date: '2026-11-09 08:21'
updated_date: '2026-11-09 09:51'
labels: []
dependencies: []
ordinal: 98000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Parked from the 2026-11-09 network-views security axis (Low, Confirmed): POST /api/v1/clusters/<id>/resources/apply is the first generic cluster write path and writes no AuditLog row (CWE-778). Repo precedent is split (permission.py writes audit rows; create/delete_namespace don't). Suggested fix: one AuditLog row per request (action='resource.apply', actor_sub=g.current_user.sub, target=kind/name list, cluster, namespace). Spec-silent → deferred, not fixed at the review gate.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
