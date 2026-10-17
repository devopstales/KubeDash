---
id: TASK-006
title: 'TICKET-05: RBAC SAR service + generic pod list + kind integration tier'
status: To Do
assignee: []
created_date: '2026-10-17 12:58'
labels: []
milestone: m-0
dependencies:
  - TASK-005
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: high
type: feature
ordinal: 6000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: services/rbac.py can() via SelfSubjectAccessReview (ADR-0004, 30s Redis cache, _sar_allowed seam), ResourceApi generic list with _KINDS table (pods wired), kind fixtures (session create + per-test-file boundary, kind_client), integration tests. Current: no resource access. Expected: bound users list pods from a real cluster; SAR denial 403s with the stable code.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/services/test_rbac.py tests/api/test_resources.py -m 'not integration' green (unknown kind 404, unbound 404, cache-hit never reaches pool); with kind: -m integration green (test pod listed; SAR-denied user 403 RBAC_DENIED)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R4 + R10 acceptance met; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. app/services/rbac.py can() + _sar_allowed seam
2. app/schemas/resource.py + app/api/resources.py ResourceApi (_KINDS pods); register
3. tests/conftest.py kind fixtures (session create + module boundary + kind_client)
4. tests/services/test_rbac.py + tests/api/test_resources.py (unit + integration)
5. pytest green both tiers (integration if kind available); commit (Refs: TASK-005)
<!-- SECTION:PLAN:END -->
