---
id: TASK-007
title: 'TICKET-06: ADR-pointing stub surface + file-map guard'
status: To Do
assignee: []
created_date: '2026-10-17 12:59'
labels: []
milestone: m-0
dependencies:
  - TASK-003
  - TASK-004
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: medium
type: feature
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: every remaining backend/app/ path from ARCHITECTURE.md §2 as an ADR-pointing stub (10 API stubs incl. scim/, 5 model stubs, 10 service stubs, 4 task stubs, sockets/logs, aggregated/ service layer, api/kubectl_auth.py + schemas/kubectl_auth.py for the in-flight plugin change), app/api/_authhook.py apply_auth, parametrized file-map guard, 501 stub route tests. Current: ARCHITECTURE.md §2 map has no code. Expected: the file map is honest; the in-flight kubectl-oidc-plugin change has its registration point.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/test_file_map.py tests/api/test_stubs.py green: every §2 backend/app/ path exists; /api/v1/logs/query + /metrics/query + /traces -> 501 NOT_IMPLEMENTED with JWT
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R9 acceptance met; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. app/api/_authhook.py apply_auth (extracted Task 3 pattern)
2. Stub APIs (logs/metrics/traces/audit/permissions/namespaces/access/kubeconfig/admin + scim/ + kubectl_auth) each with @blp.route 501
3. Stub models/services/tasks/sockets/aggregated per blueprint Task 6 patterns
4. tests/test_file_map.py (EXPECTED list incl. aggregated/ + kubectl_auth) + tests/api/test_stubs.py
5. pytest green; commit (Refs: TASK-003, TASK-004)
<!-- SECTION:PLAN:END -->
