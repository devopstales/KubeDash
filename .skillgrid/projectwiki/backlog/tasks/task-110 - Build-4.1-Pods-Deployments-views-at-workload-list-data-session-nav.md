---
id: TASK-110
title: 'Build 4.1 Pods + Deployments views at /workload (list + data, session nav)'
status: In Progress
assignee: []
created_date: '2026-11-17 08:58'
updated_date: '2026-11-17 08:59'
labels: []
dependencies: []
priority: high
type: feature
ordinal: 99000
---

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 R1-R9 of 2026-10-28-pods-deployments-views: pods list (Pod List card), pod data 5 tabs, deployments list (Deployments List), deployment data 6 tabs, ObjectRoute+OldDataRedirect, stubs removed, e2e+vitest green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 QA report PASS + review record + shipped to change-archive
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Backend: get_pod/get_deployment 0/1-list + list_deployments + _KINDS/_GETTERS (done) 2. Frontend: Pods/PodData views (done) 3. Frontend: Deployments/DeploymentData views 4. App.tsx ObjectRoute blocks + stub removal + e2e 5. vitest + fe-build + fe-check + backend suite + ruff/mypy 6. QA report 7. review 8. ship
<!-- SECTION:PLAN:END -->
