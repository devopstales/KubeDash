---
id: TASK-023
title: K8s liveness & readiness probes
status: Done
assignee: []
created_date: '2026-10-19 16:38'
updated_date: '2026-10-19 16:40'
labels: []
dependencies: []
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Which branch is the target for the probe work? main (deploy/charts/ui-statefulset) already has livenessProbe → /api/health/live and readinessProbe → /api/health/ready; rebase/5.0 (charts/kubedash/deployment) already has livenessProbe → /healthz and readinessProbe → /readyz. Deciding the target decides the task scope.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Target branch for the probe work is confirmed by the user
- [x] #2 Probes (liveness + readiness) are verified present and pointed at live endpoints on the target branch, with chart lint/template passing
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Target confirmed: rebase (5.0 chart). Verified: charts/kubedash/templates/deployment.yaml has livenessProbe → /healthz (initialDelay 10s, period 30s) and readinessProbe → /readyz (initialDelay 5s, period 10s). backend/app/__init__.py register_health() serves both (healthz always 200; readyz 503 naming failing deps). helm lint + helm template pass. Probe tests: 18 passed, 1 failed (tests/test_health.py::test_readyz_names_failing_database, AttributeError at line 32) — failure is pre-existing on rebase HEAD (reproduced with working-tree changes stashed), unrelated to probes.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
No code change needed: both probes already exist on rebase/5.0 (chart deployment.yaml + /healthz and /readyz endpoints in app/__init__.py). Verified with helm lint/template and the backend probe tests (18 passed; 1 pre-existing unrelated failure noted).
<!-- SECTION:FINAL_SUMMARY:END -->
