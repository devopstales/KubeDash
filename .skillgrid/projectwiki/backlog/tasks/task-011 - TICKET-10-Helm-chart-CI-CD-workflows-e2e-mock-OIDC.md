---
id: TASK-011
title: 'TICKET-10: Helm chart + CI/CD workflows + e2e mock OIDC'
status: Done
assignee:
  - '@paladm'
created_date: '2026-10-17 13:00'
updated_date: '2026-10-17 19:18'
labels: []
milestone: m-0
dependencies:
  - TASK-010
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: medium
type: feature
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: charts/kubedash (Chart, values §7.2 subset + the two §7.5 tuning keys, Deployment with Downward-API KUBEDASH_REPLICA_ID + KUBEDASH_ROLE=leader + GUNICORN_WORKERS/THREADS + tuning env, Service, ConfigMap, Secret), ci.yaml (backend/frontend/cli/chart/image+Trivy/actionlint), e2e.yaml (kind + helm + oidc-mock + Playwright), e2e/oidc-mock.py, test_chart.py template assertions. Current: no chart/CI. Expected: chart lints+renders with the replica-id wiring; CI green on the branch.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/test_chart.py green (fieldRef metadata.name; KUBEDASH_ROLE=leader; issuer/clientId/image rendered; gunicorn 8/3; two tuning keys); helm lint + helm template exit 0; both workflows pass actionlint; ci.yaml green on branch (record if CI cannot run locally)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R6 chart half + R8 met; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. charts/kubedash/{Chart.yaml,values.yaml,templates/*}
2. .github/workflows/ci.yaml + e2e.yaml + e2e/oidc-mock.py
3. backend/tests/test_chart.py (template assertions)
4. pytest + helm lint/template + actionlint green; commit (Refs: TASK-010)
<!-- SECTION:PLAN:END -->
