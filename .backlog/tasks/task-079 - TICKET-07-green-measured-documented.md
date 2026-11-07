---
id: TASK-079
title: 'TICKET-07: green, measured, documented'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:11'
labels: []
milestone: m-4
dependencies:
  - TASK-078
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-kind-catalog/briefing.md
priority: high
type: feature
ordinal: 75000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Kind Catalog (2026-11-07-kind-catalog, ADR-0041): blueprint Task 7: run the full floor; prove the interface shrank — `grep -c " def list_\| def get_" backend/app/services/k8s_client.py` → only the 4 external-LB override pairs + `list_events` remain, `wc -l` recorded; re-run `npx jscpd --health --reporters ai .` and record the new health score + `k8s_client.py`/`test_resources.py` complexity vs the 2026-11-07 baseline (health 32/E; `k8s_client` cx 393/2,487L; `test_resources` cx 307/3,938L); **add** (not modify) the read-path section to `.skillgrid/ARCHITECTURE.md` — the as-built catalog + engine + five concepts, ADR-0010's informer cache noted as the planned replacement — plus the kind-addition procedure (one catalog row + one fixture entry); commit with the measurement numbers in the body.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 full floor green; the grep count assertion holds; the measurement numbers are in the commit body; `ARCHITECTURE.md` contains the read-path section + kind-addition procedure.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: green-and-measured
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: blueprint Task 7: run the full floor; prove the interface shrank — `grep -c " def list_\| def get_" backend/app/services/k8s_client.py` → only the 4 external-LB override pairs + `list_events` remain, `wc -l` recorded; re-run `npx jscpd --health --reporters ai .` and record the new health score + `k8s_client.py`/`test_resources.py` complexity vs the 2026-11-07 baseline (health 32/E; `k8s_client` cx 393/2,487L; `test_resources` cx 307/3,938L); **add** (not modify) the read-path section to `.skillgrid/ARCHITECTURE.md` — the as-built catalog + engine + five concepts, ADR-0010's informer cache note. 2: verify per Acceptance: full floor green; the grep count assertion holds; the measurement numbers are in the commit body; `ARCHITECTURE.md` contains the read-path section + kind-addition procedure.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
