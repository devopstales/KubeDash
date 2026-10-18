---
id: TASK-008
title: 'TICKET-07: Leader-gated RQ worker + real cluster_sync/health tasks'
status: Done
assignee:
  - '@paladm'
created_date: '2026-10-17 12:59'
updated_date: '2026-10-17 16:51'
labels: []
milestone: m-0
dependencies:
  - TASK-003
  - TASK-005
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: medium
type: feature
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: wsgi.py RQ worker thread (leader-checked scheduler loop over INTERVALS, work(timeout=5)) + real tasks/health.py and tasks/cluster_sync.py probe implementations (exception-safe, last_probe_at). Current: worker/tasks are stubs. Expected: exactly the leader schedules+runs jobs; a follower promotes within one poll and resumes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/test_worker_gate.py tests/tasks/ green: follower no worker thread; leader candidate daemon thread; enqueued app.tasks.health.run executes via work_one(); health marks unreachable down (exception caught) and live up with last_probe_at set
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: blueprint Task 7 + threat-matrix process-integration row met; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. wsgi.py: Leader start + rq.Worker thread + leader-checked INTERVALS scheduler loop
2. app/tasks/health.py + cluster_sync.py real probe implementations
3. tests/test_worker_gate.py (gate + job execution) + tests/tasks/test_health.py
4. pytest green; commit (Refs: TASK-003, TASK-005)
<!-- SECTION:PLAN:END -->
