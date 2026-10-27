---
id: TASK-045
title: >-
  [FEATURE] TICKET-05 wsgi.py: pgqueue worker + leader-gated reaper, replace RQ
  (backend-wsgi)
status: To Do
assignee: []
created_date: '2026-10-27 19:15'
updated_date: '2026-10-27 19:16'
labels: []
milestone: m-2
dependencies:
  - TASK-043
references:
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/briefing.md
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/blueprint.md
  - .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/tasks.md
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/acceptance.feature
documentation:
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/blueprint.md
priority: high
type: feature
ordinal: 41000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The tracer-thread end: replace the RQ scheduler/worker child with the pgqueue poll loop (ADR-0029). Current State: wsgi.py uses RQ + a worker child process. Expected State: _run_once enqueues due tasks via pgqueue.enqueue only while leader.is_leader() (preserve INTERVALS + role gate); _worker_loop pgqueue.claims every 5s, runs the task, complete/fails it; a leader-gated reaper sweeps pgqueue.reap + revocation.reap_expired + kvstore.kv_reap. Update tests/test_worker_gate.py: keep the _FakeLeader + role-gate tests, point the scheduler seam at a pgqueue-shaped fake (enqueue(path, engine)), re-point the integration job-runs test to the pgqueue claim path (no Redis).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the scheduler enqueues due tasks only when leading (the existing test_schedule_if_leader_* shape against a pgqueue-shaped seam)
- [ ] #2 the leader role still spawns the kubedash-worker daemon thread (no RQ child)
- [ ] #3 a job enqueued while leading executes via the pgqueue claim (integration)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 wsgi no longer imports rq
<!-- DOD:END -->
