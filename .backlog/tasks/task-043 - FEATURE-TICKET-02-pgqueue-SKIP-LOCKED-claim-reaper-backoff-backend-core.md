---
id: TASK-043
title: '[FEATURE] TICKET-02 pgqueue: SKIP LOCKED claim, reaper, backoff (backend-core)'
status: To Do
assignee: []
created_date: '2026-10-27 19:15'
updated_date: '2026-10-27 19:16'
labels: []
milestone: m-2
dependencies:
  - TASK-042
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
ordinal: 39000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Postgres task queue core (ADR-0029). Current State: tasks run on RQ/Redis. Expected State: app/core/pgqueue.py with enqueue, claim (atomic FOR UPDATE SKIP LOCKED), complete, fail (re-queue with LEAST(cap, base*5^attempts) backoff, dead-letter at attempts>=3), reap (re-queue stale processing rows), backoff_seconds. Pure SQLAlchemy text(); no Flask imports. Reaper interval constant (>2min) > longest task runtime (findings #6).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 enqueue then claim returns the path and sets the row processing/locked_by
- [ ] #2 10 concurrent claimers on 50 rows -> exactly 10 distinct claims, 0 double-claimed
- [ ] #3 a failing task retries 3x with the backoff curve then status=failed (dead-letter)
- [ ] #4 a processing row with locked_at older than the reaper interval is re-queued by reap
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Reaper interval constant >2min exceeds the longest task runtime (findings #6)
<!-- DOD:END -->
