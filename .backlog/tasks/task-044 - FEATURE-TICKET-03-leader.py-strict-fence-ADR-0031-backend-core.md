---
id: TASK-044
title: '[FEATURE] TICKET-03 leader.py strict fence (ADR-0031) (backend-core)'
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
ordinal: 40000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The cross-node LWW tiebreaker (ADR-0031). Current State: leader election is advisory-lock + lease row; the advisory lock is session-local, not a cross-node mutex. Expected State: leader_lease.fence is monotonic; acquire (the lease upsert) becomes INSERT ... fence=fence+1 ... ON CONFLICT DO UPDATE ... RETURNING fence; the stale check stays a fast path but the fence is authoritative; _heartbeat conditions WHERE id=1 AND replica_id=:rid AND fence=:f and demotes on 0 rows; Leader.fence is exposed. A fenced-out leader's write affects 0 rows and it demotes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 after A acquires (fence 1) and B acquires (fence 2), A's stale-fence heartbeat affects 0 rows and A demotes
- [ ] #2 a fenced write (WHERE fence=:my_fence) from the stale leader is rejected (0 rows) while the current holder's write commits (1 row)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Every leader write is fenced WHERE fence=:my_fence (findings #3)
<!-- DOD:END -->
