---
id: TASK-003
title: 'TICKET-02: Core models, initial migration, leader election'
status: To Do
assignee: []
created_date: '2026-10-17 12:57'
labels: []
milestone: m-0
dependencies:
  - TASK-002
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: high
type: feature
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: users/clusters/cluster_bindings/refresh_tokens/leader_lease models, the initial Alembic revision (one-way OD-3), and Leader election (per-replica advisory lock key, stale takeover, failover). Current: no models. Expected: models round-trip in Postgres; exactly one leader among replicas; failover within budget.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/test_models.py tests/test_leader.py green: role validation raises on unknown role; single replica leads; second replica no double-lead; failover after leader stop <= 15s; migration contains all 5 create_table calls
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R3 prereq met; OD-3 human checkpoint passed before flask db migrate; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. app/models/{user,cluster,binding,token,leader_lease}.py (SQLAlchemy 2.0, cluster incl. last_probe_at)
2. app/core/leader.py Leader (hashintext lock key, stale takeover, release on stop)
3. flask db init + migrate -m initial + upgrade; verify 5 tables
4. tests/test_models.py + tests/test_leader.py (incl. failover)
5. pytest green; commit (Refs: TASK-002)
<!-- SECTION:PLAN:END -->
