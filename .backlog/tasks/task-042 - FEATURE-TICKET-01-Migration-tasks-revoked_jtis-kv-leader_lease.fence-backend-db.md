---
id: TASK-042
title: >-
  [FEATURE] TICKET-01 Migration: tasks, revoked_jtis, kv, leader_lease.fence
  (backend-db)
status: Done
assignee: []
created_date: '2026-10-27 19:15'
updated_date: '2026-10-27 20:01'
labels: []
milestone: m-2
dependencies: []
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
ordinal: 38000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The tracer-thread foundation for the Postgres queue + revocation change (ADR-0029/0030/0031). Current State: the three tables and the fence column do not exist; every later ticket reads them. Expected State: a single Alembic migration creates tasks (id/path/status/attempts/enqueued_at/locked_at/locked_by/available_at + plain index), revoked_jtis (jti PK + expires_at), kv (key PK + value + expires_at + index), and adds leader_lease.fence (NOT NULL default 0). No partial index with now() in the predicate (findings #2). The three ORM models are exported from app.models. One-way: STOP for approval before running the migration (new tables + fence column; migration-gated).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 After alembic upgrade head, tasks/revoked_jtis/kv exist with the right columns and constraints
- [ ] #2 leader_lease.fence is NOT NULL default 0
- [ ] #3 No partial index with now() in the predicate (findings #2)
- [ ] #4 The three ORM models are exported from app.models and test_new_tables.py passes
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Migration down_revision equals the current single head 2eb286befb21
<!-- DOD:END -->
