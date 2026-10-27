---
id: TASK-048
title: '[FEATURE] TICKET-07 remove Redis + two-node pgEdge dev compose (infra)'
status: To Do
assignee: []
created_date: '2026-10-27 19:16'
updated_date: '2026-10-27 19:16'
labels: []
milestone: m-2
dependencies:
  - TASK-045
  - TASK-047
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
ordinal: 44000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The contract step: remove Redis from the stack and switch the dev default to two-node pgEdge (ADR-0029/0030/0031). Current State: flask-redis + redis_client + KUBEDASH_REDIS_URL exist; dev compose is postgres:16 + redis. Expected State: no module in backend/app references redis_client or flask_redis; flask-redis out of pyproject.toml; redis_url gone from config.py + ini_config.py; dev/docker-compose.pgedge.yml + dev/pgedge/db.json (two pgedge/pgedge:pg17-latest nodes, autoddl, the pgedge internal_admin user, hostnames matching compose service names - findings #5); dev/docker-compose.yml postgres+redis replaced with the pgEdge include, redisdata dropped; Taskfile dev-up/dev-ps/db-shell re-pointed at n1. One-way: STOP for approval before removing flask-redis/KUBEDASH_REDIS_URL + switching the dev default.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no module in backend/app references redis_client or flask_redis; flask-redis not in pyproject.toml
- [ ] #2 task dev-up brings up two pgEdge nodes (both in spock.node) with no redis container
- [ ] #3 the backend passes its health check against n1
- [ ] #4 a migration applied on n1 is present on n2 (autoddl)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 db.json includes the pgedge internal_admin user + hostnames matching compose service names (findings #5)
- [ ] #7 Precondition: grep -rn redis_client backend/app returns 0 hits (TICKET-05 + TICKET-06 landed)
<!-- DOD:END -->
