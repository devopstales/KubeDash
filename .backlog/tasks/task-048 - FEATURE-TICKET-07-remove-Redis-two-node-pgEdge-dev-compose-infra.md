---
id: TASK-048
title: '[FEATURE] TICKET-07 remove Redis + two-node pgEdge dev compose (infra)'
status: In Progress
assignee:
  - opencode/qwen3.8-uncensored
created_date: '2026-10-27 19:16'
updated_date: '2026-10-29 08:43'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
## Plan (forward session 2026-10-29)

Implementation is already in the working tree (31 modified + 3 new files). This session: verify, fix the 8 failing unit tests, then validate compose ACs and close.

### Status vs acceptance criteria
- AC#1 (no redis in backend/app, flask-redis out of pyproject): SATISFIED. New guard test backend/tests/test_no_redis_imports.py added.
- AC#7 (grep redis_client backend/app = 0 hits): SATISFIED.
- AC#2/AC#3/AC#4 (compose validation): PENDING — needs Docker; docker CLI present, image pull pending.
- DoD#6 (db.json internal_admin + hostnames = compose names): SATISFIED in dev/pgedge/db.json (pgedge internal_admin user; hostnames kdpg-n1/kdpg-n2 match service names).

### Failing tests (8) — root causes identified
1. PG-tier readyz 503 (test_health.py::test_readyz_ok_when_deps_up, test_admin_source.py::test_readyz_ok_when_admin_kubeconfig_empty): the `app` fixture sets KUBEDASH_ADMIN_KUBECONFIG=/test/admin.kubeconfig but that file does not exist on this host -> admin-kubeconfig probe reports down. FIX: have the `app` fixture (tests/conftest.py) create the file in tmp_path and point the override at it.
2. sqlite-tier local auth (test_local_auth.py x2): local_enabled=True because bootstrap_admin_email/password have in-code 4.1 parity defaults (admin@kubedash.local/changeme), so the no-bootstrap app is not actually no-bootstrap. FIX: api_app_no_bootstrap must clear both env vars (monkeypatch.delenv) before create_app.
3. admin users create (test_admin_users.py x2): 422 with generic 'Unprocessable Entity' instead of INVALID_KUBECONFIG — needs the real schema/validator error surfaced (inspect admin users create handler + schema validators; likely a password/role enum mismatch or a validator that raises ValueError instead of the typed 422). FIX in handler/validator so the stable code contract holds.
4. test_ini_config.py::test_optional_and_behavior_knobs_keep_defaults: flaky — passes in isolation, fails in the full run (env/INI state leakage from a prior module; investigate ordering, likely a test that leaves KUBEDASH_HOME/ini_config in a state that survives monkeypatch teardown — check for missing ini_config.reset() in a fixture). FIX: make the leaking test reset, or harden the assertion's setup.

### Compose validation (after unit green)
- `docker compose -f dev/docker-compose.yml up -d kdpg-n1 kdpg-n2`; check `spock.node` rows (AC#2: both n1+n2, no redis container), backend health vs n1 (AC#3), apply a migration on n1 and confirm present on n2 (AC#4). Tear down + `dev-clean`-style volume removal when done.
- Note: dev/docker-compose.pgedge.yml exists as a standalone file whose services duplicate docker-compose.yml (the pgEdge services are inlined there). Decision: keep both consistent or make docker-compose.yml canonical and delete the redundant include — confirm no Taskfile reference to the .pgedge.yml before deleting.

### Docs (DoD#5)
- Update .skillgrid/ARCHITECTURE.md + AGENTS.md references to Redis (KUBEDASH_REDIS_URL table row, dev stack section) and the redis marker in pyproject.toml is already handled.

### Commit
- One conventional commit for the TICKET-07 working tree once tests are green: `refactor(dev): remove Redis, pgEdge two-node dev default (ADR-0029/0030/0031)`. Then docs(tracker) commit flipping TASK-048 to Done.
<!-- SECTION:PLAN:END -->
