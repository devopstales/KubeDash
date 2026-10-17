---
id: TASK-010
title: 'TICKET-09: Single-container Dockerfile + SPA static serving'
status: To Do
assignee: []
created_date: '2026-10-17 13:00'
labels: []
milestone: m-0
dependencies:
  - TASK-009
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: medium
type: feature
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: register_static (idempotency-guarded catch-all: immutable /assets/*, no-cache index.html, registered last so /api/v1/* wins — one-way OD-4, ADR-0006), 3-stage Dockerfile (node build -> uv deps -> runtime, non-root 10001, HEALTHCHECK /healthz, GUNICORN_WORKERS/THREADS env in CMD, sync workers), .dockerignore, static + Dockerfile tests. Current: no image. Expected: one container serves API + SPA; API never shadowed by the catch-all.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/test_static.py tests/test_dockerfile.py green (root + fallback index; assets immutable; /api/v1/clusters not shadowed; USER 10001; no unquoted $() in RUN); docker build -f backend/Dockerfile . exits 0 (record if Docker unavailable)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R6 image half met; OD-4 human checkpoint passed; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. backend/app/__init__.py register_static (idempotency guard, cache headers)
2. backend/Dockerfile 3 stages + .dockerignore
3. tests/test_static.py (static_app fixture via config_overrides) + tests/test_dockerfile.py
4. pytest green + docker build (record env-block if no Docker); commit (Refs: TASK-009)
<!-- SECTION:PLAN:END -->
