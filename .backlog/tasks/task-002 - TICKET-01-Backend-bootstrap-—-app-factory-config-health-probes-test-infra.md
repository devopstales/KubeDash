---
id: TASK-002
title: 'TICKET-01: Backend bootstrap — app factory, config, health probes, test infra'
status: To Do
assignee: []
created_date: '2026-10-17 12:57'
labels: []
milestone: m-0
dependencies: []
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: high
type: feature
ordinal: 2000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket for the KubeDash 5.0 base-structure change. Builds the backend uv project, create_app() factory, Pydantic Settings (incl. the two §7.5 keys), extensions, /healthz + /readyz, OpenAPI check, and the Testcontainers PG/Redis + app/client fixture layer every later ticket drives. Current: no backend/ exists. Expected: pytest green against real containers; the tracer spine has a bootable app.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 uv run pytest tests/ -v green: app constructs; /healthz 200; /readyz 200 with deps up and 503 naming 'redis' when down; /api/openapi.json valid OpenAPI 3.0
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R1 acceptance met; spec-zone code commit with [skillgrid-context] block
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. backend/pyproject.toml (uv, deps per blueprint Task 1, ruff+mypy+pytest config)
2. app/core/config.py Settings + app/extensions.py + app/__init__.py create_app (health, errors, static no-op)
3. wsgi.py entrypoint
4. tests/conftest.py Testcontainers fixtures + tests/test_app.py + tests/test_health.py
5. uv sync && uv run pytest -v green; commit
<!-- SECTION:PLAN:END -->
