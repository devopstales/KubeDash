---
id: TASK-014
title: 'Dev environment: docker-compose stack + Task commands'
status: To Do
assignee: []
created_date: '2026-10-17 13:42'
updated_date: '2026-10-17 13:49'
labels: []
dependencies: []
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
KubeDashs Flask backend needs local Postgres + Redis, and the query-only observability layer (ARCHITECTURE.md §6) needs Prometheus, Grafana, and Jaeger to actually query. Today there is no one-command way to bring the full dev stack up for local work. This adds a dev/ compose stack (5 services) plus root Taskfile dev-* commands so a developer can start, stop, and clean the whole environment in one shot. Ports are pinned to the app defaults (5432/6379) so the Flask database_url/redis_url need no env change. Grafana auto-provisions Prometheus + Jaeger datasources.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 task dev-up starts all 5 services and task dev-ps shows every one healthy
- [ ] #2 task dev-down stops the stack while preserving data volumes
- [ ] #3 task dev-clean stops and removes the data volumes
- [ ] #4 The Flask app default DATABASE_URL/REDIS_URL connect to the stack unchanged
- [ ] #5 Grafana (admin/admin) auto-provisions Prometheus and Jaeger datasources on a fresh up
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add dev/docker-compose.yml: 5 services (postgres:16, redis:7, prom/prometheus, grafana/grafana, jaegertracing/all-in-one:1.62) with healthchecks, named data volumes, ports pinned to app defaults.
2. Add dev/.env as single source of truth for shared creds/ports (matches backend defaults).
3. Add dev/prometheus/prometheus.yml (self-scrape) and dev/grafana/provisioning/{datasources,dashboards} (Prometheus + Jaeger datasources auto-provisioned).
4. Add root Taskfile.yaml with dev-up / dev-down / dev-clean / dev-logs / dev-ps via docker compose -f {{.TASKFILE_DIR}}/dev/docker-compose.yml.
5. Verify: Taskfile parses (task --list), paths render correctly, YAML valid. Docker absent in this sandbox so runtime `up` not exercised here.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented. Two Taskfile bugs found+fixed during verification: (a) unquoted YAML scalar starting with {{ fails to parse -> quoted all cmd/var strings; (b) {{.ROOT}} resolves to empty "/" in this sandbox -> switched to {{.TASKFILE_DIR}} which yields the repo root. task --list and path rendering both verified; docker compose not runnable here (no docker binary).

Follow-up (user request): consolidated cli/Taskfile.yaml into the root Taskfile.yaml so the repo has a single Taskfile. Moved the cli build tasks (build, cross) into root with dir: cli so go build still runs from cli/; VERSION override kept via top-level env (task build VERSION=x). Verified from repo root: task build -> cli/kubedash 0.1.0; task build VERSION=9.9.9-test -> 9.9.9-test; task cross -> 5 binaries in cli/dist/. cli/.gitignore already ignores /kubedash + /dist/ (removed test artifacts). Removed cli/Taskfile.yaml. SDD spec blueprints that reference cli/Taskfile.yaml are historical records, left as-is.
<!-- SECTION:NOTES:END -->
