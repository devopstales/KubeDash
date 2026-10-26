---
id: TASK-037
title: >-
  [CHORE] TICKET-05: Dev wiring (Taskfile + Dockerfile) + chart env-override
  backstop
status: To Do
assignee: []
created_date: '2026-10-26 13:19'
updated_date: '2026-10-26 13:19'
labels: []
dependencies:
  - TASK-036
references:
  - .skillgrid/specs/2026-10-26-ini-config-source/briefing.md
  - .skillgrid/specs/2026-10-26-ini-config-source/blueprint.md
  - .skillgrid/specs/2026-10-26-ini-config-source/tasks.md
  - .skillgrid/specs/2026-10-26-ini-config-source/adr.md
  - .skillgrid/specs/2026-10-26-ini-config-source/acceptance.feature
priority: medium
type: chore
ordinal: 37000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Config source change (ADR-0028). Create backend/kubedash.ini (gitignored, dev values); drop KUBEDASH_STATIC_DIR from all four Taskfile targets + inline bootstrap/cookie env (INI carries them); keep KUBEDASH_ROLE/REPLICA_ID/FLASK_RUN_PORT + ssl overrides; Dockerfile drops KUBEDASH_STATIC_DIR, bakes KUBEDASH_HOME=/app; chart deployment.yaml/secret.yaml get WHY-comment + KUBEDASH_HOME note; finalize adr.md manifest. Backstops: dev-stack-boots-from-ini, chart-env-overrides-ini.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 task dev-stack boots from backend/kubedash.ini (healthz 200, SPA from backend/static, KUBEDASH_ROLE=leader from INI, no KUBEDASH_STATIC_DIR)
- [ ] #2 helm template shows KUBEDASH_JWT_SECRET secretKeyRef (env overrides INI)
- [ ] #3 full unit suite + fe-build green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 dev-stack boots and serves
- [ ] #7 chart env override documented
- [ ] #8 adr.md manifest finalized
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Create backend/kubedash.ini (dev values) + gitignore
2. Drop KUBEDASH_STATIC_DIR from 4 Taskfile targets + inline bootstrap/cookie env
3. Dockerfile: drop KUBEDASH_STATIC_DIR, add KUBEDASH_HOME=/app
4. Chart WHY-comment + KUBEDASH_HOME note
5. Finalize adr.md manifest
6. Backstops: task dev-stack + helm template; full suite + fe-build
<!-- SECTION:PLAN:END -->
