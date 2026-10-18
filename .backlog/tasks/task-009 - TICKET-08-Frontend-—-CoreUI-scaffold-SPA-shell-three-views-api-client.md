---
id: TASK-009
title: 'TICKET-08: Frontend — CoreUI scaffold + SPA shell + three views + api client'
status: Done
assignee:
  - '@paladm'
created_date: '2026-10-17 12:59'
updated_date: '2026-10-17 17:50'
labels: []
milestone: m-0
dependencies:
  - TASK-002
  - TASK-006
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: high
type: feature
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: CoreUI free React admin template + KubeDash deps; lib/api.ts (JWT attach, single-in-flight 401 refresh, rotated kd_refresh storage, error envelope); lib/types.ts via openapi-typescript; store/cluster.ts; hooks/useCluster.ts; views Login/Clusters/Cluster (token-in-URL consumption, CTable lists, pod table); MSW tests incl. double-rotation; playwright config + smoke spec. Current: no frontend/. Expected: pnpm test/tsc/lint/build all green; the SPA shell renders the spine.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pnpm test green (api attach/refresh/double-rotation/envelope + both view tests); pnpm exec tsc --noEmit + pnpm lint + pnpm build exit 0; dist/ has hashed assets
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R5 acceptance met (e2e half carried by TICKET-10); spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Copy coreui-free-react-admin-template -> frontend/; pnpm add KubeDash deps
2. lib/api.ts + lib/types.ts + store/cluster.ts + hooks/useCluster.ts
3. views/{Login,Clusters,Cluster} + routes.tsx + _nav.tsx + Header cluster switcher + main.tsx QueryClientProvider
4. tests/msw.ts + tests/api.test.ts + tests/views/*.test.tsx + playwright.config.ts + e2e/smoke.spec.ts
5. pnpm test/tsc/lint/build green; commit (Refs: TASK-002, TASK-006)
<!-- SECTION:PLAN:END -->
