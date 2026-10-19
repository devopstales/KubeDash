---
id: TASK-020
title: 'TICKET-17: Frontend — Login (SSO + local) + Profile + routes'
status: In Progress
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-18 13:44'
labels: []
milestone: m-0
dependencies:
  - TASK-016
  - TASK-019
priority: medium
type: feature
ordinal: 20000
---

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
1. TDD: write failing tests (frontend/tests/views/Login.test.tsx: token-in-URL parks + lands on /profile via router-moved assertion, local form success parses the 302 + parks + navigates, SSO button iff sso_enabled, local form iff local_enabled, 401 surfaces inline, settings-failure fail-open; frontend/tests/views/Profile.test.tsx: renders me-fields + role/auth badges, logout clears storage + navigates). 2. Implement: Login view rewrite (parking effect -> navigate('/profile', {replace:true}); mount auto-bounce REMOVED; settings useQuery fail-open; SSO button document navigation unchanged; local form fetch redirect:'follow' + parse res.url in-process + park + navigate; 401/403 envelope inline); Profile view new (identity card: name/email/groups/role badge/auth-source badge/last login + logout POST -> clear both keys -> /login); App.tsx /profile route inside DefaultLayout + ProtectedRoute (lazy); types.ts Me growth cross-checked against the re-dumped frontend/openapi.json. 3. Verify: pnpm test + tsc --noEmit + pnpm exec eslint src + pnpm build (CI-backstop note: bare 'pnpm lint' hangs >400s locally — pre-existing; use 'pnpm exec eslint src' as the local gate). 4. Commit per work-unit-commits.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T5 subagent session started: baseline fe tests 6/6 green; implementing Login rewrite + Profile + routes + types.ts growth per task-5-brief.
<!-- SECTION:NOTES:END -->
