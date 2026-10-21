---
id: TASK-020
title: 'TICKET-17: Frontend — Login (SSO + local) + Profile + routes'
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-21 07:18'
labels: []
milestone: m-0
dependencies:
  - TASK-016
  - TASK-019
priority: medium
type: feature
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implemented and shipped in 5d91a998 (Login rewrite: token-in-URL parking -> /profile, SSO iff sso_enabled, local form iff local_enabled via /auth/local 302 parse + park, 401/403 inline, settings fail-open; new Profile view: identity card + logout; App.tsx /profile route; types.ts Me/Cluster growth cross-checked vs re-dumped openapi.json; Login 7 + Profile 4 tests, MSW). QA gate PASS fe3b4f4b; change shipped + archived (0893619b).
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. TDD: write failing tests (frontend/tests/views/Login.test.tsx: token-in-URL parks + lands on /profile via router-moved assertion, local form success parses the 302 + parks + navigates, SSO button iff sso_enabled, local form iff local_enabled, 401 surfaces inline, settings-failure fail-open; frontend/tests/views/Profile.test.tsx: renders me-fields + role/auth badges, logout clears storage + navigates). 2. Implement: Login view rewrite (parking effect -> navigate('/profile', {replace:true}); mount auto-bounce REMOVED; settings useQuery fail-open; SSO button document navigation unchanged; local form fetch redirect:'follow' + parse res.url in-process + park + navigate; 401/403 envelope inline); Profile view new (identity card: name/email/groups/role badge/auth-source badge/last login + logout POST -> clear both keys -> /login); App.tsx /profile route inside DefaultLayout + ProtectedRoute (lazy); types.ts Me growth cross-checked against the re-dumped frontend/openapi.json. 3. Verify: pnpm test + tsc --noEmit + pnpm exec eslint src + pnpm build (CI-backstop note: bare 'pnpm lint' hangs >400s locally — pre-existing; use 'pnpm exec eslint src' as the local gate). 4. Commit per work-unit-commits.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T5 subagent session started: baseline fe tests 6/6 green; implementing Login rewrite + Profile + routes + types.ts growth per task-5-brief.
<!-- SECTION:NOTES:END -->
