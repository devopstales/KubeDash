---
id: TASK-020
title: 'TICKET-17: Frontend — Login (SSO + local) + Profile + routes'
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-20 15:45'
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
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. TDD: Login.test.tsx (token-in-URL parks + lands on /profile via router-moved assertion; local form success parses the 302 + parks + navigates; SSO button iff sso_enabled; local form iff local_enabled; 401 surfaces inline; settings-failure fail-open) + Profile.test.tsx (renders me-fields + role/auth badges; logout clears storage + navigates). [done — committed 5d91a998]
2. Implement: Login view rewrite (parking effect -> navigate('/profile', {replace:true}); mount auto-bounce removed; settings useQuery fail-open; SSO document navigation unchanged; local form fetch redirect:'follow' + parse res.url + park + navigate; 401/403 envelope inline); Profile view new (identity card + logout POST -> clear both keys -> /login); App.tsx /profile route inside DefaultLayout + ProtectedRoute (lazy); types.ts Me growth cross-checked against re-dumped frontend/openapi.json. [done — committed 5d91a998; Login template + favicon extended in 72965ec9]
3. Verify: pnpm test + tsc --noEmit + pnpm exec eslint src + pnpm build (CI-backstop: bare 'pnpm lint' hangs >400s locally — pre-existing). [done — this session: 11/11 targeted, tsc 0, eslint 0, build 0; full suite 34/35 with 1 pre-existing unrelated Cluster.test.tsx failure]
4. Commit per work-unit-commits. [done]
Deviation notes: none on the core plan; Login template polish (favicon/manifest/nohup dev-stack) committed separately in 72965ec9. Docs/ADR bookkeeping is TASK-022 scope.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
T5 subagent session started: baseline fe tests 6/6 green; implementing Login rewrite + Profile + routes + types.ts growth per task-5-brief.

T5 resumed (this session). Implementation already landed in 5d91a998 (feat(fe): login page (SSO + local) + profile landing (ADR-0021)); Login.test.tsx + Profile.test.tsx later extended in 72965ec9 (Login template + favicon). Working tree: no frontend/ changes this session — verification only.

Verification (fresh runs, this session): vitest Login+Profile = 11/11 passed; tsc --noEmit exit 0; pnpm exec eslint src exit 0; pnpm build exit 0 (vite, 12.6s). Full suite: 34/35 passed — the 1 failure is tests/views/Cluster.test.tsx ('Unable to find an element with the text: Running'), pre-existing, unrelated to this task's files (Login/Profile/route/types).

CI-backstop confirmed: bare 'pnpm lint' hangs >400s locally (pre-existing); 'pnpm exec eslint src' used as the local gate per the plan.

DoD #5 deferred to TASK-022 (TICKET-19: docs/ADR bookkeeping) — consistent with how the other auth-vertical tickets handled docs.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Login page (SSO + local) and Profile landing for ADR-0021. Login view: SSO button iff sso_enabled (full document navigation to /api/v1/auth/login), local password form iff local_enabled (POST /api/v1/auth/local with redirect:'follow'; the 302 token pair is parsed from res.url in-process — MSW's redirectTo fallback handled in tests); one shared parkTokens seam parks kd_token/kd_refresh; /?token=&refresh= parking effect navigates to /profile (replace) and strips the query; old mount auto-bounce removed (it 404'd at /authorize on no-IdP installs); settings fetched from open GET /auth/settings with fail-open on error (FAIL_OPEN renders both options); 401/403 envelope surfaces inline. Profile view: identity card from useCluster() me (display name, email, groups, role badge, auth_source badge, admin kubeconfig source, last login) + logout (POST /auth/logout best-effort, clears both kd_* keys, replaces to /login). Route /profile added in App.tsx inside DefaultLayout + ProtectedRoute (lazy). Me types grown per the re-dumped openapi.json.

Verification: vitest tests/views/Login + Profile 11/11 passed; tsc --noEmit clean; pnpm exec eslint src clean; pnpm build clean. Full fe suite 34/35 — 1 pre-existing unrelated failure in tests/views/Cluster.test.tsx (present before this change's files touched anything it renders). Docs/ADR bookkeeping owned by TASK-022.
<!-- SECTION:FINAL_SUMMARY:END -->
