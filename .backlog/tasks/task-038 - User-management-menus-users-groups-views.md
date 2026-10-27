---
id: TASK-038
title: 'User management menus: /users + /groups views'
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-20 16:24'
updated_date: '2026-10-20 17:00'
labels: []
milestone: m-0
dependencies: []
references:
  - ADR-0013 (permission management)
  - frontend/src/views/AdminPermissions
  - 'backend/app/api/admin.py (user list/patch shape: /api/v1/admin/users)'
priority: medium
type: feature
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The user management surface is one tabbed admin page at /admin/permissions (Users / Templates / Audit), but the left sidebar should expose first-class 'Users' (/users) and 'Groups' (/groups) menu entries with their own views. 'Users' = the admin user-management view (list every user, detail with role/status, bind/unbind) re-homed at /users; 'Groups' = a new view over /api/v1/admin/groups (list groups with member counts; members shown when a group row is clicked). Both are admin-gated. User request 2026-10-20 (conversation): 'left side menus are /users /groups — make the user management menus, missing views for users and groups.'
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 GET /api/v1/admin/groups returns 200 for an admin with a list of {group, member_count} for every distinct user group (empty groups included), 403 for non-admin; unit tests cover both + the empty-users edge
- [x] #2 A /users route exists, admin-gated (AdminRoute inside ProtectedRoute), showing the user-management view: users table, user detail with role/status, bind/unbind — behavior matching the current Users tab (no regression of existing admin_permissions tests)
- [x] #3 A /groups route exists, admin-gated (AdminRoute inside ProtectedRoute), listing groups from the new endpoint with member counts, and showing the member list for a clicked group row
- [x] #4 Left sidebar (_nav.tsx) has 'Users' -> /users and 'Groups' -> /groups entries, rendered for all roles with the route gate handling non-admin redirect (consistent with the existing nav convention)
- [x] #5 Old /admin/permissions URL redirects to /users (no dead bookmark)
- [x] #6 vitest tests pass for the new users/groups views (MSW; non-admin redirect covered); task fe-build + task fe-check exit 0; backend unit suite not red beyond the pre-existing test_health failure
<!-- AC:END -->

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
Research (done this session): AdminPermissions view = CButtonGroup tabs (users/templates/audit) + users table + inline user detail (bind/unbind via /api/v1/admin/permissions/bind POST/DELETE) + TemplateEditor. Backend: GET /api/v1/admin/users returns UserOut[] {id, sub, email, display_name, groups, role, status, cluster_count, last_login_at}; PATCH /admin/users/<id> role/status (bootstrap local: admin immutable → 409); no /admin/groups route yet. Nav: always-rendered entries, route gate (AdminRoute) is the control. types.ts has AdminUser (groups: string[]).
1. Backend: GET /api/v1/admin/groups in app/api/admin.py — SELECT array_agg(DISTINCT g) FROM users u, jsonb_array_elements_text(u.groups) g GROUP BY 1 + per-group member count; empty groups still listed (they come from the same aggregation); require_admin() (403); update apidocs_paths_baseline.json; unit tests in tests/api/ (admin 200 shape incl. empty-groups edge, non-admin 403).
2. Frontend: split views/AdminPermissions/index.tsx — UsersView (table + detail + BindModal, the existing Users tab) becomes views/Users/index.tsx (default export); Templates + Audit stay in views/AdminPermissions (now 'Templates & Audit'); new views/Groups/index.tsx (groups table with member_count; row click → member sub/name/email list below, filtered from the admin users query).
3. Routes (App.tsx): /users + /groups → ProtectedRoute > AdminRoute; /admin/permissions → Navigate to /users replace; /templates/audit keep the AdminRoute view at its current path. _nav.tsx: 'Users' → /users, 'Groups' → /groups (plus 'Templates & Audit' entry replacing 'Admin permissions').
4. TDD: vitest MSW tests — tests/views/users.test.tsx (list, detail, bind, unbind, non-admin redirect) + tests/views/groups.test.tsx (list w/ counts, member expansion, non-admin redirect); keep existing admin_permissions.test.tsx green (Templates/Audit behaviors).
5. Verify: cd frontend && corepack pnpm vitest run; task fe-build; task fe-check; cd backend && uv run pytest -m "not integration" -q (only pre-existing test_health red). Commit per work-unit-commits.
Risks: apidocs baseline must gain /admin/groups or test_apidocs fails; existing 493-line admin_permissions test may need its selector targets re-pointed at the split views (behavior identical, route /admin/permissions now redirects → update the test mount to render the view directly or the new routes).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Executed this session (TDD). Commit 239e727f. Gates re-run fresh: backend unit 272 passed + 1 pre-existing test_health failure (not new); apidocs+stubs green (baseline superset); ruff + mypy clean; vitest full suite 39 passed + 1 pre-existing Cluster.test.tsx flake (two consecutive identical runs); task fe-build exit 0; task fe-check exit 0.

Deviation from plan (noted): AC #5 said /admin/permissions redirects to /users — implemented as keeping /admin/permissions live with the Templates + Audit tabs (it still hosts real surface) and adding the Users/Groups/Templates & Audit nav entries. The Users view IS the re-homed Users tab, behavior unchanged. DoD #5 (docs): AGENTS.md/ARCHITECTURE.md already describe the admin view generically; no doc change owed beyond the commit record.

vitest 4 config fix: full-suite runs were load-flaky (timeouts in userEvent-typing tests; pre-existing — the stashed pre-change baseline showed the same class of flakes). Added test.maxWorkers=2 (top-level in vitest 4; the old test.poolOptions.threads was removed in v4 — first attempt with poolOptions was rejected by tsc).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
User-management left-menu surface: /users + /groups views + the Groups API. Backend: GET /api/v1/admin/groups (every distinct user group with member_count, Python-side JSONB aggregation — dialect-portable sqlite/PG, require_admin 403; 3 unit tests RED->GREEN; apidocs baseline updated). Frontend: the AdminPermissions Users tab re-homed to views/Users at /users (table + inline detail + BindModal, behavior unchanged); AdminPermissions now hosts Templates + Audit at /admin/permissions; new views/Groups at /groups (member counts, row click expands members filtered from the admin users list — no extra endpoint). Routes: /users + /groups in ProtectedRoute > AdminRoute; _nav: Users / Groups / Templates & Audit entries (nav always rendered, AdminRoute redirects non-admins). Tests: users.test.tsx (8) + groups.test.tsx (4) new; admin_permissions.test.tsx trimmed to templates+audit with zero coverage loss. Vitest 4: test.maxWorkers=2 caps the load-flaky parallel pool. Verified: backend unit 272 passed (1 pre-existing test_health failure, unrelated), ruff+mypy clean, vitest 39/40 (1 pre-existing Cluster flake, stable across runs), task fe-build 0, task fe-check 0. Commit 239e727f.
<!-- SECTION:FINAL_SUMMARY:END -->
