---
id: TASK-041
title: 'Users page: match main branch layout + DataTables React + create/edit/delete'
status: In Progress
assignee:
  - '@opencode'
created_date: '2026-10-20 20:16'
updated_date: '2026-10-20 20:17'
labels: []
milestone: m-0
dependencies: []
references:
  - >-
    main: src/kubedash/templates/users/user.html.j2 (User List DataTables page +
    Create/Edit modals)
  - >-
    main: src/kubedash/templates/base2.html.j2 (vendored DataTables 2.2.2 +
    jQuery + Bootstrap 5)
  - >-
    https://datatables.net/manual/components/react/quick-start
    (datatables.net-react + datatables.net-dt)
  - 'TASK-024 (user-management menus: /users view)'
  - 'TASK-026 (admin-managed groups: /users groups column + membership panel)'
  - >-
    backend/app/api/admin.py (list_users/patch_user),
    backend/app/core/security.py (pbkdf2 ADR-0021)
priority: medium
type: feature
ordinal: 27000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Make /users look and behave like the main-branch Users page (DataTables search/sort/pagination, 'User List' card, User Management breadcrumb, + add button, Username/Email/Permission/Type/Action columns, Create + Edit modals), implemented with the official DataTables React component (datatables.net-react + datatables.net-dt, vendored -> air-gap safe) and CoreUI. Keep the richer 5.0 columns (Status, Groups badges, cluster bindings, last login) and the existing inline user-detail panel. Backend: expose user_type (Local/OIDC) on GET /admin/users, add DELETE /admin/users/<id> (409 for bootstrap admin/caller, cascade, audit) and POST /admin/users (create a local-password user reusing the ADR-0021 pbkdf2 util). TDD red->green; gates fe-build/fe-check/backend-unit/ruff/mypy.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 GET /api/v1/admin/users rows include user_type ('Local' for auth_source=local, 'OIDC' otherwise)
- [ ] #2 POST /api/v1/admin/users creates an auth_source=local user (name/email/password/role) using the ADR-0021 pbkdf2 hash; 201; 409 CLUSTER_ALREADY_EXISTS on duplicate email/sub; 422 INVALID_KUBECONFIG on blank fields; audits user.create
- [ ] #3 DELETE /api/v1/admin/users/<user_id> deletes a user (200), 409 for the bootstrap local: admin and for the caller, cascades user_groups + cluster_bindings, audits user.delete
- [ ] #4 All three new/changed routes are require_admin (403 RBAC_DENIED for non-admin); apidocs baseline updated (+POST/DELETE /admin/users)
- [ ] #5 /users renders via the datatables.net-react DataTable (search box + sortable headers + pagination active), inside a 'User List' card with a User Management breadcrumb and a + add button (admin only)
- [ ] #6 /users columns: Username (clickable -> detail), Email, Permission, Type (Local/OIDC), Status, Groups (badges), Cluster bindings, Last login, Action (edit/delete/bind; delete hidden for the bootstrap admin)
- [ ] #7 Create User modal (name/email/password/permission) posts to POST /admin/users; Edit User modal (role/status) posts to PATCH /admin/users/<id>; delete button calls DELETE and removes the row; existing inline user-detail panel (bindings + groups membership) is preserved
- [ ] #8 TDD: backend tests for POST/DELETE users + user_type (red->green); frontend tests for search/sort/pagination, create posts, edit patches, delete removes + hidden-for-bootstrap, Type column; task fe-build + task fe-check exit 0 (air-gap intact with the vendored DataTables); backend unit suite not red beyond the pre-existing test_health failure
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
Research (this session): main /user/list = 'User List' card + #dataTable DataTables (search/sort/pagination via $('#dataTable').DataTable()) + breadcrumb User Management>Users + '+' add button; columns Username/Email/Permission/Type/Action; Create User + Edit User Bootstrap modals. 5.0 /users = CTable + inline detail panel (bindings + groups membership, TASK-026). DataTables React: datatables.net-react + datatables.net-dt (DataTable.use(DtCore), <Column render>), import 'datatables.net-dt/css' — vendored, air-gap safe.
1. Frontend deps: pnpm add datatables.net-dt datatables.net-react (vendored, no CDN). Verify air-gap: task fe-check must still pass after build.
2. Backend GET /admin/users: add user_type per row (auth_source 'local'->'Local', else 'OIDC').
3. Backend POST /admin/users: create auth_source=local user (username/display_name, email, password, role); hash via the ADR-0021 pbkdf2 util in core/security.py; 201; 409 CLUSTER_ALREADY_EXISTS on dup email/sub; 422 blank; audit user.create; require_admin.
4. Backend DELETE /admin/users/<id>: 200 delete; 409 for bootstrap local: admin + for the caller; cascades user_groups/cluster_bindings (FK ondelete CASCADE); audit user.delete; require_admin.
5. apidocs baseline + POST/DELETE /api/v1/admin/users.
6. Frontend /users: rebuild with datatables.net-react DataTable inside a 'User List' card + breadcrumb + '+' add button. Columns: Username (click->detail), Email, Permission, Type, Status, Groups (badges), Cluster bindings, Last login (DtCore.render.date), Action (edit/delete/bind; delete hidden for bootstrap). Create User modal (name/email/password/permission)->POST. Edit modal (role/status)->PATCH. Keep inline user-detail panel (bindings + groups membership).
7. TDD: backend tests/api (POST/DELETE users + user_type) red->green; frontend tests/views/users.test.tsx (search/sort/pagination, create posts, edit patches, delete removes + hidden-for-bootstrap, Type column) red->green.
8. Verify: backend unit (-m 'not integration', only pre-existing test_health red), ruff+mypy, task fe-build, task fe-check, vitest. Commit (only task-027 files; working tree carries unrelated observability files — do not stage them).
Risks: (a) DataTables default CSS may clash with CoreUI — verify visually, add a wrapper class if needed; (b) datatables.net-react is a new dep — confirm it bundles with no CDN ref (fe-check); (c) jsdom + DataTables interaction for search/sort/pagination tests — if the component is too heavy for jsdom, assert the data wiring + a couple of DOM behaviors and keep it pragmatic; (d) reusing the pbkdf2 hash util — read core/security.py for the exact function signature first.
<!-- SECTION:PLAN:END -->
