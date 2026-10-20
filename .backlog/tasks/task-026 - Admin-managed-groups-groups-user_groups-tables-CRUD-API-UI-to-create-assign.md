---
id: TASK-026
title: >-
  Admin-managed groups: groups + user_groups tables, CRUD API, UI to
  create/assign
status: In Progress
assignee:
  - '@opencode'
created_date: '2026-10-20 19:18'
updated_date: '2026-10-20 19:19'
labels: []
milestone: m-0
dependencies: []
references:
  - >-
    main: src/kubedash/templates/users/group.html.j2 + group-privilege.html.j2
    (Members/RoleBindings tabs)
  - >-
    main: src/kubedash/blueprint/user.py groups()/groups_privilege()
    (SSOGroupsList / SSOGroupsMemberList)
  - 'TASK-024 (user-management menus: /users + /groups views)'
  - backend/app/api/admin.py (existing admin users/groups routes)
priority: medium
type: feature
ordinal: 26000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The /groups and /users admin pages render but show no content (2026-10-20): groups only came from the OIDC groups claim, and the local bootstrap admin has none, so /groups was empty and /users showed no groups. The user wants these to behave like the main branch (old app) user-management pages — real, admin-managed data. Build a Postgres groups table + a user_groups mapping (mirrors main's sso_groups / sso_user_group_mapping), an admin CRUD API (create/list/delete group, assign/unassign user), and wire the UI: /groups lists created groups (name + member count) and clicking a group shows its Members; /users shows each user's groups and lets the admin add/remove a user from a group. OIDC groups claims still merge into the effective group list. This is the 'no content' fix for the user-management menus.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 A migration adds a groups table (id, name unique, created_at) and a user_groups mapping (user_id, group_id, unique together) — alembic revision, reversible, idempotent against the create_all-era shape
- [ ] #2 Admin API: POST /api/v1/admin/groups (create, 409 on duplicate name), DELETE /api/v1/admin/groups/<name> (removes membership rows), POST /api/v1/admin/groups/<name>/members {user_sub} (assign), DELETE .../members/<user_sub> (unassign); all require_admin (403 non-admin); GET /api/v1/admin/groups now returns stored groups merged with OIDC-claim groups (a group with no stored row still appears if some user's claim has it)
- [ ] #3 GET /api/v1/admin/users rows include the user's groups = stored memberships merged with the user's OIDC claim (deduped, sorted)
- [ ] #4 /groups view: lists groups (name + member count); clicking a group shows its members (sub/email/name); an admin can create a new group (name prompt/form) and the list updates
- [ ] #5 /users view: each user row shows their groups; the user detail panel lets the admin add a user to a group and remove them (membership controls wired to the API)
- [ ] #6 vitest: /groups create + member expansion + non-admin redirect; /users group display + assign/unassign; backend: create/list/delete/assign/unassign/409/403/merge-with-claim unit tests (TDD red->green)
- [ ] #7 task fe-build + task fe-check exit 0; backend unit suite not red beyond the pre-existing test_health failure; apidocs baseline updated for the new routes
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
Research (this session): main branch groups = sso_groups + sso_user_group_mapping tables; /group lists SSOGroupsList(); group detail has Members + RoleBindings tabs (SSOGroupsMemberList). 5.0 current: GET /admin/groups aggregates user.groups (OIDC claim) in Python; /groups view lists + member expansion (filter from /admin/users); /users view shows no groups column yet (AdminUser.groups exists in the type but the table has no groups <th>).
1. Models: backend/app/models/group.py — Group (id, name unique, created_at) + UserGroup (user_id FK, group_id FK, unique (user_id, group_id)); register in models/__init__.
2. Migration: new alembic rev (down = 3c9f21a7d5b4) creating groups + user_groups (FK + unique + indexes); idempotent create_table guards; downgrade drops both. Apply to dev DB (task db-migrate).
3. API (admin.py): keep GET /admin/groups but change to merge stored groups + OIDC-claim groups (member_count = distinct users with that group via stored OR claim); POST /admin/groups {name} (409 CLUSTER_ALREADY_EXISTS on dup — frozen 409 code); DELETE /admin/groups/<name> (cascade membership); POST /admin/groups/<name>/members {user_sub} (404 unknown user); DELETE /admin/groups/<name>/members/<user_sub>. All require_admin. GET /admin/users: _out groups = stored memberships merged with user.groups claim (deduped sorted).
4. Schemas: GroupIn {name}, or reuse; update apidocs_paths_baseline.json (+4 paths: admin/groups already there, + admin/groups/{name}, + admin/groups/{name}/members, + admin/groups/{name}/members/{user_sub}).
5. Frontend /groups: add a create-group control (small inline form: name + Add); list unchanged; member expansion unchanged (now backed by real data).
6. Frontend /users: add a 'Groups' column to the users table (badges from u.groups); in the user detail panel add a membership block: list the user's groups with a remove (x) each + an add control (pick a group from the /admin/groups list) that calls the assign/unassign API and refetches.
7. Types: AdminUser.groups already exists; add GroupOut stays {group, member_count} (no change); no new top-level type needed (membership uses existing).
8. TDD: backend tests/api/test_admin_groups.py — extend with create/delete/assign/unassign/409/403/merge-with-claim; frontend tests/views/groups.test.tsx — create-group + member expansion + non-admin; tests/views/users.test.tsx — groups column + assign/unassign.
9. Verify: backend unit (only pre-existing test_health red), ruff+mypy, task db-migrate on dev DB, vitest, task fe-build + fe-check. Commit (models, migration, admin.py, schemas, baseline, frontend views+tests, types if any).
Risks: sqlite api tier — Group/UserGroup are plain relational (no JSONB) so portable; the merge query must work on sqlite (use Python-side or simple JOIN, not PG-only). member_count semantics: count distinct users having the group via stored OR claim (match the existing claim-based count so stored-only groups show their assigned members).
<!-- SECTION:PLAN:END -->
