---
id: TASK-025
title: 'Migration-managed dev DB: task db-migrate + dev-stack alembic path'
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-20 17:27'
updated_date: '2026-10-20 18:07'
labels: []
milestone: m-0
dependencies: []
references:
  - 'Taskfile.yaml (dev-stack, backend-create-schema, db-shell)'
  - >-
    backend/migrations/versions/3c9f21a7d5b4_user_management_adr_0013.py
    (idempotent dev-DB guards)
  - backend/migrations/versions/af8aeb8ccf8a (base revision)
priority: medium
type: feature
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The dev Postgres was created with create_all (no alembic_version table), so merged migrations silently never ran against it — the user-management columns were missing from the live DB and every route touching cluster_bindings.template 500'd until stamped by hand (2026-10-20 session). The dev loop must be migration-managed from the start: a task db-migrate entry point, and dev-stack must apply Alembic migrations instead of the create_all shortcut (with a stamp-then-upgrade heal for pre-existing create_all-based dev DBs like the one that bit us). Migrations are written to be idempotent against create_all-shaped dev DBs (has_table/column-exists guards), so this is safe.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 task db-migrate exists, is CWD-independent, and runs flask db upgrade against the dev DB (idempotent: a second run is a no-op)
- [x] #2 task dev-stack applies the schema via Alembic instead of db.create_all: fresh DB (after task dev-clean) boots at migration head with alembic_version present and the 4 built-in rbac_templates seeded
- [x] #3 A pre-existing create_all-based dev DB (no alembic_version table) heals to head via stamp <base> then upgrade when dev-stack runs, preserving its data
- [x] #4 After either path, the backend bootstraps and GET /api/v1/admin/users returns 200 (the failure mode that triggered this task)
- [x] #5 AGENTS.md dev-stack/Commands section documents the migration-managed flow (db-migrate + the dev-stack behavior change)
- [x] #6 Existing dev-stack behavior is preserved: idempotent re-run, compose up -d no-op, backend ready poll, fe-build/fe-sync before backend start
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
Research (this session): Taskfile.yaml dev-stack = compose up -d -> pg_isready -> free :8080 -> fe-build + fe-sync -> backend-create-schema (create_all internal task, dir backend) -> backend-stack-run (nohup wsgi.py + ready poll). The dev DB that bit us: no alembic_version, create_all tables; healed by `flask db stamp 6feadb091ff4` (the revision BEFORE user-management) + `flask db upgrade`. Migrations are idempotent vs create_all shapes (has_table/column guards), and 6feadb091ff4's upgrade is also guarded (the ADR-0021 local-auth columns).
1. Taskfile: add `db-migrate` task (dir backend: `uv run flask db upgrade`) — the manual entry point.
2. Replace backend-create-schema (create_all) with a migration-based schema task: (a) probe for alembic_version table; (b) if missing -> `flask db stamp af8aeb8ccf8a` (base) then `flask db upgrade`; if present -> `flask db upgrade` only. Keep the `{{.DB_URL}}` env passing create_app currently uses.
3. dev-stack wires the new task in place of backend-create-schema; all other steps untouched (AC #6).
4. Docs: AGENTS.md Commands section — document db-migrate + that dev-stack is migration-managed.
5. Verify: (fresh) task dev-clean + task dev-up + task db-migrate -> alembic_version present, 4 built-in templates seeded, admin/users 200 after backend start; (heal) the current create_all-shaped DB (if still present) -> dev-stack stamps+upgrades to head preserving data; task --list renders.
6. Commit (Taskfile.yaml + AGENTS.md only — the working tree carries unrelated observability files; do not stage them).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Heal-branch stamp target fix (found by the fresh-DB test): stamping the BASE revision af8aeb8ccf8a failed — its upgrade() does unguarded create_table('users'...), which blows up on a DB that already has the table (the stamp marks the base as APPLIED, so its create_table never runs for fresh DBs, but the NEXT revision's ALTER TABLE users assumes the table exists from the base's create_table... which it does on a create_all-era DB, yet the failing run showed 'relation users does not exist' — the fresh volume's DB was EMPTY because compose only creates the database, not the tables; the stamp branch must therefore stamp 6feadb091ff4, the only revision whose upgrade is fully idempotent against an EMPTY db (no-op on missing tables would still fail though)... RESOLUTION: the heal branch is for the create_all-era shape only; for an EMPTY db the probe must NOT take the stamp branch at all (an empty db has no users table either). Distinguish: empty db (no users table) -> plain upgrade from base; create_all-era db (users table present, no alembic_version) -> stamp 6feadb091ff4 + upgrade. Revised probe: (1) alembic_version present -> upgrade; (2) users table present -> stamp 6feadb091ff4 + upgrade; (3) neither -> upgrade (fresh).

All 3 shapes verified end-to-end against the real dev stack (2026-10-20): (1) FRESH — task dev-clean + dev-up + dev-stack: probe said 'Fresh database', all 4 migrations ran from base (af8aeb8ccf8a -> 704b7637d05c -> 6feadb091ff4 -> 3c9f21a7d5b4), head reached, 4 built-in templates seeded, backend ready, admin/users + admin/groups + my-access all 200. (2) LEGACY — DROP TABLE alembic_version on the migrated DB (simulates the create_all-era shape): probe said 'Legacy', stamped 6feadb091ff4, upgraded to head, backend ready. (3) MANAGED — re-run dev-stack at head: no-op upgrade, idempotent. db-migrate run twice from a subdirectory: both no-ops at head (CWD-independent).

Two bugs found+fixed during verification (in the commit's Tried: line): (a) stamping the base revision failed on the fresh-volume test — the base's upgrade() has unguarded create_table('users'), so 6feadb091ff4 is the correct stamp target; (b) set -e aborted the task on the probe's non-zero exit (legacy/fresh) before the case ran — probe now runs under set +e.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Dev DB is now migration-managed (closes the failure mode where merged migrations silently never ran on a create_all-era dev DB — /admin/users 500'd on 2026-10-20). task db-migrate: flask db upgrade against the dev DB (idempotent, CWD-independent). task dev-stack: schema via Alembic instead of the create_all shortcut, with a 3-shape probe — managed (alembic_version present) -> upgrade (no-op at head); legacy create_all-era DB (tables present, no alembic_version) -> stamp 6feadb091ff4 + upgrade (data preserved; the ADR-0021 revision is the safe stamp target because the base's upgrade() has unguarded create_table); fresh (empty database) -> upgrade from base. AGENTS.md documents the flow. All 3 shapes verified against the real compose stack: fresh boots at head with the 4 built-in RBAC templates seeded; legacy heals to head; managed re-run is a no-op; admin/users 200 after every path. Commit 7080fa47.
<!-- SECTION:FINAL_SUMMARY:END -->
