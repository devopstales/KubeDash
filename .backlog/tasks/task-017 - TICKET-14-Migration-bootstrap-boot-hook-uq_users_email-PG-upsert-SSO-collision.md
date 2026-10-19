---
id: TASK-017
title: >-
  TICKET-14: Migration + bootstrap boot hook (uq_users_email, PG upsert, SSO
  collision)
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-18 12:00'
labels: []
milestone: m-0
dependencies:
  - TASK-016
priority: high
type: feature
ordinal: 17000
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
1. TDD: write failing tests (tests/test_bootstrap.py: boot creates exactly one admin row; second boot idempotent; env password change updates hash for local rows; env unset no-op; SSO-collision test in PG tier; tests/test_models.py amendment: new columns + email unique). 2. Implement: Alembic revision (2 columns + uq_users_email, down-ref 704b7637d05c), models/user.py email unique=True + sub comment, _bootstrap_local_admin(app) in app/__init__.py (PG upsert, case-gated auth_source+password_hash per I-NEW-2), wsgi.py call after create_app, _upsert_user explicit auth_source='oidc', root PG conftest I-NEW-1 env triple. 3. Verify: pytest tests/test_bootstrap.py tests/test_models.py tests/api/test_local_auth.py -v (PG tier via Testcontainers), full api tier, ruff, mypy. 4. Commit per work-unit-commits.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TICKET-14 complete. commit 7474c9a2. Gated: tests/test_bootstrap.py + tests/test_models.py = 11 passed (PG tier, Testcontainers); tests/api/test_local_auth.py 7 passed; tests/api/test_auth.py 13 passed (api tier); ruff + mypy clean. Migration 6feadb091ff4 (down-ref 704b7637d05c): password_hash nullable, auth_source NOT NULL DEFAULT oidc, uq_users_email unique constraint (C-NEW-1). _bootstrap_local_admin(app) in app/__init__.py: PG upsert ON CONFLICT(email) DO UPDATE, case-gated auth_source+password_hash refresh for auth_source='local' rows only (I-NEW-2 SSO-wins: an oidc row keeps its SSO identity AND its hash across boots). wsgi.py calls hook after create_app, before Leader/RQ. _upsert_user writes auth_source='oidc' explicitly. models/user.py: email unique=True, sub comment documents reserved local: prefix (M-NEW-1). Decision: SSO-collision test lives in PG tier (test_bootstrap.py) not tests/api/test_auth.py — the hook is PG-dialect and the sqlite api tier skips the hook; 401 consequence pinned in test_local_auth.py. Migration test runs the real revision upgrade() through MigrationContext and asserts uq_users_email in pg_constraint.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Local admin bootstrap (ADR-0021): additive Alembic migration 6feadb091ff4 (password_hash, auth_source NOT NULL DEFAULT 'oidc', uq_users_email unique constraint) + _bootstrap_local_admin boot hook — idempotent PG upsert at boot (wsgi.py, after create_app, before leader/RQ), case-gated so an SSO-claimed row keeps auth_source='oidc' and its password_hash (SSO wins; local login then 401). Verified: 11/11 PG-tier bootstrap+models (incl. idempotent second boot, env password rotation, env-unset no-op, SSO-collision hash-freeze), 7/7 local auth, 13/13 OIDC auth, ruff+mypy clean. Review clean (0 critical/important).
<!-- SECTION:FINAL_SUMMARY:END -->
