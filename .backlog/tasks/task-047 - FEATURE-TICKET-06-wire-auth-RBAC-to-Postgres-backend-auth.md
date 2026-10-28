---
id: TASK-047
title: '[FEATURE] TICKET-06 wire auth + RBAC to Postgres (backend-auth)'
status: Done
assignee: []
created_date: '2026-10-27 19:16'
updated_date: '2026-10-28 19:53'
labels: []
milestone: m-2
dependencies:
  - TASK-046
references:
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/briefing.md
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/blueprint.md
  - .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/tasks.md
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/acceptance.feature
documentation:
  - >-
    .skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/blueprint.md
priority: high
type: feature
ordinal: 43000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Swap the four Redis call sites to Postgres (ADR-0030). Current State: security.py verify_jwt/new_state/consume_state + api/auth.py logout + rbac.py SAR cache read redis_client. Expected State: verify_jwt -> revocation.is_revoked(db.engine, jti); new_state/consume_state -> kvstore (one-shot); logout -> revocation.revoke_jti(db.engine, _current_jti(), ACCESS_TTL_SECONDS) (keep refresh-token revocation; add the _current_jti() helper in security.py); rbac._cache_get/_cache_set -> kvstore (drop redis_client import + bytes-decode branch). The sar:<...> key shape is unchanged (ADR-0004 addendum).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a logged-out token jti, replayed -> 401 token revoked before expiry
- [ ] #2 verify_jwt raises on a revoked_jtis hit
- [ ] #3 consume_state is one-shot (second consume -> StateMismatchError)
- [ ] #4 rbac.can on a cached key serves from kv and never re-asks the cluster
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 The sar:<...> key shape is unchanged (ADR-0004 addendum - every SAR attribute in the key)
<!-- DOD:END -->
