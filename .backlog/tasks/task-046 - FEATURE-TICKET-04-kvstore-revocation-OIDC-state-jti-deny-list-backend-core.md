---
id: TASK-046
title: >-
  [FEATURE] TICKET-04 kvstore + revocation: OIDC state, jti deny-list
  (backend-core)
status: To Do
assignee: []
created_date: '2026-10-27 19:15'
updated_date: '2026-10-27 19:16'
labels: []
milestone: m-2
dependencies:
  - TASK-042
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
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The generic TTL kv store + the jti deny-list (ADR-0030). Current State: OIDC state + jti revocation + SAR verdict live in Redis. Expected State: app/core/kvstore.py with kv_set/kv_get/kv_delete/kv_reap (kv_get returns None if absent OR expired; kv_delete is one-shot) and app/services/revocation.py with revoke_jti/is_revoked/reap_expired (pure, no Flask). Both bind the key/jti as a PARAMETER - no function in the WHERE clause (findings #1). The revocation lookup plans as a PK Index Only Scan.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 kv_set/kv_get/kv_delete round-trips; an expired key reads as absent
- [ ] #2 kv_reap deletes only expired rows
- [ ] #3 revoke_jti then is_revoked is True; a different jti is False
- [ ] #4 reap_expired deletes only passed jtis
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 The revocation lookup is a PK Index Only Scan with jti bound as a parameter (findings #1)
<!-- DOD:END -->
