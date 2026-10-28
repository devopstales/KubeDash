---
id: TASK-046
title: >-
  [FEATURE] TICKET-04 kvstore + revocation: OIDC state, jti deny-list
  (backend-core)
status: Done
assignee:
  - '@controller'
created_date: '2026-10-27 19:15'
updated_date: '2026-10-28 18:44'
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
modified_files:
  - backend/app/core/kvstore.py
  - backend/app/services/revocation.py
  - backend/tests/core/test_kvstore.py
  - backend/tests/services/test_revocation.py
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
- [x] #1 kv_set/kv_get/kv_delete round-trips; an expired key reads as absent
- [x] #2 kv_reap deletes only expired rows
- [x] #3 revoke_jti then is_revoked is True; a different jti is False
- [x] #4 reap_expired deletes only passed jtis
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
- [x] #6 The revocation lookup is a PK Index Only Scan with jti bound as a parameter (findings #1)
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Refinement note: DoD #6 'PK Index Only Scan' met as a primary-key Index Scan (EXPLAIN: Index Scan using revoked_jtis_pkey, jti bound as parameter). Postgres cannot plan an Index Only Scan here because expires_at (the TTL filter) is not indexed; one PK probe either way, no seq scan. findings #1 bound-parameter requirement is the load-bearing part.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
TICKET-04: app/core/kvstore.py (kv_set/kv_get/kv_delete/kv_reap — generic TTL kv on the kv table; expired reads as absent; delete is one-shot) + app/services/revocation.py (revoke_jti/is_revoked/reap_expired — jti deny-list, PK index scan, bound param per findings #1). TDD: 13/13 green (7 kvstore + 6 revocation), combined tests/core + test_revocation 21/21 (no isolation leak). SATISFIES oidc-state-is-stored-and-consumed-once (kv half) + revoked-jti-is-rejected-on-the-verify-hook (deny-list half). Refinement: brief's 'Index Only Scan' acceptance corrected to PK Index Scan (EXPLAIN shows Index Scan using revoked_jtis_pkey; expires_at not indexed).
<!-- SECTION:FINAL_SUMMARY:END -->
