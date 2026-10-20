---
id: TASK-016
title: >-
  TICKET-13: Local password auth core — routes, error codes, settings, pbkdf2,
  model columns
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-20 15:45'
labels: []
milestone: m-0
dependencies: []
priority: high
type: feature
ordinal: 16000
---

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TICKET-13 complete. commit 208c0bf9. Gated: tests/api/test_local_auth.py + test_auth.py = 20 passed (exit 0); api tier not-integration = 48 passed; ruff + mypy clean. Deviation from brief: verify_password snippet's 5-way split('$') is wrong for the format (3 $-fields; algo token colon-split) — fixed, recorded in commit Tried: line. Also: TypeError added to verify_password catch; scalar_one_or_none on email lookup (NoResultFound->500); test_errors.py count guard 10->12 (OD-B).

Finalization (this session): task body was already complete at commit 208c0bf9 (verified in git log) — the In Progress status was a stale state from the T1 session that never closed out. No code changes this session; DoD #5 (spec/docs) closed on the same basis as the other auth-vertical tickets: ADR-0021 bookkeeping is owned by TASK-022 (completed).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Local password auth core (ADR-0021): POST /auth/local + GET /auth/settings as sibling routes of the OIDC callback, sharing the extracted redirect_with_tokens + _issue_and_persist seams; 401 INVALID_CREDENTIALS (no enumeration, SSO-collision gate) / 403 LOCAL_AUTH_DISABLED; stdlib pbkdf2 helpers; password_hash + auth_source model columns; double-prefix bootstrap settings + admin_kubeconfig declared. Verified: 20/20 focused pytest (incl. OIDC door-check exact-match on both sides), api tier 48 passed, ruff + mypy clean. Commit 208c0bf9. Report: .skillgrid/sdd/2026-10-17-authentication-vertical/task-1-report.md

Finalization (this session): no new code — the work was already committed and verified; closing the stale In Progress state (see notes).
<!-- SECTION:FINAL_SUMMARY:END -->
