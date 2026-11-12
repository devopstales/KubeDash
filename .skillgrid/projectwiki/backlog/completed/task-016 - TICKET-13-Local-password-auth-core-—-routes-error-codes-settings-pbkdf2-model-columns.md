---
id: TASK-016
title: >-
  TICKET-13: Local password auth core — routes, error codes, settings, pbkdf2,
  model columns
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-21 07:18'
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
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Local password auth core (ADR-0021): POST /auth/local + GET /auth/settings as sibling routes of the OIDC callback, sharing the extracted redirect_with_tokens + _issue_and_persist seams; 401 INVALID_CREDENTIALS (no enumeration, SSO-collision gate) / 403 LOCAL_AUTH_DISABLED; stdlib pbkdf2 helpers; password_hash + auth_source model columns; double-prefix bootstrap settings + admin_kubeconfig declared. Verified: 20/20 focused pytest (incl. OIDC door-check exact-match on both sides), api tier 48 passed, ruff + mypy clean. Report: .skillgrid/sdd/2026-10-17-authentication-vertical/task-1-report.md
<!-- SECTION:FINAL_SUMMARY:END -->
