---
id: TASK-004
title: 'TICKET-03: v1 error contract + JWT/OIDC security core + auth API'
status: In Progress
assignee:
  - '@devopstales'
created_date: '2026-10-17 12:58'
updated_date: '2026-10-17 15:34'
labels: []
milestone: m-0
dependencies:
  - TASK-003
references:
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/blueprint.md
  - .skillgrid/specs/2026-10-17-kubedash-base-structure/tasks.md
priority: high
type: feature
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
SDD ticket: KubeDashHttpError hierarchy with the 8 stable v1 codes (one-way OD-1), security.py (Authlib oidc_authorize_url(state)/oidc_exchange real bodies, issue/verify JWT with jti revocation set, rotate_refresh delete-on-consume, OIDC state round-trip), AuthApi login/callback/refresh/logout/me, JWT delivery contract (302 -> /?token=...&refresh=...), MockOIDC test pair. Current: no auth. Expected: full OIDC round trip issues a working JWT; every protected route 401s without it.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 pytest tests/api/test_auth.py tests/test_errors.py green: login->me echoes sub; state mismatch 400 STATE_MISMATCH; no JWT 401 stable shape; expired JWT 401; refresh reuse 401 AND consumed row deleted; error envelope shape
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level DoD: briefing.md R2 acceptance met; OD-1 human checkpoint passed; spec-zone code commit
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. app/core/errors.py KubeDashHttpError + 8 code subclasses
2. app/core/security.py (Authlib pair, token pair, verify+revocation, rotate delete-on-consume, state)
3. app/api/auth.py AuthApi + register in api/__init__.py; schemas
4. tests/api/conftest.py MockOIDC pair + auth_client; tests/api/test_auth.py + tests/test_errors.py
5. pytest green; commit (Refs: TASK-003)
<!-- SECTION:PLAN:END -->
