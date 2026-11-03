---
id: TASK-055
title: 'TICKET-01: objectRef lib + unit tests (RED first)'
status: Done
assignee:
  - '@paladm'
created_date: '2026-10-29 16:35'
updated_date: '2026-11-03 10:40'
labels: []
milestone: m-2
dependencies: []
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 51000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): implement frontend/src/lib/objectRef.ts per the blueprint contract (sessionStorage registry kd_object_refs + active pointer kd_object_active, 15-min lazy self-expiry, crypto token mint, openObject, postObjectToTab hidden-form POST with 60s self-deleting localStorage relay kd_ref_<token>, consumeIncoming, sweepRelay) plus frontend/tests/lib/objectRef.test.ts. No view changes in this ticket - the lib and its RED-first unit tests only.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 objectRef.test.ts scenarios green: registry round-trip, token uniqueness, backdated-16-min expiry clears the active pointer, relay consume + self-delete, expired relay -> null, sweepRelay idempotent
- [x] #2 cd frontend && corepack pnpm test tests/lib exits 0
- [x] #3 no object identity (kind/name/namespace) is ever written to localStorage outside the token-scoped kd_ref_<token> relay keys
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
- [x] #6 pnpm test tests/lib green
- [x] #7 git diff backend/ empty
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: write tests/lib/objectRef.test.ts RED (registry round-trip, token uniqueness, backdated-16-min expiry, relay consume+self-delete, expired relay null, sweepRelay idempotent, no identity outside kd_ref_ keys). 2: implement src/lib/objectRef.ts per blueprint section 1 until green. 3: verify localStorage invariant (only kd_ref_<token> keys carry identity) + pnpm test tests/lib exits 0.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented objectRef.ts (registry, active pointer with lazy 15-min expiry, mintToken 32-bit hex, openObject, postObjectToTab with token-scoped localStorage relay + 60s expiry + self-delete, consumeIncoming with ?o= strip, sweepRelay idempotent). 22 unit tests in tests/lib/objectRef.test.ts all green. Stubbed HTMLFormElement.prototype.submit in tests/setup.ts to silence jsdom 'Not implemented' noise (jsdom's submit is a no-op; a real browser's submit IS the POST navigation). Full suite: same 13 pre-existing failures as on clean tree (users/groups/node/admin_permissions views, in-flight TASK-041 work) — no new failures introduced. tsc --noEmit green. git diff backend/ empty.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added frontend/src/lib/objectRef.ts (registry + active pointer with lazy 15-min expiry, mintToken 32-bit hex, openObject, postObjectToTab with token-scoped localStorage relay + 60s expiry + self-delete, consumeIncoming with ?o= strip, sweepRelay idempotent) + frontend/tests/lib/objectRef.test.ts (22 scenarios: registry round-trip, token uniqueness, backdated-16-min expiry, relay consume + self-delete, expired relay null, sweepRelay idempotent, no identity outside kd_ref_ keys). Stubbed HTMLFormElement.prototype.submit in tests/setup.ts to silence jsdom 'Not implemented' noise. Verified: pnpm test tests/lib exits 0 (22/22), tsc --noEmit clean, git diff backend/ empty, full suite shows same 13 pre-existing failures as clean tree (no new failures). Blocks TICKET-02 (TASK-056).
<!-- SECTION:FINAL_SUMMARY:END -->
