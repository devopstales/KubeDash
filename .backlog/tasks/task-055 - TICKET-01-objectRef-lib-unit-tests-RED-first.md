---
id: TASK-055
title: 'TICKET-01: objectRef lib + unit tests (RED first)'
status: To Do
assignee: []
created_date: '2026-10-29 16:35'
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
- [ ] #1 objectRef.test.ts scenarios green: registry round-trip, token uniqueness, backdated-16-min expiry clears the active pointer, relay consume + self-delete, expired relay -> null, sweepRelay idempotent
- [ ] #2 cd frontend && corepack pnpm test tests/lib exits 0
- [ ] #3 no object identity (kind/name/namespace) is ever written to localStorage outside the token-scoped kd_ref_<token> relay keys
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test tests/lib green
- [ ] #7 git diff backend/ empty
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: write objectRef.test.ts RED (registry, expiry, relay, sweep). 2: implement objectRef.ts per blueprint section 1 until green. 3: verify no localStorage key survives a consumed handoff.
<!-- SECTION:PLAN:END -->
