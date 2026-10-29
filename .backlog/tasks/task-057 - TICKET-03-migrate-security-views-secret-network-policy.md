---
id: TASK-057
title: 'TICKET-03: migrate security views (secret, network-policy)'
status: To Do
assignee: []
created_date: '2026-10-29 16:36'
labels: []
milestone: m-2
dependencies:
  - TASK-056
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 53000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): migrate Security/Secret.tsx, SecretData.tsx, NetworkPolicy.tsx, NetworkPolicyData.tsx to the ObjectRoute contract. Secret: drop the ?selected= bolding hint (R9) - bolding reads getActiveRef(). NetworkPolicy: ?kind=/?type= stay genuine filters (R9); identity via ref. The R8 test (header default, ref team-a -> API read team-a) lands in tests/views/secrets.test.tsx. SATISFIES: the ref's namespace wins over the header selector; the selected bolding hint is replaced by the active ref; a genuine filter param may remain a query param.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 clicking a secret/policy name renders the data view with location.search === ''
- [ ] #2 with the header on default and a ref for team-a, the API read is for team-a and the Namespace row renders team-a
- [ ] #3 no ?selected= in any produced navigation URL
- [ ] #4 pnpm test tests/views/secrets* tests/views/network_polic* exits 0
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test tests/views/secrets* tests/views/network_polic* green
- [ ] #7 no ?selected= producer remains in src/views
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - re-point secrets/network_policy tests (search === '', ref-driven render, R8 case). 2: migrate the 4 views (identity from ref, drop ?selected=). 3: App.tsx additive ObjectRoute wraps.
<!-- SECTION:PLAN:END -->
