---
id: TASK-057
title: 'TICKET-03: migrate security views (secret, network-policy)'
status: Done
assignee: []
created_date: '2026-10-29 16:36'
updated_date: '2026-11-03 11:17'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
TICKET-03 security batch: migrating Secret + NetworkPolicy to ObjectRoute contract. Pattern confirmed from priorityclass template (cluster-scoped) — security is namespaced. Views: Secret/SecretData/NetworkPolicy/NetworkPolicyData. App.tsx wrap both alongside /data routes. Tests re-point + R8.

Views migrated: Secret (button+ShareObjectButton, getActiveRef bold, dropped ?selected=), SecretData (props {name,namespace}, dropped useSearchParams + fallback, added ShareObjectButton), NetworkPolicy (button+ShareObjectButton per-kind), NetworkPolicyData (props {name,kind,namespace}, dropped useSearchParams, added ShareObjectButton). App.tsx: secret wrapped in ObjectRoute + LegacySecretData /data route; network-policy uses NetworkPolicyRoute dispatcher (matches 3 policy kinds) + LegacyNetworkPolicyData /data route. ObjectRoute.tsx: added registerNavigate seam export (used by dispatcher). Tests re-pointed + R8 test added. tsc clean, security tests 24/24 pass, build green, backend diff empty.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
TICKET-03 done: migrated Security views (Secret, SecretData, NetworkPolicy, NetworkPolicyData) to the ADR-0040 ObjectRoute contract. List views: name cell is now a button calling openObject (kind = API kind for policies) + ShareObjectButton in the cell; the Secret view bolds the opened row from getActiveRef() instead of a ?selected= param (R9). Data views receive {name,namespace} (and {name,kind,namespace} for policies) as props from ObjectRoute — useSearchParams + the || selectedNamespace || 'default' fallback are gone (R1/R8), and each data header carries a ShareObjectButton. App.tsx wraps the secret route in ObjectRoute + keeps a LegacySecretData /data route; the network-policy route uses a NetworkPolicyRoute dispatcher that matches all three policy API kinds on the clean route + keeps a LegacyNetworkPolicyData /data route (expand, not contract — old /data routes stay for TICKET-07). ObjectRoute.tsx gained a registerNavigate seam export (used by the dispatcher). Tests re-pointed: link assertions → button + clean-URL click assertions; data-view tests render with identity props and assert window.location.search === '' (R1); added the R8 test (header 'default', ref 'team-a' → API read 'team-a'). tsc --noEmit clean; cd frontend && corepack pnpm test tests/views/secrets* tests/views/network_polic* → 24/24 pass; pnpm build green; git diff backend/ empty. Pre-existing failures in groups/users/node/admin_permissions (verified failing without my changes).
<!-- SECTION:FINAL_SUMMARY:END -->
