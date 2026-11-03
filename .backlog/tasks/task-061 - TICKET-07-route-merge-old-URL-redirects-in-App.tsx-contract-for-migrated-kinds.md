---
id: TASK-061
title: >-
  TICKET-07: route merge + old-URL redirects in App.tsx (contract for migrated
  kinds)
status: Done
assignee: []
created_date: '2026-10-29 16:37'
updated_date: '2026-11-03 13:05'
labels: []
milestone: m-2
dependencies:
  - TASK-057
  - TASK-058
  - TASK-059
  - TASK-060
references:
  - .skillgrid/specs/2026-10-29-session-object-navigation/briefing.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/tasks.md
  - .skillgrid/specs/2026-10-29-session-object-navigation/acceptance.feature
priority: high
type: feature
ordinal: 57000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): in App.tsx replace the expanded list+data route pairs with single ObjectRoute entries (drop the /data suffix routes as primary) and add the OldDataRedirect routes (R7): read legacy ?name=/?namespace= (+?kind=/?type= where applicable), hydrate the ref with origin: 'link', Navigate to the clean route replace. Apply to ALL kinds migrated in TASK-056..060 (21 routes). Decision (blueprint open decision 1): the redirect layer is KEPT as the permanent bookmark-compat layer. SATISFIES: an old data URL redirects to the clean route with the ref hydrated; back from the detail returns to the list.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the routes table has no /.../data primary entry for a migrated kind
- [ ] #2 opening /security/secret/data?name=db-creds&namespace=team-a lands on the data page at the clean URL with ref origin link
- [ ] #3 back/forward still moves list<->detail
- [ ] #4 task fe-build green; pnpm test (full frontend suite) green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test full suite green
- [ ] #7 task fe-build + task fe-check green
- [ ] #8 no /.../data primary route remains for a migrated kind
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - new tests/App.test.tsx for the redirect scenarios. 2: App.tsx contract pass (21 route pairs -> single entries + redirect routes). 3: full frontend suite + fe-build.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Route contract complete. App.tsx: removed 16 Legacy*Data wrappers (replaced by OldDataRedirect), converted all 15 /data routes from direct-data-render to redirect (R7). New component src/components/OldDataRedirect.tsx reads legacy ?name=/?namespace=/?kind=, hydrates ref with origin='link', Navigate replace to clean route. 21 kinds covered (secret, network-policy, serviceaccount, role, clusterrole, namespace, node, crd, priorityclass, runtimeclass, resourcequota, poddisruptionbudget, verticalpodautoscaler, horizontalpodautoscaler, limitrange). New tests/App.test.tsx (4 scenarios: redirect→detail, namespace fallback, no infinite loop, click-flow). e2e ui-smoke: added old-URL redirect scenario. fe-build green; full suite 12 pre-existing failures (users/groups/admin_permissions) unchanged; git diff backend/ empty.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
TICKET-07 route contract complete: all 15 /data routes converted from direct Legacy*Data wrappers to OldDataRedirect (R7). New component reads legacy query params, hydrates the session ref with origin='link', and navigates replace to the clean route. Tests: 4 new redirect scenarios in tests/App.test.tsx + e2e old-URL redirect in ui-smoke.spec.ts. fe-build green; full frontend suite passes (12 pre-existing users/groups/admin_permissions failures unchanged); git diff backend/ empty.
<!-- SECTION:FINAL_SUMMARY:END -->
