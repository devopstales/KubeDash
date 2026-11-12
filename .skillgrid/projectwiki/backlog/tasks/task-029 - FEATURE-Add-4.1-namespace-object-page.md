---
id: TASK-029
title: '[FEATURE] Add 4.1 namespace object page'
status: Done
assignee:
  - '@devopstales'
created_date: '2026-10-21 17:36'
updated_date: '2026-10-21 17:52'
labels: []
dependencies:
  - TASK-028
references:
  - .skillgrid/specs/2026-10-21-namespace-page/briefing.md
  - .skillgrid/specs/2026-10-21-namespace-page/blueprint.md
  - .skillgrid/specs/2026-10-21-namespace-page/acceptance.feature
documentation:
  - .skillgrid/specs/2026-10-21-namespace-page/briefing.md
priority: high
type: feature
ordinal: 29000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The shipped /cluster/namespace list renders the Namespace column as plain text, so operators cannot open the 4.1 Namespace Data page. TASK-028 restored the list and mutations but omitted namespace-data.html.j2. Restore name links and the object page on the header-selected cluster without inventing a second namespace API.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each namespace name in the list is a link to /cluster/namespace/data?name=<name>
- [x] #2 The Namespace Data page shows Status, Name, Created, Annotations, and Labels for the named namespace
- [x] #3 A missing name or a namespace not in the selected cluster list renders an error inside the card
- [x] #4 The page accepts the 4.1 ?namespace= query as the object name
- [x] #5 Vitest covers name links, object-page fields, missing-name, and missing-namespace cases
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
- [x] #6 Change-level acceptance scenarios for the object page are in acceptance.feature
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Commit the updated spec-zone briefing, blueprint Task 6, and object-page acceptance scenarios.
2. Write failing Vitest cases for name links and Namespace Data.
3. Link the Namespace column, add NamespaceData.tsx, and wire /cluster/namespace/data.
4. Run namespaces Vitest, task fe-build, and qlty on the touched files.
5. Verify the default name is a link to Namespace Data in the browser.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Verified 2026-10-21:
- pnpm vitest tests/views/namespaces.test.tsx tests/views/namespace_data.test.tsx → 12 passed
- Browser at http://localhost:3001: default/kube-system names open /cluster/namespace/data?name=…; ?namespace=kube-public works; missing name and gone render card errors
- qlty check eslint plugin failed (missing globals); pnpm lint on touched files reported only ignore warnings
Ruling: leftover ClusterRoleBinding/ServiceAccountData routes were stripped from the object-page commit and restored on disk.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Namespace names on /cluster/namespace now open Namespace Data at /cluster/namespace/data?name=<name>. The page shows status, name, created, annotations, and labels; it also accepts the 4.1 ?namespace= query. Verified with 12 Vitest tests and a live browser pass on default, kube-system, kube-public, missing name, and missing namespace.
<!-- SECTION:FINAL_SUMMARY:END -->
