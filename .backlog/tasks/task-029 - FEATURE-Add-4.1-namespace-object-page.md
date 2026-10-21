---
id: TASK-029
title: '[FEATURE] Add 4.1 namespace object page'
status: In Progress
assignee:
  - '@devopstales'
created_date: '2026-10-21 17:36'
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
- [ ] #1 Each namespace name in the list is a link to /cluster/namespace/data?name=<name>
- [ ] #2 The Namespace Data page shows Status, Name, Created, Annotations, and Labels for the named namespace
- [ ] #3 A missing name or a namespace not in the selected cluster list renders an error inside the card
- [ ] #4 The page accepts the 4.1 ?namespace= query as the object name
- [ ] #5 Vitest covers name links, object-page fields, missing-name, and missing-namespace cases
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Change-level acceptance scenarios for the object page are in acceptance.feature
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Commit the updated spec-zone briefing, blueprint Task 6, and object-page acceptance scenarios.
2. Write failing Vitest cases for name links and Namespace Data.
3. Link the Namespace column, add NamespaceData.tsx, and wire /cluster/namespace/data.
4. Run namespaces Vitest, task fe-build, and qlty on the touched files.
5. Verify the default name is a link to Namespace Data in the browser.
<!-- SECTION:PLAN:END -->
