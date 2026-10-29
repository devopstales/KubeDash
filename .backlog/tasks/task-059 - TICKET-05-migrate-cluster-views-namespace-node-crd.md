---
id: TASK-059
title: 'TICKET-05: migrate cluster views (namespace, node, crd)'
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
ordinal: 55000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Session object navigation (2026-10-29-session-object-navigation, ADR-0040): migrate Cluster/Namespaces.tsx, NamespaceData.tsx, Nodes.tsx, NodeData.tsx, CRDs.tsx, CrdData.tsx to the ObjectRoute contract. NamespaceData's legacy ?namespace= bookmark read is replaced by the ref (the bookmark path becomes the R7 redirect in TASK-061). CrdData's two-call read (CRD + instances) is unchanged in shape - only the identity source moves to the ref. SATISFIES: opening an object from a list leaves the URL clean; the data page never carries identity params.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 clicking a namespace/node/CRD name renders the data view with location.search === ''
- [ ] #2 CrdData still issues its two API calls (CRD read + instances read) with the ref's name
- [ ] #3 pnpm test tests/views/namespaces* tests/views/namespace_data* tests/views/node* tests/views/crds* exits 0
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 pnpm test over the 4 test files green
- [ ] #7 CrdData two-call contract unchanged (asserted in test)
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: RED - re-point the 4 view test files. 2: migrate the 6 views (identity from ref; NamespaceData drops the 4.1-bookmark ?namespace= read). 3: App.tsx additive ObjectRoute wraps.
<!-- SECTION:PLAN:END -->
