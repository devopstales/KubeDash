---
id: TASK-059
title: 'TICKET-05: migrate cluster views (namespace, node, crd)'
status: Done
assignee: []
created_date: '2026-10-29 16:36'
updated_date: '2026-11-03 11:58'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Starting: read templates + all 6 Cluster views + tests. Migrating now.

Migrated 6 Cluster views (Namespaces/NamespaceData/Nodes/NodeData/CRDs/CrdData) to ADR-0040 ObjectRoute: list names are buttons (openObject, cluster-scoped, no namespace) + ShareObjectButton; data views take {name} as props (useSearchParams gone, 4.1 ?namespace= bookmark fallback kept on the legacy /data wrapper in App.tsx); App.tsx wraps all three kinds in ObjectRoute alongside the legacy /data routes. Re-pointed 4 test files (26 tests): click→detail with location.search === '' (R1); CrdData test asserts its two calls (CRD read + instances read) carry the ref's name, instances adding the topbar namespace. STYLEGUIDE name-cell example updated. Verified: 4 test files pass, task fe-build green, git diff -- backend/ empty.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Cluster views (namespace/node/crd) migrated to the ADR-0040 ObjectRoute contract per the priorityclass/secret templates. List views: name cells are buttons calling openObject(kind, name, undefined, listRoute, navigate) with a ShareObjectButton beside each; the URL never carries identity (R1). Data views: useSearchParams deleted, identity arrives as a {name} prop from ObjectRoute's active ref (R8); NamespaceData's 4.1 ?namespace= bookmark read moved to the legacy /data wrapper (TICKET-07's R7 redirect supersedes it); CrdData's two-call read (CRD + instances) is unchanged in shape. App.tsx: /cluster/namespace, /cluster/node, /cluster/crd wrapped in ObjectRoute; the old /data routes stay (LegacyNamespaceData/LegacyNodeData/LegacyCrdData) for TICKET-07 — expand, not contract. Tests re-pointed: link assertions → click→detail-render with window.location.search === ''; CrdData test captures both request URLs and asserts the ref's name on both (instances additionally carries the topbar namespace). All acceptance criteria verified: 4 test files green (26 tests), task fe-build green, git diff -- backend/ empty.
<!-- SECTION:FINAL_SUMMARY:END -->
