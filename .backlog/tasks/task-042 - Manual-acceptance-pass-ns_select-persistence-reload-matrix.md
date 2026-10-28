---
id: TASK-042
title: 'Manual acceptance pass: ns_select persistence reload matrix'
status: To Do
assignee: []
created_date: '2026-10-27 12:47'
labels: []
dependencies: []
priority: medium
type: task
ordinal: 38000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Run the manual browser acceptance matrix for the ns_select persistence change (spec .skillgrid/specs/2026-10-27-ns-select-persist/, acceptance 1-5):

1. Select cluster + namespace in header, hard reload → same cluster/ns restored.
2. Switch namespace, reload → new value restored.
3. Switch cluster (disjoint ns set), submit ns there, reload → that cluster+ns restored; switching back restores the first cluster's ns.
4. Delete the selected namespace on the Namespaces page → store null, select falls back, localStorage holds null.
5. Clear localStorage → header behaves as before (fallback chain, no crash).

Requires the dev stack: `task dev-stack` (plain HTTP, ADR-0027) or `task dev-stack-ssl`, then `task fe-dev`. Blueprint steps 3-5 of Task 1 are deferred to this pass.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
