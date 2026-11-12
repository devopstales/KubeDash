---
id: TASK-031
title: >-
  Build cluster node view (4.1 columns + per-node metrics + cluster tiles) at
  /cluster/node
status: Done
assignee: []
created_date: '2026-10-23 14:47'
updated_date: '2026-10-23 15:07'
labels: []
dependencies: []
ordinal: 31000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Execute .skillgrid/specs/2026-10-21-cluster-node blueprint. Tasks 1-3 (list_nodes, resources nodes row, /metrics/nodes endpoint) done in 09c38225/a953632b. Remaining: Task 4 four cluster metric tiles (CPU usage, Memory usage, Pods, Storage — Storage has no source → unknown) + Task 5 acceptance.feature + quality gate. Certainty rule: unknown never 0.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
