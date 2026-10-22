---
id: TASK-030
title: >-
  Build cluster dashboard (Option C: concentric donuts + overcommit + events) at
  /dashboard/cluster-metric
status: In Progress
assignee: []
created_date: '2026-10-22 08:02'
updated_date: '2026-10-22 08:04'
labels: []
dependencies: []
references:
  - .skillgrid/specs/2026-10-21-cluster-dashboard/briefing.md
  - .skillgrid/specs/2026-10-21-cluster-dashboard/blueprint.md
  - .skillgrid/specs/2026-10-21-cluster-dashboard/adr.md
  - .skillgrid/specs/2026-10-21-cluster-dashboard/acceptance.feature
  - .skillgrid/prototypes/002-cluster-dashboard/dashboard-c-41-donut.html
priority: high
type: feature
ordinal: 30000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Execute .skillgrid/specs/2026-10-21-cluster-dashboard/ (briefing R1–R5, blueprint Tasks 1–7). The view routes at /dashboard/cluster-metric; the sidebar Cluster Metrics entry is retargeted to it (user decision 2026-10-22, supersedes the ADR-0022 pairing for this entry). TDD, one conventional commit per blueprint task. Backlog ticket: TASK-030.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
