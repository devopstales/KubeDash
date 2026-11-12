---
id: TASK-030
title: >-
  Build cluster dashboard (Option C: concentric donuts + overcommit + events) at
  /dashboard/cluster-metric
status: Done
assignee: []
created_date: '2026-10-22 08:02'
updated_date: '2026-10-23 08:59'
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Cluster dashboard (Option C) delivered at /dashboard/cluster-metric: pure allocation rollup (cluster_allocation.py), K8sClient list_nodes/node_usage/list_events (metrics.k8s.io via call_api), GET /clusters/<id>/metrics/summary (two-tier SAR gate) + GET /clusters/<id>/events, ConcentricDonut component (3-ring, overcommit red bar, unknown-never-zero, theme-aware), Cluster/Dashboard view, nav retarget (Cluster Metrics -> /dashboard/cluster-metric). Gates: backend 336, frontend 128, fe-check, jscpd clean; final two-axis review + fix wave (commits 9e0df88f..d29748f6 on rebase). Backstop pending: live e2e + kind smoke need a dev stack.
<!-- SECTION:FINAL_SUMMARY:END -->
