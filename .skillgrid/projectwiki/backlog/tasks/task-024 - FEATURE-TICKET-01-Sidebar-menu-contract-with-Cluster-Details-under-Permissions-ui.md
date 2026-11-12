---
id: TASK-024
title: >-
  [FEATURE] TICKET-01 Sidebar menu contract with Cluster Details under
  Permissions (ui)
status: Done
assignee: []
created_date: '2026-10-21 11:37'
updated_date: '2026-10-21 11:46'
labels: []
milestone: m-1
dependencies: []
references:
  - .skillgrid/specs/2026-10-21-sidebar-nav/briefing.md
  - .skillgrid/specs/2026-10-21-sidebar-nav/blueprint.md
  - .skillgrid/specs/2026-10-21-sidebar-nav/tasks.md
  - .skillgrid/specs/2026-10-21-sidebar-nav/acceptance.feature
documentation:
  - .skillgrid/specs/2026-10-21-sidebar-nav/briefing.md
  - .skillgrid/artifacts/04-adr-0022-sidebar-nav-4-1-parity.md
priority: high
type: feature
ordinal: 24000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The sidebar is four flat items, so operators coming from KubeDash 4.1 cannot find resources where they left them and new views have no agreed menu slot. This ticket defines the menu as data: the 4.1 structure (Dashboard, Permissions, Interface, admin-only Settings) without Plugins, with Cluster Details first under Permissions. It is the door check for the change: if the existing sidebar renderer cannot take this shape, stop before TICKET-02/03.

**Current State:**
- `frontend/src/_nav.tsx` exports four flat items; Cluster detail is hardcoded to `/clusters/1`.

**Expected State:**
- `navigation({ clusterId, isAdmin })` returns the rows in briefing.md § Menu.

Implementation plan: blueprint.md Task 1. Scenarios: tasks.md TICKET-01 SATISFIES. 4.1 is a visual reference only; no Jinja.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 navigation({ clusterId: 7, isAdmin: true }) flattens to exactly the label order in briefing.md § Menu
- [ ] #2 Cluster Details is the first Permissions entry and links to /clusters/7; with clusterId null it links to /clusters
- [ ] #3 isAdmin false omits the Settings group and Auth Provider, Kubernetes Cluster, HA Status, Audit Log
- [ ] #4 Plugins, Cert-Manager, LoadBalancers, Gateway API, Trivy Operator and Applications never appear
- [ ] #5 Vitest tests are titled with the SATISFIES scenario names and pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Scenarios menu-matches-4-1-without-plugins, cluster-details-follows-selection, cluster-details-without-selection-opens-cluster-list, plugin-entries-never-appear, cluster-metrics-and-kubernetes-cluster-share-cluster-list are green
<!-- DOD:END -->
