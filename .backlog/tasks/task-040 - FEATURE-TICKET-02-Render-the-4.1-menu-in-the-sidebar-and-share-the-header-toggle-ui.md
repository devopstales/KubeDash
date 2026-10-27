---
id: TASK-040
title: >-
  [FEATURE] TICKET-02 Render the 4.1 menu in the sidebar and share the header
  toggle (ui)
status: Done
assignee: []
created_date: '2026-10-21 11:37'
updated_date: '2026-10-21 11:55'
labels: []
milestone: m-1
dependencies:
  - TASK-024
references:
  - .skillgrid/specs/2026-10-21-sidebar-nav/briefing.md
  - .skillgrid/specs/2026-10-21-sidebar-nav/blueprint.md
  - .skillgrid/specs/2026-10-21-sidebar-nav/tasks.md
  - .skillgrid/specs/2026-10-21-sidebar-nav/acceptance.feature
documentation:
  - .skillgrid/specs/2026-10-21-sidebar-nav/briefing.md
priority: medium
type: feature
ordinal: 26000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Once the menu is defined as data (TICKET-01), the sidebar must render it from the selected cluster and the user role. The header menu button currently updates state that nothing reads, so it cannot show or hide the sidebar the way 4.1 does.

**Current State:**
- `AppSidebar` renders the static four-item array and owns its own visibility state.
- `AppHeader` keeps an unused `sidebarShow` state.

**Expected State:**
- `AppSidebar` renders `navigation()`; a shared sidebar store drives visibility from the header button; the footer fold button still only narrows the sidebar to icons.

Implementation plan: blueprint.md Task 2. Scenarios: tasks.md TICKET-02 SATISFIES. Blocked by TASK-024.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 With prod (id 7) selected, the Permissions section starts with a Cluster Details link to /clusters/7, then My access
- [ ] #2 The Workload entry shows a Beta badge and Cluster Metrics shows none
- [ ] #3 A non-admin sees no Settings group
- [ ] #4 The header menu button hides the sidebar and pressing it again shows it
- [ ] #5 The sidebar footer fold button narrows the sidebar without hiding it
- [ ] #6 Existing view tests and task fe-build still pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Scenarios sidebar-shows-cluster-details-link, workload-entry-shows-beta-badge, settings-hidden-for-non-admin, header-toggler-hides-sidebar, header-toggler-restores-sidebar, folding-the-sidebar-does-not-hide-it are green
<!-- DOD:END -->
