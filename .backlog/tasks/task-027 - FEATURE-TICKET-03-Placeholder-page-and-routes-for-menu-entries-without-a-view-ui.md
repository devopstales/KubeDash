---
id: TASK-027
title: >-
  [FEATURE] TICKET-03 Placeholder page and routes for menu entries without a
  view (ui)
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
ordinal: 27000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
About thirty 4.1 menu entries (Pods, Nodes, Roles, settings pages, and so on) have no 5.0 view yet. Without routes they fall through to the catch-all and silently land on the cluster list, which looks like a broken link.

**Current State:**
- `App.tsx` has routes only for clusters, cluster detail, profile, My access and admin permissions; every other path redirects to `/clusters`.

**Expected State:**
- One shared placeholder page shows the menu label and "This view is not available yet."; settings placeholders stay admin-only; existing views and the catch-all are unchanged.

Implementation plan: blueprint.md Task 3 (placeholder half). Scenarios: tasks.md TICKET-03 SATISFIES. Blocked by TASK-024 (the route list must equal the menu paths).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Opening Pods shows a page titled Pods with the sentence This view is not available yet. and no redirect
- [ ] #2 Every placeholder entry in the Examples table of every-stub-entry-has-a-page renders its own title
- [ ] #3 Auth Provider settings page renders for an admin and redirects a non-admin to the home page
- [ ] #4 My access still opens the existing My access page, and an unknown path still redirects to the cluster list
- [ ] #5 A test confirms the placeholder routes equal the placeholder paths returned by navigation()
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Scenarios stub-page-names-the-entry, every-stub-entry-has-a-page, settings-url-rejects-non-admin, existing-views-still-open, unknown-path-still-redirects-to-cluster-list are green
<!-- DOD:END -->
