---
id: TASK-025
title: '[FEATURE] TICKET-04 Admin tab from menu link and 4.1 footer without links (ui)'
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
  - .skillgrid/artifacts/04-adr-0020-air-gap-deployment.md
priority: medium
type: feature
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The 4.1 menu has separate Users and Audit Log entries, but the 5.0 admin permissions page always opens on the Users tab, so an Audit Log menu link would land on the wrong tab. The footer also links to an external CoreUI docs URL, which the air-gapped bundle must not contain (ADR-0020).

**Current State:**
- `AdminPermissionsView` always starts on Users.
- `AppFooter` contains an outbound `<a href>`.

**Expected State:**
- The `?tab=` query picks the initial tab; unknown values fall back to Users.
- The footer shows the 4.1 wording as plain text.

Implementation plan: blueprint.md Task 3 (admin tab and footer half). Scenarios: tasks.md TICKET-04 SATISFIES. Independent of TICKET-01.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 At /admin/permissions?tab=audit the Audit tab is selected and shows the existing empty state
- [ ] #2 An unknown tab value selects Users
- [ ] #3 A non-admin at /admin/permissions?tab=audit is redirected to the home page
- [ ] #4 Footer shows "DevOpsTales - KubeDash Copyright © 2021-2026" and "Powered by CoreUI UI Components" with no links
- [ ] #5 task fe-check exits 0
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 Scenarios audit-tab-opens-from-menu, unknown-tab-falls-back-to-users, non-admin-cannot-open-audit-tab, footer-shows-4-1-labels, footer-has-no-outbound-link, bundle-passes-air-gap-check are green
<!-- DOD:END -->
