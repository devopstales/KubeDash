---
id: TASK-099
title: >-
  Delete dead CoreUI header components (components/header/) - jscpd entry-point
  heuristic miss
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-08 10:28'
updated_date: '2026-11-08 11:05'
labels: []
dependencies: []
priority: low
ordinal: 95000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
frontend/src/components/header/ (index.js barrel + AppHeaderDropdown.jsx, ~90 lines) is dead: zero external references (verified 2026-11-08, grep over frontend/src|tests|e2e), AppHeaderDropdown's only importer is its own barrel. jscpd never flags the chain: index.* files get the entry-point heuristic (barrel not flagged as unused-file), so the components it re-exports are considered imported. AppHeaderDropdown.jsx additionally carries 9 <CIcon/> uses whose import was deleted by change D T04 (restored in fix round 2 - ReviewD04 Important finding). Pre-existing dead code, not orphaned by change D (unlike the views/icons/index.js addendum). Delete both files + verify build green; check AppSidebarNav.jsx and any other CoreUI header siblings for the same orphan class while in there. Branch-review addendum (2026-11-08, whole-branch review of change D): also clean the template-derived prose residue - frontend/ARCHITECTURE.md (lines ~134,216,305,413), frontend/DEVELOPMENT.md (~112,121), frontend/README.md (~164) still describe the deleted store.js / <WidgetsDropdown/> and the template Redux setup (app uses zustand). Pre-existing, already stale pre-change D; include in this template-residue cleanup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 components/header/ deleted; no dangling refs; task fe-build + task fe-check green
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->
