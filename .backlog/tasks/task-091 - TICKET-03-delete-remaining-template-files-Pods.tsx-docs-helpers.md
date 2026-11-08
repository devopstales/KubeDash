---
id: TASK-091
title: 'TICKET-03: delete remaining template files, Pods.tsx, docs helpers'
status: Done
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
updated_date: '2026-11-08 10:22'
labels: []
milestone: m-3
dependencies:
  - TASK-090
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-dead-code-cleanup/briefing.md
priority: high
type: chore
ordinal: 87000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): delete the verified `views/authentication/**`, `views/charts/Charts.jsx`, `views/icons/**`, `views/error-pages/**`, `components/{AppContent,DocsComponents,DocsExample,DocsIcons,DocsLink}.jsx` (re-verified AFTER TICKET-02 — the 37 demo files that imported them from the `src/components` barrel are gone), `store.js`, `views/Cluster/Pods.tsx` (re-checked against the route table: `App.tsx` lazy imports + `stubRoutes` — it sits in a live view directory).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 no template demo page remains in `frontend/src/views`; no import specifier for a deleted file remains; `corepack pnpm test && task fe-build && task fe-check` green at this commit.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: template-tail-deleted
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: delete the verified `views/authentication/**`, `views/charts/Charts.jsx`, `views/icons/**`, `views/error-pages/**`, `components/{AppContent,DocsComponents,DocsExample,DocsIcons,DocsLink}.jsx` (re-verified AFTER TICKET-02 — the 37 demo files that imported them from the `src/components` barrel are gone), `store.js`, `views/Cluster/Pods.tsx` (re-checked against the route table: `App.tsx` lazy imports + `stubRoutes` — it sits in a live view directory).. 2: verify per Acceptance: no template demo page remains in `frontend/src/views`; no import specifier for a deleted file remains; `corepack pnpm test && task fe-build && task fe-check` green at this commit.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-11-08 08:52
---
Execution started 2026-11-08 (subagent-execution, wave 3, ImplD03 flint, parallel with T04; batch = report rows labeled T03 incl. row-59 addendum = 20 files / 1,528 lines)
---

created: 2026-11-08 10:22
---
Executed 2026-11-08: commit f724c5d4 (20 files / 1,528 deletions incl. row-59 addendum; zero-hit re-verify incl. Pods.tsx route-table + docs-helpers barrel checks); review Approved (ReviewD03) 0C/0I/1M - icons barrel orphan deleted as addendum row 60 (c40d4c49, controller). SATISFIES: template-tail-deleted.
---
<!-- COMMENTS:END -->
