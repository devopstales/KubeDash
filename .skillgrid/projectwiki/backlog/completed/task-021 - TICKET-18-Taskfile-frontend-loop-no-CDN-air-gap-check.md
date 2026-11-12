---
id: TASK-021
title: 'TICKET-18: Taskfile frontend loop + no-CDN air-gap check'
status: Done
assignee:
  - '@skillgrid-agent'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-21 07:22'
labels: []
milestone: m-0
dependencies: []
priority: medium
type: feature
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Implemented and shipped in f191ddbf: scripts/fe-airgap-check.mjs (ESM, zero-dep; default allow-list pinned by I-NEW-3 pre-flight over real frontend/dist), root Taskfile fe-install/fe-build/fe-sync/fe-dev/fe-check, backend/static/ in .gitignore, 4/4 pytest fixtures (TDD red->green). Follow-up (not a defect): AppHeader/AppFooter carry devopstales.github.io links from the CoreUI template — air-gap check now reports them as offenders (exit 1); needs an allow-list entry or link removal in a future ticket.
<!-- SECTION:DESCRIPTION:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
- [x] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. TDD: write backend/tests/test_fe_airgap_check.py (4 fixture cases) and record RED (script missing)
2. Implement scripts/fe-airgap-check.mjs (ESM, zero-dep, Taskfile-free; .svg-only binary scan; substring allow-list, --allow extends)
3. I-NEW-3 pre-flight over real frontend/dist: pin default allow-list entries with per-entry comments
4. Taskfile.yaml: fe-install/fe-build/fe-sync/fe-dev/fe-check per brief conventions; .gitignore += backend/static/
5. Real-loop gate: task fe-install fe-build fe-sync fe-check; verify backend/static/index.html + fe-check exit 0
6. 4-pass self-review, commit (only owned files), write task-6-report.md
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Validation: pytest tests/test_fe_airgap_check.py 4/4 green (RED recorded pre-implementation); task fe-sync + node scripts/fe-airgap-check.mjs frontend/dist exit 0 on rebuilt real bundle; backend/static/index.html present. pnpm corepack-only locally (bare-pnpm 127 via task); fe-build chain (tsc+lint+build) verified stepwise via corepack pnpm. Default allow-list pinned per I-NEW-3 pre-flight (see report).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added scripts/fe-airgap-check.mjs (Taskfile-free no-CDN air-gap check, ADR-0020, default allow-list pinned by pre-flight over real frontend/dist), five root Taskfile tasks (fe-install/fe-build/fe-sync/fe-dev/fe-check) mirroring the Dockerfile static mapping, and backend/static/ in .gitignore. Verified with 4/4 pytest fixtures (TDD red->green) and the real loop: fe-sync produced backend/static/index.html, fe-check exit 0 on the rebuilt bundle. Commit f191ddbf.
<!-- SECTION:FINAL_SUMMARY:END -->
