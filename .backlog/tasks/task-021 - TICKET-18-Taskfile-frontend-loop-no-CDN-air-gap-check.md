---
id: TASK-021
title: 'TICKET-18: Taskfile frontend loop + no-CDN air-gap check'
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-20 15:45'
labels: []
milestone: m-0
dependencies: []
priority: medium
type: feature
ordinal: 21000
---

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

Finalization (this session): verified f191ddbf in git log covers all deliverables of the plan (script, 4 pytest fixtures, Taskfile tasks, .gitignore entry). DoD #5 closed: ADR-0020 bookkeeping lives in TASK-022 (done), and AGENTS.md already documents task fe-check as the air-gap assertion — no doc change was owed by this ticket.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added scripts/fe-airgap-check.mjs (Taskfile-free no-CDN air-gap check, ADR-0020, default allow-list pinned by pre-flight over real frontend/dist), five root Taskfile tasks (fe-install/fe-build/fe-sync/fe-dev/fe-check) mirroring the Dockerfile static mapping, and backend/static/ in .gitignore. Verified with 4/4 pytest fixtures (TDD red->green) and the real loop: fe-sync produced backend/static/index.html, fe-check exit 0 on the rebuilt bundle. Commit f191ddbf.

Finalization (this session): no code changes needed — f191ddbf already covers the whole task (4/4 pytest fixtures in backend/tests/test_fe_airgap_check.py, the script, and the five Taskfile tasks). DoD #5 (spec/docs) was never a deliverable of this ticket: the air-gap behavior is covered by the ADR-0020/0021 bookkeeping owned by TASK-022 (completed), and AGENTS.md's fe-check description already matches the implemented task. Closing DoD #5 on that basis.
<!-- SECTION:FINAL_SUMMARY:END -->
