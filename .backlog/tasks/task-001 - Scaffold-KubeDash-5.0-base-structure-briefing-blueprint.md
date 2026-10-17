---
id: TASK-001
title: Scaffold KubeDash 5.0 base structure (briefing + blueprint)
status: In Progress
assignee:
  - '@paladm'
created_date: '2026-10-17 11:49'
updated_date: '2026-10-17 12:53'
labels: []
dependencies: []
ordinal: 1000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The repo is on the rebase branch with docs/ADR layer only (no target-stack code). The proposed 5.0 stack in .skillgrid/ARCHITECTURE.md (backend/ Flask-Smorest, frontend/ CoreUI React, cli/ Go, charts/) needs a base-structure change: a tracer skeleton where every top-level module exists with a working spine (app factory + config, OIDC login -> JWT, cluster registry, one resource list, SPA shell with one view, CI green). This task produces the change's spec artifacts: briefing.md then blueprint.md under .skillgrid/specs/2026-10-17-kubedash-base-structure/. Reference: .skillgrid/ARCHITECTURE.md sections 2-4; in-force ADRs 0001-0006 (Flask-Smorest, multi-cluster registry, CoreUI React, single-container, RQ, leader election).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 briefing.md exists at .skillgrid/specs/2026-10-17-kubedash-base-structure/briefing.md with falsifiable requirements (Current/Target/Acceptance each) and user approval recorded
- [ ] #2 blueprint.md exists in the same folder with hypothesis, must-haves, threat matrix (if applicable), file structure, and bite-sized TDD tasks
- [ ] #3 blueprint passes critic subagent review and user review
- [ ] #4 artifacts committed to git (spec-zone commit, no code)
- [ ] #5 .skillgrid/state.yaml current_change updated to 2026-10-17-kubedash-base-structure
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Read skillgrid state: ARCHITECTURE.md sections 2-4, ASSUMPTIONS.md LOCKED index, in-flight kubectl-oidc-plugin blueprint (already done) 2. Create change folder .skillgrid/specs/2026-10-17-kubedash-base-structure/ 3. Draft briefing.md from brainstorming template: problem/intent (tracer skeleton of 5.0 stack), success criteria, requirements with Current/Target/Acceptance, implementation decisions, testing decisions, ADR constraints (0001-0006, 0009, 0010) 4. Self-review briefing (falsifiability, placeholders, scope) 5. Present briefing to user, get approval 6. Commit briefing (spec-zone) 7. Update state.yaml current_change + current_phase 8. Draft blueprint.md from writing-blueprints template: hypothesis, must-haves (truths/artifacts/key links, one-way doors), threat matrix (shell/subprocess for helm), file structure, TDD tasks 9. Self-review + critic subagent review 10. Present blueprint + critic findings to user, resolve issues, get approval 11. Commit blueprint, update state.yaml to blueprint phase, offer execution handoff (slicing)
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Briefing written and approved by user (answer-select: Approved). Scope: 5.0 stack tracer skeleton, spine R1-R5 real, stubs R9, CI R8, test infra R10. Assumptions: ADR-0010 informer deferred, Playwright smoke = full journey.

Blueprint written (12 tasks). Critic subagent: NEEDS FIXES, 20 findings (4 CRIT/6 HIGH/6 MED/4 LOW). User chose 'Fix all' — all resolved inline, resolution log in blueprint.md. Awaiting final user approval.
<!-- SECTION:NOTES:END -->
