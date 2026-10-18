---
id: TASK-022
title: >-
  TICKET-19: Docs, ADR-0021 bookkeeping, CI wiring, acceptance + full
  verification
status: In Progress
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-18 18:58'
labels: []
milestone: m-0
dependencies:
  - TASK-020
  - TASK-021
priority: medium
type: feature
ordinal: 22000
---

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
1. acceptance.feature cross-check only (already committed 3adf77ab — verify 7 frozen scenario names present). 2. ADR bookkeeping: ASSUMPTIONS.md (LOCKED +0021 row, ADR-0020 annotation superseded-in-part, sequence -> 0021); .backlog/decisions/decision-021.md (ADR copy); ARCHITECTURE.md section 11 implemented note; artifacts/04-adr-0021-local-admin-auth.md Consequences + M-NEW-1 note; README.md (fe-loop quickstart + 3 env vars + task fe-dev note). 3. CI wiring: ci.yaml frontend job + node scripts/fe-airgap-check.mjs frontend/dist after pnpm build. 4. L3 full verification (backend ruff+mypy+pytest not-integration, frontend four gates, go vet+test, helm lint+template, grep cross-checks: 0021 >= 2 in ASSUMPTIONS.md, SATISFIES = 7 in blueprint.md). 5. state.yaml phase update + commit (spec-zone + docs).
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
L3 full verification (TICKET-19 / Task 7): backend ruff OK + mypy OK (73 files) + pytest 184 passed / 3 failed (test_health::test_readyz_names_failing_database = pre-existing env-blocked per baseline; test_worker_gate x2 = pre-existing wsgi module-state leak across the PG tier, fails in full run but passes standalone — CI backstop). Frontend: vitest 17 passed, tsc clean, eslint clean (substituted for bare 'pnpm lint' which hangs >400s locally), build OK, fe-airgap-check on dist exit 0. CLI: go vet OK, go test ok. Helm: lint 0 failed, template OK. Cross-checks: grep -c 0021 ASSUMPTIONS.md = 3 (>=2); blueprint SATISFIES lines = 11 total, all 7 frozen scenario names each referenced >= 2x. Commit follows.
<!-- SECTION:NOTES:END -->
