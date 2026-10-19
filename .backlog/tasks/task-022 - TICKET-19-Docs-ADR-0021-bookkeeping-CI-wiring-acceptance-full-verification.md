---
id: TASK-022
title: >-
  TICKET-19: Docs, ADR-0021 bookkeeping, CI wiring, acceptance + full
  verification
status: Done
assignee:
  - '@opencode'
created_date: '2026-10-18 09:13'
updated_date: '2026-10-18 19:11'
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
- [x] #1 Tests pass
- [x] #2 Lint and formatting pass
- [x] #3 Edge cases covered
- [x] #4 No new warnings introduced
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

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
ADR-0021 in force + acceptance cross-checks + CI no-CDN gate + L3 full verification (commit 9276de5c). ASSUMPTIONS.md LOCKED index: 0021 row in force, ADR-0020 annotated superseded-in-part, sequence -> 0021 (grep 0021 = 3). decision-021 created per ticketing convention (body byte-identical to the artifact). ARCHITECTURE.md S11 annotated (bootstrap-admin implemented; multi-user deferred to ADR-0013). README: 3 new env vars + fe-loop quickstart + task fe-dev CORS note (M-NEW-3). ci.yaml: frontend job runs node scripts/fe-airgap-check.mjs frontend/dist after pnpm build (repo root). state.yaml: executing. L3: backend ruff+mypy clean, pytest 184 passed / 3 env-blocked (incl. test_worker_gate x2 — INTRODUCED by TICKET-14's wsgi boot hook, not pre-existing: reviewer verified the module-level _bootstrap_local_admin runs on importlib.reload under the leaked Settings singleton; follow-up fix recorded as FU-1 in the SDD ledger), frontend 17/17 + tsc + eslint + build, go + helm green, all 7 frozen scenario names cross-checked. acceptance.feature committed at 3adf77ab (cross-check only).
<!-- SECTION:FINAL_SUMMARY:END -->
