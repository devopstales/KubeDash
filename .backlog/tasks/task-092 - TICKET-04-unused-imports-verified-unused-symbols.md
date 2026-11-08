---
id: TASK-092
title: 'TICKET-04: unused imports + verified unused symbols'
status: Done
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
updated_date: '2026-11-08 10:44'
labels: []
milestone: m-3
dependencies:
  - TASK-089
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
ordinal: 88000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): hand-delete the 79 unused-import findings from the TICKET-01 re-generated report (frontend — `pnpm lint --fix` is formatting-only here: the eslint config has no unused-imports rule and matches no `.ts/.tsx` file); `uv run ruff check --fix --select F401` + manual diff review (backend — the 4 backend files + `dev/sso/server.py` + `scripts/prometheus-push-e2e.py` + the migration; drop the `.git/lost-found` finding, not source); delete the verified unused symbols (`gateway_convert` leftovers `PROVIDERS`/`_REGEX_CHARS`/`_tls_secret_by_host`, the dead `KIND`/`LIST_ROUTE` constants in six data views, `NodeData.tsx` `PROBE_CONDITIONS`, `ServiceAccountData.tsx` `SecretRef` + its naming comment, unused `lib/types.ts`/`lib/groupTypes.ts` types, the migration's `_has_unique` + orphaned comment, `scripts/prometheus-push.py` `_METRIC_RE`) — the wsgi pair STAYS (live-dynamic).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 a re-generated jscpd report lists no unused-import finding; every verified symbol is gone; the test-only exports (`resetRefreshForTests`, `setLoginRedirectForTests`, `getRegisteredNavigate`) remain; the diff is deletions + import-cleanup lines only; `corepack pnpm test && task fe-build && task fe-check && uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` green.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: unused-code-removed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: hand-delete the 79 unused-import findings from the TICKET-01 re-generated report (frontend — `pnpm lint --fix` is formatting-only here: the eslint config has no unused-imports rule and matches no `.ts/.tsx` file); `uv run ruff check --fix --select F401` + manual diff review (backend — the 4 backend files + `dev/sso/server.py` + `scripts/prometheus-push-e2e.py` + the migration; drop the `.git/lost-found` finding, not source); delete the verified unused symbols (`gateway_convert` leftovers `PROVIDERS`/`_REGEX_CHARS`/`_tls_secret_by_host`, the dead `KIND`/`LIST_ROUTE` constants in six data views,. 2: verify per Acceptance: a re-generated jscpd report lists no unused-import finding; every verified symbol is gone; the test-only exports (`resetRefreshForTests`, `setLoginRedirectForTests`, `getRegisteredNavigate`) remain; the diff is deletions + import-cleanup lines only; `corepack pnpm test && task fe-build && task fe-check && uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` green.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-11-08 08:33
---
Execution started 2026-11-08 (subagent-execution, wave 2, ImplD04 flint, parallel with T02)
---

created: 2026-11-08 10:44
---
Executed 2026-11-08: 35469827 (87 files, 10 F401 + symbol deletions, ruff 103->93 0 new), 7a55bde3 (Fragment fix - jscpd false positive #1), 17425c2f (CIcon restore - false positive #2 + 2 brief-named comments + report SHA). Review: Needs fixes -> fix round 2 -> parent re-review consolidated (10-line diff read in full, all 4 fixes exact). ruff/mypy legs = pre-existing debt TASK-098. SATISFIES: unused-code-removed.
---
<!-- COMMENTS:END -->
