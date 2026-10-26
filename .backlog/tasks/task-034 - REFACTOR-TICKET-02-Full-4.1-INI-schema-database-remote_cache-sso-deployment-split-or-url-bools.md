---
id: TASK-034
title: >-
  [REFACTOR] TICKET-02: Full 4.1 INI schema
  (database/remote_cache/sso/deployment, split-or-url, bools)
status: Done
assignee: []
created_date: '2026-10-26 13:17'
updated_date: '2026-10-26 14:34'
labels: []
dependencies:
  - TASK-033
references:
  - .skillgrid/specs/2026-10-26-ini-config-source/briefing.md
  - .skillgrid/specs/2026-10-26-ini-config-source/blueprint.md
  - .skillgrid/specs/2026-10-26-ini-config-source/tasks.md
  - .skillgrid/specs/2026-10-26-ini-config-source/acceptance.feature
priority: high
type: refactor
ordinal: 34000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Config source change (ADR-0028). Complete _FIELDS for every Settings field; add _resolve_database (split-or-url + quote_plus) and _resolve_redis (split-or-url, port/db defaults); flask_env DEFAULT/no-leak fallback; sso_bootstrap_users optional; bool parse for tls_edge/cookie_secure.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tests/test_ini_config.py green: database-split-or-url (incl quote_plus), remote-cache-split-or-url
- [ ] #2 full unit suite green: uv run pytest -m "not integration" -q
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 tests pass
- [ ] #7 no new warnings
- [ ] #8 spec tasks.md TICKET-02 checked
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Write failing tests (database-split-or-url, remote-cache-split-or-url)
2. Complete _FIELDS for all remaining fields
3. Add _resolve_database (split-or-url, quote_plus) + _resolve_redis
4. flask_env DEFAULT/no-leak + sso_bootstrap_users optional + bool parse
5. Point remaining config.py fields at ini_config.resolve
6. Full unit suite green
<!-- SECTION:PLAN:END -->
