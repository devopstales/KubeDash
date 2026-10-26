---
id: TASK-033
title: >-
  [REFACTOR] TICKET-01: INI>env>override resolution core + home derivation +
  Settings projection
status: Done
assignee: []
created_date: '2026-10-26 13:17'
updated_date: '2026-10-26 14:18'
labels: []
dependencies: []
references:
  - .skillgrid/specs/2026-10-26-ini-config-source/briefing.md
  - .skillgrid/specs/2026-10-26-ini-config-source/blueprint.md
  - .skillgrid/specs/2026-10-26-ini-config-source/tasks.md
  - .skillgrid/specs/2026-10-26-ini-config-source/acceptance.feature
priority: high
type: refactor
ordinal: 33000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Config source change (ADR-0028). Create app/core/ini_config.py (home discovery via KUBEDASH_HOME else wsgi.py dir, home_paths(), load_ini, apply_overrides, resolve, reset, ConfigError) with partial _FIELDS; rewrite config.py fields to default_factory=ini_config.resolve; wire create_app to apply_overrides first + register_static to home_paths()["static"]; update test reset contract to ini_config.reset() + KUBEDASH_HOME fixtures. KUBEDASH_STATIC_DIR dropped.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tests/test_ini_config.py green: ini-provides-value, env-overrides-ini, override-beats-env-and-ini, optional-and-behavior-knobs-keep-defaults, home-paths-derived-from-kubedash-home, home-falls-back-to-wsgi-dir, static-dir-from-home-paths
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
- [ ] #8 spec tasks.md TICKET-01 checked
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Write failing tests (test_ini_config.py: the 7 scenarios)
2. Implement ini_config.py (home_paths, resolve, reset, load_ini, apply_overrides)
3. Rewrite config.py fields to default_factory=ini_config.resolve
4. Wire create_app (apply_overrides first) + register_static (home_paths static)
5. Update conftest reset to ini_config.reset() + KUBEDASH_HOME fixtures
6. Full unit suite green
<!-- SECTION:PLAN:END -->
