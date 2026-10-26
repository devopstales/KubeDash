---
id: TASK-036
title: '[CHORE] TICKET-04: Ship kubedash.ini.example + strip in-code identity defaults'
status: To Do
assignee: []
created_date: '2026-10-26 13:18'
updated_date: '2026-10-26 13:19'
labels: []
dependencies:
  - TASK-035
references:
  - .skillgrid/specs/2026-10-26-ini-config-source/briefing.md
  - .skillgrid/specs/2026-10-26-ini-config-source/blueprint.md
  - .skillgrid/specs/2026-10-26-ini-config-source/tasks.md
  - .skillgrid/specs/2026-10-26-ini-config-source/acceptance.feature
priority: medium
type: chore
ordinal: 36000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Config source change (ADR-0028). Create backend/kubedash.ini.example (4.1 format, empty secrets, commented retired [k8s]/[plugin_settings]); strip dead in-code defaults from config.py (identity/credential fields are default_factory=ini_config.resolve with no literal; only optional/behavior knobs keep a literal); add wsgi.py WHY-comment (env-only process knobs).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 test_example_file_parses_and_has_no_secrets green (parses interpolation-off, [security] secrets + [sso_settings] secret empty)
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
- [ ] #7 example file has no non-empty secrets
- [ ] #8 spec tasks.md TICKET-04 checked
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Write failing test (example file parses, no secrets)
2. Create backend/kubedash.ini.example
3. Strip dead in-code defaults from config.py
4. wsgi.py WHY-comment (env-only process knobs)
5. Full unit suite green
<!-- SECTION:PLAN:END -->
