---
id: TASK-035
title: >-
  [REFACTOR] TICKET-03: Fail-fast on required keys + retire k8s/plugin_settings
  (one-way: ADR-0021 supersede)
status: Done
assignee: []
created_date: '2026-10-26 13:18'
updated_date: '2026-10-26 14:34'
labels: []
dependencies:
  - TASK-034
references:
  - .skillgrid/specs/2026-10-26-ini-config-source/briefing.md
  - .skillgrid/specs/2026-10-26-ini-config-source/blueprint.md
  - .skillgrid/specs/2026-10-26-ini-config-source/tasks.md
  - .skillgrid/specs/2026-10-26-ini-config-source/adr.md
  - .skillgrid/specs/2026-10-26-ini-config-source/acceptance.feature
priority: high
type: refactor
ordinal: 35000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Config source change (ADR-0028). ONE-WAY (supersedes-in-part ADR-0021 bootstrap-admin delivery): define REQUIRED = {kubedash_jwt_secret, kubedash_secret_key, bootstrap_admin_email, bootstrap_admin_password, admin_kubeconfig}; resolve raises ConfigError for these when absent from overrides/env/INI; confirm [k8s]/[plugin_settings] unmapped (a 4.1 file with them loads fine). Human checkpoint before commit.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 tests/test_ini_config.py green: required-key-missing-fails-fast, retired-k8s-and-plugin-sections-ignored
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
- [ ] #7 ADR-0021 supersede confirmed by user (one-way checkpoint)
- [ ] #8 spec tasks.md TICKET-03 checked
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Write failing tests (required-key-missing-fails-fast, retired-k8s-and-plugin-sections-ignored)
2. Define REQUIRED frozenset
3. Add fail-fast branch in resolve
4. Confirm [k8s]/[plugin_settings] unmapped
5. STOP: confirm ADR-0021 supersede with user
6. Full unit suite green
<!-- SECTION:PLAN:END -->
