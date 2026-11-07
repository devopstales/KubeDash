---
id: TASK-087
title: 'TICKET-03: pinned relay TTL tests, both sides'
status: To Do
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
labels: []
milestone: m-6
dependencies:
  - TASK-085
references:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/briefing.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/tasks.md
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/acceptance.feature
documentation:
  - >-
    /Users/paladm/git/kubedash_4/.skillgrid/specs/2026-11-07-navigation-seam/briefing.md
priority: high
type: refactor
ordinal: 83000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Navigation Seam (2026-11-07-navigation-seam): frontend pin in `tests/lib/objectRef.test.ts` (`expect(RELAY_TTL_MS).toBe(60_000)`, comment: `// backend/app/core/object_handoff.py STASH_TTL_SECONDS — change both together (ADR-0040 R4 handoff window)`); backend pin in `backend/tests/api/test_object_handoff.py` (`assert STASH_TTL_SECONDS == 60`, comment: `# frontend/src/lib/objectRef.ts RELAY_TTL_MS — change both together (ADR-0040 R4 handoff window)`).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `corepack pnpm test tests/lib/objectRef.test.ts` and `uv run pytest tests/api/test_object_handoff.py -v` both exit 0 with the two pins present; mutating either constant fails the other side's pin (the comments name the counterpart — the pin is bilateral by construction).
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: the relay TTL pair is pinned on both sides of the boundary
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: frontend pin in `tests/lib/objectRef.test.ts` (`expect(RELAY_TTL_MS).toBe(60_000)`, comment: `// backend/app/core/object_handoff.py STASH_TTL_SECONDS — change both together (ADR-0040 R4 handoff window)`); backend pin in `backend/tests/api/test_object_handoff.py` (`assert STASH_TTL_SECONDS == 60`, comment: `# frontend/src/lib/objectRef.ts RELAY_TTL_MS — change both together (ADR-0040 R4 handoff window)`).. 2: verify per Acceptance: `corepack pnpm test tests/lib/objectRef.test.ts` and `uv run pytest tests/api/test_object_handoff.py -v` both exit 0 with the two pins present; mutating either constant fails the other side's pin (the comments name the counterpart — the pin is bilateral by construction).. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->
