---
id: TASK-094
title: 'TICKET-06: backend 23 files - dynamic-wiring verdicts'
status: Done
assignee:
  - '@paladm'
created_date: '2026-11-07 19:12'
updated_date: '2026-11-07 20:28'
labels: []
milestone: m-3
dependencies: []
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
ordinal: 90000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Dead-Code Cleanup (2026-11-07-dead-code-cleanup): check each of the 23 backend files for dynamic wiring — grep scope `backend/` (the wsgi scheduler `INTERVALS` + enqueue loop at `wsgi.py:194` + the spawn string at `wsgi.py:179`; `tests/test_file_map.py`'s `EXPECTED` string-pins all 23 verbatim; the sockets blueprint registration — `SocketIO(` is instantiated nowhere, the two sockets files are docstring-only stubs; `app/models/__init__.py` deliberately keeps the 3 stub models UNIMPORTED — a design fact to record; the `:8443` aggregated mock mTLS app factory; services called by name or string from tasks/api); record the per-file verdict in a `.backlog` note — live-dynamic (`health.py`, `cluster_sync.py` — the only two that import live code), stub-by-design (the rest), string-pinned (all 23) — no deletions in this change.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 the backlog note carries a verdict for all 23 files with the `test_file_map.py` string-pin recorded; any proposed-deletion flag names the `test_file_map.py` + `ARCHITECTURE.md` section-2 updates it implies; no source file modified.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 Tests pass
- [ ] #2 Lint and formatting pass
- [ ] #3 Edge cases covered
- [ ] #4 No new warnings introduced
- [ ] #5 Spec/docs updated if behavior changes
- [ ] #6 SATISFIES scenarios green per acceptance.feature: backend-files-verified
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1: check each of the 23 backend files for dynamic wiring — grep scope `backend/` (the wsgi scheduler `INTERVALS` + enqueue loop at `wsgi.py:194` + the spawn string at `wsgi.py:179`; `tests/test_file_map.py`'s `EXPECTED` string-pins all 23 verbatim; the sockets blueprint registration — `SocketIO(` is instantiated nowhere, the two sockets files are docstring-only stubs; `app/models/__init__.py` deliberately keeps the 3 stub models UNIMPORTED — a design fact to record; the `:8443` aggregated mock mTLS app factory; services called by name or string from tasks/api); record the per-file verdict in a `.. 2: verify per Acceptance: the backlog note carries a verdict for all 23 files with the `test_file_map.py` string-pin recorded; any proposed-deletion flag names the `test_file_map.py` + `ARCHITECTURE.md` section-2 updates it implies; no source file modified.. 3: mark AC/DoD, conventional commit with Refs footer.
<!-- SECTION:PLAN:END -->

## Comments

<!-- COMMENTS:BEGIN -->
created: 2026-11-07 19:46
---
Execution started 2026-11-07 (subagent-execution, wave 1, feature-branch-chain on rebase)
---

created: 2026-11-07 20:28
---
Executed 2026-11-07: commit 5654e914 (note doc-001, 23/23 verdicts, live-dynamic x2 / stub-by-design x21 / string-pinned x23); review Approved with 2 minor wording nits (non-blocking). SATISFIES: backend-files-verified.
---
<!-- COMMENTS:END -->
