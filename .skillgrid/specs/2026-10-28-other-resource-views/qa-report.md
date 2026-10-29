# QA Report — Other-Resource Views Batch (6 changes)

**Gate: PASS** (re-verified 2026-10-29 by the orchestrator after the
reviewer's CONCERNS verdict; the three WARNING findings were the truncated
verification scope, now re-executed at tip `aead16a7`).

**Batch:** base `a72427ae` → tip `aead16a7`, branch `rebase`

| # | Change | Task | Commits |
|---|--------|------|---------|
| 1 | `2026-10-28-runtimeclass-views` | TASK-046 | 718eda35..cab0e37a |
| 2 | `2026-10-28-resourcequota-views` | TASK-047 | 783cff0a..db1233a0 |
| 3 | `2026-10-28-pdb-views` | TASK-048 | 5f1f9244..1a510cb4 |
| 4 | `2026-10-28-vpa-views` | TASK-049 | c0616fa4..29ee7c8d |
| 5 | `2026-10-28-hpa-views` | TASK-050 | 0178df05..b9ba23fb |
| 6 | `2026-10-28-limitrange-views` | TASK-054 | d8ba964d..aead16a7 |

## Fresh verification floor (re-executed at tip, 2026-10-29)

| Check | Result |
|---|---|
| `uv run pytest -m "not integration" -q` | **532 passed, 10 deselected, 0 failed** (146 s) |
| Targeted backend (6 new service files + `test_resources.py`, `-m "not integration"`) | **130 passed, 6 deselected** (kind-tier) |
| `corepack pnpm vitest run` (full) | **242 passed / 13 failed — the failures are exactly the declared baseline** (users 7, groups 4, admin_permissions 1, node-detail-renders 1); nothing new |
| Targeted frontend (12 view test files + `Stub.test.tsx`) | **70 passed (70)** |
| `task fe-build` (tsc --noEmit incl. tests + eslint + vite build) | green |
| `task fe-check` (air-gap assertion on `frontend/dist`) | green |
| `git diff --stat a72427ae..aead16a7 -- frontend/src/_nav.tsx` | **empty — nav byte-identical** |
| Dependency-file diff (`frontend/package.json`, `pnpm-lock.yaml`, `backend/pyproject.toml`, `uv.lock`) | **empty — no new dependencies (ADR-0020)** |
| Scope: `git diff --name-only a72427ae..aead16a7` (60 files) | subset of the six blueprints' File Structure lists + their spec folders + `state.yaml` + `.backlog` task files + the concurrent volumesnapshot spec (TASK-053 work stream) + the mnemonic cache; `Stub/routes.ts` has zero `/other-resource/*` entries left; `frontend/e2e/ui-smoke.spec.ts` only in the limitrange T4 commit |

## Reviewer findings disposition (CONCERNS → PASS)

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| F1 | WARNING | Verification floor not re-executed by the QA session (no shell) | **FIXED** — all floor commands re-run at tip, results above |
| F2 | WARNING | `_nav.tsx` byte-identity carried, not re-proven | **FIXED** — diff vs base empty |
| F3 | WARNING | Scope + dependency check not re-proven | **FIXED** — both diffs run, clean |
| F4 | SUGGESTION | Report persistence + WINDOWS rows | done (this file, W008-W010) |
| F5 | SUGGESTION | e2e REAL_ROUTES covers only limit-range; the other five kinds' R5 is unit-level only — add the 10 remaining real paths (one line each) | parked (follow-up) |
| F6 | SUGGESTION | Stale `/other-resource/priorityclass` entry in e2e `STUB_TITLES` (ui-smoke.spec.ts:50-53) — a real view since 2026-10-27 | parked (noise, follow-up) |

## Traceability (reviewer, static, on-tip)

82/82 scenarios across the six `acceptance.feature` files mapped to named
tests (backend 36 API-tier + 6 service files with `[scenario]` docstring
tags; frontend 12 view test files + `Stub.test.tsx`). No UNTESTED, no
FAILING, no PARTIAL. TDD evidence: 24/24 task units OK (RED before GREEN
per task, commit hashes resolve). Assertion quality: 0 CRITICAL / 0
WARNING across all 18 test files read in full.

## Carried baselines (not findings)

- Backend kind-tier ScopeMismatch errors in `test_resources.py` (2-3,
  testcontainers teardown race; the kind apiserver is unreachable from test
  processes — SAR probes dial 1.2.3.4).
- Frontend 13-14 pre-existing failures (users/groups/admin_permissions/
  node-detail-renders) — owned by the in-flight users/groups pages, not this
  batch; tracked as W007.
