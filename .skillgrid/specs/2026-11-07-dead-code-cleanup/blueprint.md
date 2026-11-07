# Dead-Code Cleanup — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T0
**Build shape:** Smallest usable whole — pure deletions; every task is verifiable on its own and the whole is the sum.
**Classification:** small (L1 verification floor + the full suites as the no-behaviour-change proof)
**Goal:** Delete the confirmed dead code (CoreUI template demo files, `Pods.tsx`, unused imports, verified unused symbols) with zero behaviour change, and record the dynamic-wiring verdict for the 23 suspicious backend files.
**Architecture:** No new code. Each deletion batch is: verify import-free (static + dynamic grep, the build as backstop) → delete → green → commit. The authoritative finding list is the jscpd dead-code report (`report/basta-report.json`, 2026-11-07 run: 81 unused files / 79 unused imports / 20 unused symbols / 7 unused exports) — re-generated at Task 1 Step 1 so the list is the current one, not a stale artifact.
**Tech Stack:** jscpd, eslint, ruff, grep, the existing test suites.
**Spec:** `./briefing.md`
**Critic:** skipped (T0, fast-track) — pure deletions, no interfaces

## Hypothesis

**Claim:** The 58 frontend template files + `Pods.tsx` + the listed unused symbols are dead — deletions change no behaviour.
**Right condition:** every batch green (`pnpm test`, `fe-build`, `fe-check`, `pytest`); jscpd dead-code % drops from 16.6% toward ~1% with zero new clone pairs in `views/`.
**Wrong condition:** a "template" file is actually imported (static or dynamic — a `React.lazy(() => import(…))`, a `stubRoutes` entry, a test), or a suite fails after a deletion.
**Thinnest MVP:** the five largest demo files (Tables/Cards/Widgets/Modals/InputGroup, ~3,985L) deleted and green.
**Door check:** Task 1 (the import-verification pass over the whole deletion list — any file that fails verification is pulled from the list, not force-deleted).

## Terms

None.

## Must-Haves (goal-backward verification)

**Truths:**
- [backstop] zero behaviour change — backstop: the four suites green at every commit + `task e2e` at the end (held-out: the e2e smoke exercises the live surface)
- no deleted file has any import reference (static or dynamic) remaining in the repo — grep-provable per batch
- jscpd dead-code findings: the 58 template files + `Pods.tsx` + the 79 unused imports are gone from a re-run
- the 23 backend files carry a tracker note with a per-file dynamic-wiring verdict

**Artifacts:**
- The deletions themselves (the file list is the artifact — Task 1's verified list, committed in the first batch's commit body)
- `.backlog` note: 23 backend files' verification verdicts

**Key links:**
- Task 1's verified list is the input to Tasks 2–4 — a file is deleted only if it passed verification
- the e2e smoke (exact-title) is the held-out check that no live view was in the template list

**One-way-door decisions:** None — pure deletions, no contract touched.

## Global Constraints

- Pure deletions + import-cleanup lines only; no other edits
- `corepack pnpm test` + `task fe-build` + `task fe-check` (frontend batches) and `uv run pytest -m "not integration"` + `uv run ruff check .` (backend batches) green at every commit
- test-only exports kept: `resetRefreshForTests`, `setLoginRedirectForTests` (the `getRegisteredNavigate` export stays until change C deletes it)
- conventional commits, one per batch (deletions are independently revertable)

## File Structure

- Deleted: `frontend/src/views/components/**` (20 demo files), `frontend/src/views/forms/**` (5), `frontend/src/views/widgets/**` (1), `frontend/src/views/dashboard/Dashboard.jsx`, `frontend/src/views/authentication/**` (5), `frontend/src/views/charts/Charts.jsx`, `frontend/src/views/icons/**` (3), `frontend/src/views/error-pages/**` (2), `frontend/src/components/{AppContent,DocsComponents,DocsExample,DocsIcons,DocsLink}.jsx`, `frontend/src/store.js`, `frontend/src/views/Cluster/Pods.tsx`
- Modified (import-cleanup lines only): the files carrying the 79 unused imports (`dev/sso/server.py`, `frontend/src/components/AppSidebarNav.jsx`, `AppBreadcrumb.jsx`, `AppFooter.jsx`, `AppHeader.jsx`, `header/AppHeaderDropdown.jsx`, `index.tsx`, `layout/DefaultLayout.jsx`, `views/AdminPermissions/{Audit,Privileges}.tsx`, `backend/app/api/events.py`, `backend/app/schemas/permissions.py`, `backend/app/services/kubectl_config.py`, `backend/migrations/versions/2eb286befb21_*.py`, …)
- Modified (verified unused symbols only): `backend/app/services/gateway_convert.py`, `backend/wsgi.py` (after the leader-RQ check), six frontend data views (dead `KIND`/`LIST_ROUTE` constants), `frontend/src/lib/types.ts`, `frontend/src/lib/groupTypes.ts`, `backend/migrations/versions/b7e2c4a9d105_*.py`, `scripts/prometheus-push.py`
- Verified-only (no deletion in this change): the 23 backend files (`backend/app/aggregated/{project,sso_group,sso_user}.py`, `backend/app/models/{access_request,namespace_request,scim_map}.py`, `backend/app/schemas/kubectl_auth.py`, `backend/app/services/{access,grafana,loki,namespace,prometheus,provisioning,scim,tempo}.py`, `backend/app/sockets/{events,logs}.py`, `backend/app/tasks/{access_expiry,alerts,cluster_sync,health,ns_request_expiry,rbac_drift}.py`)

---

### Task 1: Verification pass — the deletion list

**Files:** none modified (the list is recorded in the commit body of Task 2's first batch)
**SATISFIES:** `deletion-list-verified`
- [ ] **Step 1: Re-generate the findings.** `npx jscpd --dead-code --reporters json .` → `report/basta-report.json` (the current list).
- [ ] **Step 2: Verify each candidate file is import-free.** For every unused-file finding under `frontend/` (the 58 + `Pods.tsx`): `grep -rn "<basename>" frontend/src frontend/tests frontend/e2e --include='*.ts*' --include='*.jsx' | grep -v "<the file itself>"` — zero hits required, checking both the module path and the bare basename (catches `React.lazy(() => import('./views/components/tables/Tables'))`-style dynamic imports and `stubRoutes`). Any hit → the file is pulled from the deletion list and recorded as an exception.
- [ ] **Step 3: Verify the unused-symbol candidates.** `wsgi.py`: confirm `_rq_worker_main`/`_build_worker_app` are not referenced (incl. by name string, e.g. a gunicorn config or the leader-RQ wiring in `app/`); `gateway_convert.py`: confirm `PROVIDERS`/`_REGEX_CHARS`/`_tls_secret_by_host` are not referenced in tests; the six data views' `KIND`/`LIST_ROUTE`; `lib/types.ts`/`lib/groupTypes.ts` types; the migration's `_has_unique`; `scripts/prometheus-push.py`'s `_METRIC_RE`. Same zero-hit rule.
- [ ] **Step 4: Commit** the verified list: `chore: dead-code verification pass — deletion list` with the full list in the body.

### Task 2: Delete the template demo bulk (components/forms/widgets/dashboard)

**Files:** Deleted: `views/components/**` (20), `views/forms/**` (5), `views/widgets/**` (1), `views/dashboard/Dashboard.jsx` (the files that passed Task 1)
**SATISFIES:** `template-bulk-deleted`
- [ ] **Step 1: Delete** the verified files; `git status` matches the list exactly.
- [ ] **Step 2: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `chore: delete CoreUI template demo files (components/forms/widgets/dashboard)`.

### Task 3: Delete the remaining template files + `Pods.tsx` + docs helpers

**Files:** Deleted: `views/authentication/**` (5), `views/charts/Charts.jsx`, `views/icons/**` (3), `views/error-pages/**` (2), `components/{AppContent,DocsComponents,DocsExample,DocsIcons,DocsLink}.jsx`, `store.js`, `views/Cluster/Pods.tsx`
**SATISFIES:** `template-tail-deleted`
- [ ] **Step 1: Verify `Pods.tsx`** against the route table (`App.tsx` lazy imports + `stubRoutes`) — it is not imported (Task 1's pass covers it; this step is the explicit re-check because it sits in a live view directory).
- [ ] **Step 2: Delete** the verified files.
- [ ] **Step 3: Run + commit.** green → `chore: delete remaining template files, Pods.tsx, docs helpers`.

### Task 4: Unused imports + verified unused symbols

**Files:** Modified: the files from the File Structure section (import-cleanup lines + the verified symbols)
**SATISFIES:** `unused-code-removed`
- [ ] **Step 1: Imports.** `corepack pnpm lint --fix` (eslint unused-imports) in `frontend/`; `uv run ruff check --fix --select F401` + manual review of the diff in `backend/` (the 4 backend files + `dev/sso/server.py` + the migration); drop the `.git/lost-found` finding (not source).
- [ ] **Step 2: Symbols.** Delete the Task 1-verified unused symbols (the `wsgi.py` pair only if the leader-RQ check passed; the migration's `_has_unique`; `gateway_convert` leftovers; the dead `KIND`/`LIST_ROUTE` constants; the unused types; `_METRIC_RE`).
- [ ] **Step 3: Run + commit.** `corepack pnpm test && task fe-build && task fe-check && uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` green → `chore: remove unused imports and verified unused symbols`.

### Task 5: Backend 23 files — dynamic-wiring verdicts (verification only)

**Files:** none deleted in this change; a `.backlog` note created via the `backlog` CLI
**SATISFIES:** `backend-files-verified`
- [ ] **Step 1: Check each of the 23 files for dynamic wiring:** RQ task name strings (`grep -rn "cluster_sync\|health\|rbac_drift\|…" backend/app --include='*.py'` for scheduler call sites), sockets blueprint registration (`app/sockets/__init__` / the app factory), models import (the `app/models` package registration / Alembic autogenerate assumptions), the aggregated app factory (`app/aggregated/` — the `:8443` mock mTLS app), the services (called by name or string from tasks/api).
- [ ] **Step 2: Record** a per-file verdict (dead-dynamically-unwired / live-dynamic / needs-follow-up) in a backlog note; any file grep-proven dead AND not referenced by a string gets a **proposed-deletion** flag for a follow-up change — no deletions in this change.
- [ ] **Step 3: Commit.** the note (tracker) + `chore: backend dead-file verification note`.

### Task 6: Green + measure

**Files:** none
**SATISFIES:** `dead-code-measured`
- [ ] **Step 1: Full floor.** `corepack pnpm test` + `task fe-build` + `task fe-check` + `task e2e` + `uv run pytest -m "not integration"` + `uv run ruff check .` + `uv run mypy app`.
- [ ] **Step 2: Re-measure.** `npx jscpd --health --reporters ai .` — record the new dead-code % and overall health vs the 2026-11-07 baseline (dead-code 22 / 16.6%, 187 findings) in the commit body.
- [ ] **Step 3: Commit.** `chore: dead-code re-measure (baseline 2026-11-07)`.

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Task 1 (verification) + every batch's grep rule; R2 → every task's green step + Task 6's e2e; R3 → global constraint (deletions + import lines only); R4 → Task 5. No gaps.
2. **Must-haves coverage:** all four requirements map to truths/artifacts/links; the behaviour-invariance truth is the `backstop` with `task e2e` as the held-out test.
3. **One-way-door completeness:** pure deletions — none.
4. **Placeholder scan:** the file lists are the 2026-11-07 jscpd findings (re-verified against a fresh run in Task 1 Step 1 — a finding that disappeared or gained a reference is handled by the zero-hit rule, not by trust in this document).
5. **Type consistency:** n/a (no new code).
