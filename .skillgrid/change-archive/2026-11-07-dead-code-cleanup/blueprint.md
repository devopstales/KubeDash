# Dead-Code Cleanup — Implementation Blueprint (steps, files, verification)

**Status:** PROPOSED
**Tier:** T0
**Build shape:** Smallest usable whole — pure deletions; every task is verifiable on its own and the whole is the sum.
**Classification:** small (L1 verification floor + the full suites as the no-behaviour-change proof)
**Goal:** Delete the confirmed dead code (CoreUI template demo files, `Pods.tsx`, unused imports, verified unused symbols) with zero behaviour change, record the dynamic-wiring verdict for the 23 suspicious backend files, and migrate the ~20 view tests' inline `KubeDataTable` fakes onto one shared fake (moved from change B per user decision 2026-11-07).
**Architecture:** No new production code (one new test file: the shared `KubeDataTable` fake, Task 5). Each deletion batch is: verify import-free (static + dynamic grep, the build as backstop) → delete → green → commit. The authoritative finding list is the jscpd dead-code report (`report/basta-report.json`, 2026-11-07 run: 81 unused files / 79 unused imports / 20 unused symbols / 7 unused exports) — re-generated at Task 1 Step 1 so the list is the current one, not a stale artifact.
**Tech Stack:** jscpd, eslint, ruff, grep, the existing test suites.
**Spec:** `./briefing.md`
**Critic:** criticD (reviewer) 2026-11-07: **SOUND-WITH-FIXES** — 4 MAJOR + 3 MINOR, all findings folded in (the zero-hit rule scoped to import specifiers + a collision disposition for the 24 substring collisions; the wsgi pair recorded live-dynamic — the spawn string at `wsgi.py:179`; `pnpm lint --fix` is formatting-only, frontend imports hand-deleted from the report; the RQ greps scoped to `backend/` + the `test_file_map.py` string-pins recorded; File Structure counts corrected to the report; the verification record pinned to Task 2's first commit body; `PROBE_CONDITIONS`/`SecretRef`/`prometheus-push-e2e.py` added; the fleet test-fake migration (moved from B) is the sole test-file exception to the pure-deletion constraint)

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

- Pure deletions + import-cleanup lines only; no other edits — Task 5's test-fake migration is the one test-file exception (user decision 2026-11-07: moved from change B)
- `corepack pnpm test` + `task fe-build` + `task fe-check` (frontend batches) and `uv run pytest -m "not integration"` + `uv run ruff check .` (backend batches) green at every commit
- test-only exports kept: `resetRefreshForTests`, `setLoginRedirectForTests` (the `getRegisteredNavigate` export stays until change C deletes it)
- conventional commits, one per batch (deletions are independently revertable)

## File Structure

- Deleted: `frontend/src/views/components/**` (25), `frontend/src/views/forms/**` (9), `frontend/src/views/widgets/**` (2), `frontend/src/views/dashboard/**` (3: `Dashboard.jsx` + `DashboardBrand.jsx` + `MainChart.jsx` — the latter two referenced only by `Dashboard.jsx:53-55`), `frontend/src/views/authentication/**` (6), `frontend/src/views/charts/Charts.jsx`, `frontend/src/views/icons/**` (3), `frontend/src/views/error-pages/**` (2), `frontend/src/components/{AppContent,DocsComponents,DocsExample,DocsIcons,DocsLink}.jsx`, `frontend/src/store.js`, `frontend/src/views/Cluster/Pods.tsx` — the authoritative list is the 58 frontend unused-file findings from the Task 1 re-run (exceptions recorded); the goal is 'the 58 findings are deleted', not the per-directory counts
- Modified (import-cleanup lines only): the files carrying the 79 unused imports (`dev/sso/server.py`, `frontend/src/components/AppSidebarNav.jsx`, `AppBreadcrumb.jsx`, `AppFooter.jsx`, `AppHeader.jsx`, `header/AppHeaderDropdown.jsx`, `index.tsx`, `layout/DefaultLayout.jsx`, `views/AdminPermissions/{Audit,Privileges}.tsx`, `backend/app/api/events.py`, `backend/app/schemas/permissions.py`, `backend/app/services/kubectl_config.py`, `backend/migrations/versions/2eb286befb21_*.py`, …)
- Modified (verified unused symbols only): `backend/app/services/gateway_convert.py`, `backend/wsgi.py` (after the leader-RQ check), six frontend data views (dead `KIND`/`LIST_ROUTE` constants), `frontend/src/lib/types.ts`, `frontend/src/lib/groupTypes.ts`, `backend/migrations/versions/b7e2c4a9d105_*.py`, `scripts/prometheus-push.py`
- Created (test-only): `frontend/tests/components/kube-data-table.test-utils.tsx` (the shared `KubeDataTable` fake — faithful init-time-capture variant)
- Modified (test-only, the fleet migration): the ~20 view tests that fake `KubeDataTable` inline (`grep -rln 'KubeDataTable' frontend/tests/views` is the authoritative list)
- Verified-only (no deletion in this change): the 23 backend files (`backend/app/aggregated/{project,sso_group,sso_user}.py`, `backend/app/models/{access_request,namespace_request,scim_map}.py`, `backend/app/schemas/kubectl_auth.py`, `backend/app/services/{access,grafana,loki,namespace,prometheus,provisioning,scim,tempo}.py`, `backend/app/sockets/{events,logs}.py`, `backend/app/tasks/{access_expiry,alerts,cluster_sync,health,ns_request_expiry,rbac_drift}.py`)

---

### Task 1: Verification pass — the deletion list

**Files:** none modified (the list is recorded in the commit body of Task 2's first batch)
**SATISFIES:** `deletion-list-verified`
- [ ] **Step 1: Re-generate the findings.** `npx jscpd --dead-code --reporters json .` → `report/basta-report.json` (the current list).
- [ ] **Step 2: Verify each candidate file is import-free.** For every unused-file finding under `frontend/` (the 58 + `Pods.tsx`): grep the **import specifier/module path**, not the bare basename (`grep -rn "components/tables/Tables\|dashboard/Dashboard\|authentication/login\|…" frontend/src frontend/tests frontend/e2e --include='*.ts*' --include='*.jsx'` — the module path catches `React.lazy(() => import('…'))`-style dynamic imports and `stubRoutes`; the bare basename is a collision-magnet: `DataTables` ⊃ `Tables`, `C*` CoreUI names ⊃ Badge/Tabs/Progress/InputGroup/Select, `Cluster/Dashboard` vs the template `Dashboard`, `views/Login` vs the template `Login`, 236 live `store/` zustand hits vs `store.js`). Disposition (criticD): a hit from a file **in the deletion set**, or from a **known-colliding identifier**, is a pass-with-note, not an exclusion; only a hit from a live file is an exclusion. Re-verify the Task 3 docs helpers (`DocsComponents*` — 37 demo files import them from the `src/components` barrel) AFTER Task 2 lands, as is done for `Pods.tsx`.
- [ ] **Step 3: Verify the unused-symbol candidates.** `wsgi.py`: `_rq_worker_main`/`_build_worker_app` — the spawn string at `wsgi.py:179` (`python -c "import wsgi; wsgi._rq_worker_main()"`, reached from `main()` → `_start_worker_if_leader` on the leader; there is no gunicorn config file in the repo) is the live reference: this pair is **expected to fail** the zero-hit rule and must be recorded as **live-dynamic (keep)**, not as an exception. `gateway_convert.py`: confirm `PROVIDERS`/`_REGEX_CHARS`/`_tls_secret_by_host` are not referenced in tests; the six data views' `KIND`/`LIST_ROUTE` + `NodeData.tsx`'s `PROBE_CONDITIONS` + `ServiceAccountData.tsx`'s `SecretRef`; `lib/types.ts`/`lib/groupTypes.ts` types; the migration's `_has_unique`; `scripts/prometheus-push.py`'s `_METRIC_RE` + `scripts/prometheus-push-e2e.py`'s `time` import. Same zero-hit rule otherwise.
- [ ] **Step 4: Record the verified list** (file → grep command → zero-hit result, exceptions annotated) — it goes into the body of Task 2's first deletion commit (no separate Task 1 commit; matches the Must-Have artifact wording).

### Task 2: Delete the template demo bulk (components/forms/widgets/dashboard)

**Files:** Deleted: `views/components/**` (25), `views/forms/**` (9), `views/widgets/**` (2), `views/dashboard/**` (3) (the files that passed Task 1)
**SATISFIES:** `template-bulk-deleted`
- [ ] **Step 1: Delete** the verified files; `git status` matches the list exactly.
- [ ] **Step 2: Run + commit.** `corepack pnpm test && task fe-build && task fe-check` green → `chore: delete CoreUI template demo files (components/forms/widgets/dashboard)`.

### Task 3: Delete the remaining template files + `Pods.tsx` + docs helpers

**Files:** Deleted: `views/authentication/**` (6), `views/charts/Charts.jsx`, `views/icons/**` (3), `views/error-pages/**` (2), `components/{AppContent,DocsComponents,DocsExample,DocsIcons,DocsLink}.jsx` (re-verified after Task 2 — the 37 demo files import them from the `src/components` barrel), `store.js`, `views/Cluster/Pods.tsx`
**SATISFIES:** `template-tail-deleted`
- [ ] **Step 1: Verify `Pods.tsx`** against the route table (`App.tsx` lazy imports + `stubRoutes`) — it is not imported (Task 1's pass covers it; this step is the explicit re-check because it sits in a live view directory).
- [ ] **Step 2: Delete** the verified files.
- [ ] **Step 3: Run + commit.** green → `chore: delete remaining template files, Pods.tsx, docs helpers`.

### Task 4: Unused imports + verified unused symbols

**Files:** Modified: the files from the File Structure section (import-cleanup lines + the verified symbols)
**SATISFIES:** `unused-code-removed`
- [ ] **Step 1: Imports.** Frontend: hand-delete each `unused-import` finding from the Task 1 re-generated report — `pnpm lint --fix` is formatting-only here (the eslint config has no unused-imports rule and matches no `.ts/.tsx` file; verified: `eslint src/views/Storage/ConfigMap.tsx` → 'File ignored'); `pnpm lint` still runs green after. Backend: `uv run ruff check --fix --select F401` + manual review of the diff in `backend/` (the 4 backend files + `dev/sso/server.py` + `scripts/prometheus-push-e2e.py` + the migration); drop the `.git/lost-found` finding (not source).
- [ ] **Step 2: Symbols.** Delete the Task 1-verified unused symbols (the `wsgi.py` pair is **live-dynamic** — the leader-RQ spawn string at `wsgi.py:179` — and stays; the migration's `_has_unique` + its orphaned comment at lines 83-85; `gateway_convert` leftovers; the dead `KIND`/`LIST_ROUTE` constants; `NodeData.tsx`'s `PROBE_CONDITIONS` + `ServiceAccountData.tsx`'s `SecretRef` (+ the comment at :29-30 that names it); the unused types; `_METRIC_RE`).
- [ ] **Step 3: Run + commit.** `corepack pnpm test && task fe-build && task fe-check && uv run pytest -m "not integration" && uv run ruff check . && uv run mypy app` green → `chore: remove unused imports and verified unused symbols`.

### Task 5: KubeDataTable test-fake fleet migration (moved from change B)

**Files:** Create: `frontend/tests/components/kube-data-table.test-utils.tsx` (the shared fake — the **faithful** init-time-capture variant: it reproduces the DataTables init-time prop capture the PV/PVC usage-join tests depend on); Modify: the ~20 view tests that fake `KubeDataTable` inline (`grep -rln 'KubeDataTable' frontend/tests/views` — three variants exist: simple, slot-renderer, faithful; each test keeps its own canned data, the fake provides the component behaviour)
**Interfaces:** the shared fake's API = the union of today's inline fakes' contracts; where the variants conflict the faithful variant wins — a test whose behaviour changes is a stop-and-report, not a silent adaptation
**SATISFIES:** `test-fake-fleet-migrated`
- [ ] **Step 1: Extract the faithful fake.** From `pvs.test.tsx` (the init-time-capture variant) into `tests/components/kube-data-table.test-utils.tsx`; switch `pvs.test.tsx` + `pvcs.test.tsx` to it; `corepack pnpm test` green.
- [ ] **Step 2: Migrate the rest.** Each remaining inline fake (simple + slot-renderer variants) switches to the shared fake with the test's canned data; test expectations unedited.
- [ ] **Step 3: Run + commit.** `corepack pnpm test && task fe-build` green → `test: migrate KubeDataTable test fakes to one shared fake`

### Task 6: Backend 23 files — dynamic-wiring verdicts (verification only)

**Files:** none deleted in this change; a `.backlog` note created via the `backlog` CLI
**SATISFIES:** `backend-files-verified`
- [ ] **Step 1: Check each of the 23 files for dynamic wiring — grep scope is `backend/`, not just `backend/app`:** the scheduler call sites are `wsgi.py:70-73` (`INTERVALS` + the enqueue loop at :194) and the spawn string at `wsgi.py:179`; `backend/tests/` — **`tests/test_file_map.py`'s `EXPECTED` lists all 23 files verbatim** (every file is string-pinned); plus the sockets blueprint registration (`app/sockets/__init__` / the app factory — `SocketIO(` is instantiated nowhere, so the two sockets files are docstring-only stubs), the models import (`app/models/__init__.py` deliberately keeps the 3 stub models UNIMPORTED — a design fact to record), the aggregated app factory (`app/aggregated/` — the `:8443` mock mTLS app), the services (called by name or string from tasks/api).
- [ ] **Step 2: Record** a per-file verdict in a backlog note — distinguish **stub-by-design** (owning change lands it) from **dead**: `health.py` + `cluster_sync.py` are live-dynamic (the wsgi scheduler; the only two of the 23 that import live code); the rest are stub-by-design. Any file grep-proven dead AND not string-pinned gets a **proposed-deletion** flag for a follow-up change; every file in `test_file_map.py`'s `EXPECTED` is string-pinned, so a proposed-deletion flag must note the `test_file_map.py` + `ARCHITECTURE.md` §2 update it implies — no deletions in this change.
- [ ] **Step 3: Commit.** the note (tracker) + `chore: backend dead-file verification note`.

### Task 7: Green + measure

**Files:** none
**SATISFIES:** `dead-code-measured`
- [ ] **Step 1: Full floor.** `corepack pnpm test` + `task fe-build` + `task fe-check` + `task e2e` + `uv run pytest -m "not integration"` + `uv run ruff check .` + `uv run mypy app`.
- [ ] **Step 2: Re-measure.** `npx jscpd --health --reporters ai .` — record the new dead-code % and overall health vs the 2026-11-07 baseline (dead-code 22 / 16.6%, 187 findings) in the commit body.
- [ ] **Step 3: Commit.** `chore: dead-code re-measure (baseline 2026-11-07)`.

## Self-Review (ran 2026-11-07)

1. **Spec coverage:** R1 → Task 1 (verification) + every batch's grep rule; R2 → every task's green step + Task 7's e2e; R3 → global constraint (deletions + import lines only); R4 → Task 6; R5 (the test-fake fleet migration, moved from change B) → Task 5. No gaps.
6. **Critic fold-in (2026-11-07):** the fleet `KubeDataTable` test-fake migration lands here as Task 5 (user decision: out of change B's R1–R7 scope; the shared fake is the faithful variant — the PV/PVC usage-join tests depend on the DataTables init-time-capture quirk). All 7 criticD findings resolved — the zero-hit rule scoped to import specifiers + the collision disposition (24 substring collisions vs live identifiers); the wsgi pair recorded live-dynamic (spawn string at :179); the frontend import mechanism corrected (hand-delete from the report; eslint has no unused-imports rule and no `.tsx` scope); the RQ greps scoped to `backend/` (the scheduler lives in `wsgi.py:70-73`; `test_file_map.py` pins all 23); File Structure counts corrected to the report (45 → 58, `views/dashboard/**` itemized); the verification record pinned to Task 2's first commit body; `PROBE_CONDITIONS` + `SecretRef` + `prometheus-push-e2e.py`'s `time` added to the symbol lists.
2. **Must-haves coverage:** all four requirements map to truths/artifacts/links; the behaviour-invariance truth is the `backstop` with `task e2e` as the held-out test.
3. **One-way-door completeness:** pure deletions — none.
4. **Placeholder scan:** the file lists are the 2026-11-07 jscpd findings (re-verified against a fresh run in Task 1 Step 1 — a finding that disappeared or gained a reference is handled by the zero-hit rule, not by trust in this document).
5. **Type consistency:** n/a (no new code).
