# Report — Dead-Code Cleanup (Change D): template leftovers + unused code

> Change: `.skillgrid/specs/2026-11-07-dead-code-cleanup/` (moves to `.skillgrid/archive/2026-11-07-dead-code-cleanup/` at ship)
> Generated: 2026-11-08T00:00Z (qa)
> Gate: PASS
>
> Two phases, one file: **qa** writes the QA half (the sections above `## Final-State Facts`,
> through `## Gate Decision` + `## Human Override`) into the spec folder. **ship** reads the
> `## Gate Decision` verdict PRE-MOVE, then moves the folder. **reflect** completes the retro
> half (from `## Final-State Facts` onward) IN PLACE in the archive folder.
>
> **Tier:** T0 (blueprint header). Change-classification floor (deletion chore): per-ticket
> static verification + verification floor green at every commit + measured outcome. Tier
> T0 adds no audits above the classification floor.
>
> **Branch:** `rebase`, base `866bae7f`, head `f717f685` (11 commits, 2026-11-08).

## Test Plan

> Derived from `blueprint.md`, `tasks.md`, and `acceptance.feature`.
> Risk-ordered. Every row must be covered by a named test or scenario before the gate passes.

### Risk Ranking

Most likely production breakage: deleting a file that is still referenced (static import,
lazy-route string, spawn string, barrel re-export) → runtime crash or dead route. Second:
the KubeDataTable fake migration silently changing a test's behaviour. Third: the
measurement itself — the dead-code % not actually dropping.

### Plan

| # | Risk / Behavior | Seam | Layer | Test / Scenario | Priority | Cadence | Status |
|---|-----------------|------|-------|-----------------|----------|---------|--------|
| 1 | No file deleted while still referenced (import specifier, dynamic import, string wiring) | per-file grep verification recorded pre-deletion | static + unit | `task-01-report.md` verification table (60 files, 12,967 lines; grep command + zero-hit per file) + reviewer re-verification per batch (ReviewD02, ReviewD03) | P0 | pr | covered |
| 2 | CoreUI demo bulk (components/forms/widgets/dashboard) gone | git status vs verified list; suite at commit | unit | `b9156319` (39 files, 11,439 lines); `corepack pnpm test` + `task fe-build` + `task fe-check` green at commit | P0 | pr | covered |
| 3 | Template tail + Pods.tsx + docs helpers gone | route table (App.tsx lazy imports + stubRoutes) + importer re-grep after bulk | static + unit | `f724c5d4` (20 files, 1,528 lines) + `c40d4c49` (icons barrel); suite green at commit | P0 | pr | covered |
| 4 | 79 unused imports + verified symbols removed; wsgi live-dynamic pair intact | ruff F401 + manual diff; re-generated jscpd | unit | `35469827` (87 files, 143 deletions); re-generated jscpd: 0 unused-import findings; `_rq_worker_main`/`_build_worker_app` present (spawn string wsgi.py:179) | P1 | pr | covered |
| 5 | One shared KubeDataTable fake; zero test-expectation edits | `frontend/tests/components/kube-data-table.test-utils.tsx` | unit | `1802d456` (33 files, −1,633/+268) + `fad8f44e` + `c336ad03`; 491/491 vitest at commit | P0 | pr | covered |
| 6 | 23 backend files: per-file verdict, no deletions | .backlog verification note | static | `5654e914` (58-line note: live-dynamic ×2, stub-by-design ×21, test_file_map.py string-pin per file); 0 backend deletions in range | P1 | pr | covered |
| 7 | Full floor green + dead-code measured down | verification floor + jscpd | unit + e2e | `f717f685` (measure commit): pnpm 491/491, fe-build, fe-check, e2e 20/20, pytest 761, ruff 93, mypy 76; jscpd dead-code 16.6% → 0.56% (187 → 36 findings); no clone pairs in views/components|forms|widgets | P0 | pr | covered |

### Edge-Case Matrix

| Requirement | Edge / Boundary | Expected Behavior | Test / Scenario | Status |
|-------------|-----------------|-------------------|-----------------|--------|
| R1 | Dynamic/lazy imports (App.tsx route strings) | Pods.tsx re-verified against route table before deletion | Plan row 3 | covered |
| R1 | Spawn-string wiring (wsgi `_rq_worker_main` at wsgi.py:179) | recorded live-dynamic, NOT deleted | Plan row 4 | covered |
| R1 | String-pin wiring (test_file_map.py EXPECTED) | all 23 backend files pinned → kept | Plan row 6 | covered |
| R1 | Barrel re-exports (views/icons/index.js, components/header/index.js) | barrel judged entry point by jscpd → contents not flagged; icons barrel deleted as T03 addendum row 60 after orphanking | Plan rows 3, 6; TASK-099 for the header chain | covered |
| R1 | Known-colliding identifiers (basename hit ≠ import hit) | grep by import specifier or module path, not bare basename; hit from live file excludes with recorded exception | task-01-report.md verification table | covered |
| R5 | Fake API drift (init-time capture vs re-render) | faithful init-time-capture fake extracted from pvs.test.tsx; per-file canned data unchanged | Plan row 5 + ReviewD05 faithfulness audit | covered |
| R5 | Test whose behaviour changed under the shared fake | stopped and reported, not silently adapted — one (certmanager tab-switch stale closure) → re-scoped in `fad8f44e`, view quirk tracked TASK-096 | Plan row 5 | covered |

### Out of Scope

- Behaviour changes — this change is a deletion chore (zero behaviour change by design); the single intentional test delta (certmanager re-scope) is the exception, named above.
- E2E coverage of deleted views — the deleted views were unrouted (no route in App.tsx), so no e2e exercised them; the e2e floor (20/20) covers the surviving surface.
- Integration tests (kind-gated, Testcontainers) — not part of the unit floor (`-m "not integration"`); the dev stack was up for e2e.
- Pre-existing duplication in the per-kind `*Data.tsx` family and `App.tsx` routing table — out of this change's scope; the kind-catalog change (2026-11-07-kind-catalog) is the structural home.

## Goal-Backward Verification

**Stated goal** (from briefing.md): delete the confirmed dead code (CoreUI template demo
material + individually verified unused code, pure deletions), record the dynamic-wiring
verdict for the 23 backend files, migrate the ~20 inline KubeDataTable test fakes onto one
shared fake — zero behaviour change, proven by the suites green at every commit, and the
jscpd dead-code percentage measured down from 16.6%.

**Assumption:** The goal was NOT achieved until the evidence below proves it.

| Level | Item | Evidence | Status |
|-------|------|----------|--------|
| Truth R1 | no file deleted without recorded import-free proof | `task-01-report.md` (60 files: grep command, zero-hit result, exceptions annotated); re-verified per batch by ReviewD02/ReviewD03/ReviewD04; orphaned icons barrel caught as T03 addendum (row 60, `c40d4c49`) | VERIFIED |
| Truth R2 | dead-code % drops from 16.6% toward ~1%, floor green | `f717f685` measure: jscpd dead-code 0.56% (187 → 36 findings), health 32/E → 55/C; controller independently re-ran `npx jscpd --health` on the final tree and matched the numbers (8-line tree delta fully accounted for: T04 fix round 2, −9/+1) | VERIFIED |
| Truth R3 | change diff = deletions + import-cleanup lines only | per-task reviewer diffs (all 7 tickets) + whole-branch review: 2 fix commits (`7a55bde3` Fragment, `17425c2f` CIcon) are repairs of jscpd false-positive regressions introduced by this branch, not behaviour | VERIFIED |
| Truth R4 | 23 backend files get per-file verdict, none deleted | `5654e914` note (58 lines, per-file verdict + string-pin); git stat: 0 backend files deleted in `866bae7f..f717f685` | VERIFIED |
| Truth R5 | one shared fake, no test behaviour change | `1802d456` diff (expectations unedited; canned data per file kept); 491/491 vitest; the one behaviour delta (certmanager) stopped-and-reported → re-scoped `fad8f44e`, view quirk TASK-096 | VERIFIED |

**Key Link:** route table ↔ deleted views — App.tsx lazy imports + stubRoutes contain no
reference to any deleted file (verified in T03 for Pods.tsx, bulk for the rest). VERIFIED.

**Data Flow:** n/a — deletion chore; no new data path. The observable effect is the jscpd
measurement itself, which moved as predicted (16.6% → 0.56%). VERIFIED.

## Traceability Matrix

| Scenario (from acceptance.feature) | Test / Scenario (from test plan) | Ran | Result |
|--------------------------------------|----------------------------------|-----|--------|
| deletion-list-verified | task-01-report.md verification table + per-batch reviewer re-verification | yes | pass |
| template-bulk-deleted | `b9156319` + suite green at commit (ReviewD02 APPROVED) | yes | pass |
| template-tail-deleted | `f724c5d4` + `c40d4c49` + suite green at commit (ReviewD03 APPROVED) | yes | pass |
| unused-code-removed | `35469827` + re-generated jscpd 0 unused-import findings + floor green (ReviewD04 APPROVED after fix round 2 `17425c2f`) | yes | pass |
| test-fake-fleet-migrated | `1802d456` + `fad8f44e` + `c336ad03`, 491/491 vitest (ReviewD05 APPROVED after `7a55bde3` Fragment fix) | yes | pass |
| backend-files-verified | `5654e914` note (23/23 verdicts) + 0 backend deletions (ReviewD06 APPROVED) | yes | pass |
| dead-code-measured | `f717f685` full floor (controller re-verified numbers) | yes | pass |

**Coverage:** 7/7 scenarios covered by a test/check that ran and passed.

## Verification-Gap Audit

| Gap | Location | Shape | Evidence | Smallest Regression |
|-----|----------|-------|----------|---------------------|
| jscpd entry-point heuristic blind spot: files imported only from a barrel (`index.js`) are judged "imported" and never flagged as unused files | `frontend/src/views/icons/index.js` (caught by our T03 orphanking), `frontend/src/components/header/index.js` (pre-existing miss, 3 files, TASK-099) | broken-verification (tooling) | T03 addendum row 60; ReviewD04 finding on the header chain (grep: zero external refs, 9 CIcon uses inside the chain) | a new barrel-imported file added to the template could never be flagged dead by jscpd alone |
| certmanager stale-closure view quirk (highlight not updated on tab switch) — test re-scoped to real behaviour; the *ideal* behaviour is unverified | `frontend/src/views/Storage/CertManagerData.tsx` (or the equivalent path named in `fad8f44e`) | regression (view), tracked | `fad8f44e` re-scope + TASK-096 | a fix to the view would break the re-scoped test, which pins the quirk |
| known pre-existing flake: `users.test.tsx` relatedTarget TypeError (unhandled error, not a test failure) | `frontend/tests/.../users.test.tsx` | broken-verification (flake), tracked | verified on pristine tree during T04 review; 1 unhandled error at T07 floor, 0 failing tests; TASK-097 | the flake can mask a real unhandled-error regression in the same file |

**Gap shapes:** none are regression gaps in this change's own code (deletion chore); all
three are named and tracked (TASK-096/097/099).

## TDD Evidence Audit

> Evidence model for a deletion chore (no new behaviour → no RED phase): per-file static
> verification + verification floor green at each commit + per-task report. T05 (fake
> extraction) is a test refactor — the shared fake file is the only new artifact; its
> "evidence" is the unchanged expectations + green suite.

| Task | SATISFIES | RED (commit + exit) | GREEN (commit + exit) | TRIANGULATE (commit + exit) | REFACTOR (suite exit) | Verdict |
|---|---|---|---|---|---|---|
| TASK-089 (T01) | deletion-list-verified | n/a (verification pass, no code) | `5654e914`-era report: task-01-report.md (60 files verified) | reviewer re-verification ×3 batches | floor green at T02 commit | OK |
| TASK-090 (T02) | template-bulk-deleted | n/a | `b9156319` (39 files, −11,439) | ReviewD02 | pnpm + fe-build + fe-check exit 0 | OK |
| TASK-091 (T03) | template-tail-deleted | n/a | `f724c5d4` (20 files, −1,528) + `c40d4c49` (barrel addendum) | ReviewD03 + icons-barrel orphanking caught | floor exit 0 | OK |
| TASK-092 (T04) | unused-code-removed | n/a | `35469827` (87 files, −143) + `17425c2f` (CIcon restore) | ReviewD04 (fix round 2) | floor exit 0 (ruff 93 = no new) | OK |
| TASK-093 (T05) | test-fake-fleet-migrated | n/a (refactor; pre-migration suite = same expectations) | `1802d456` (33 files) + `fad8f44e` + `c336ad03` + `7a55bde3` | ReviewD05 (fake faithfulness audit) | pnpm 491/491 exit 0 | OK |
| TASK-094 (T06) | backend-files-verified | n/a | `5654e914` (58-line note) | ReviewD06 (23/23 verdicts) | pytest exit 0 | OK |
| TASK-095 (T07) | dead-code-measured | n/a | `f717f685` (measure commit; floor + jscpd) | controller independent re-measure | full floor exit 0 | OK |

**Summary:** 7/7 tasks have complete evidence for the deletion-chore model. (No RED phase
by change shape — W015/W021 co-commit-shape precedent applies; the per-task reports in
`.skillgrid/meta/.sdd/2026-11-07-dead-code-cleanup/` carry the verification detail.)

## Assertion Quality Audit

| File | Line | Pattern | Evidence | Severity |
|---|---|---|---|---|
| `frontend/tests/components/kube-data-table.test-utils.tsx` | — | (shared fake, not a test) | faithful init-time-capture shape extracted from pvs.test.tsx; audited by ReviewD05 | — |
| certmanager tab-switch test (`fad8f44e`) | — | implementation-detail coupling (pins the stale-closure quirk as "real behaviour") | deliberate re-scope per the change's stop-and-report rule; view fix tracked TASK-096 | SUGGESTION |
| 32 migrated view tests (`1802d456`) | — | (expectations unedited) | diff-verified by ReviewD05: only the fake import line changed per file | — |

**Summary:** 0 CRITICAL, 0 WARNING, 1 SUGGESTION.

## Changed-File Coverage

Coverage: n/a — no coverage tool configured (`testing.coverage` absent from config;
Vitest/RQ coverage not in the repo floor).

## Test Quality Audit

| Test | Contract Violated | Evidence |
|------|-------------------|----------|
| 32 migrated view tests | none — expectations byte-identical to pre-migration (ReviewD05 diff) | `1802d456` diff |
| certmanager re-scope | none — asserts real component behaviour (highlight state after re-render), the claimed path | `fad8f44e` |
| shared fake | Complete mocks — realistic KubeDataTable shape (init-time capture API), not a partial stub | `kube-data-table.test-utils.tsx` |

## Test Strategy Audit

**Available layers** (from `testing.layers`): unit (vitest / pytest), e2e (Playwright), integration (kind-gated).

| Behavior | Assigned Layer | Degrade? | Duplicate Coverage? | Rationale |
|----------|---------------|----------|---------------------|-----------|
| deletion safety (no live refs) | static grep + unit suite | no | no | no lower layer can see import wiring; the suite at commit catches what grep can't |
| fake-migration neutrality | unit (vitest) | no | no | tests are the artifact under change |
| dead-code measurement | static (jscpd) + full floor | no | no | the measurement IS the acceptance evidence |
| surviving-surface health | e2e (20/20) | no | no | auth-smoke + ui-smoke against the local stack |

**Layer distribution:** static 4, unit 2, e2e 1 — appropriate for a deletion chore (no
behaviour to unit-test; the suite is the regression net, not the proof).

## Security Audit

**Mode:** Manual fallback (Trivy not configured for qa in config).

### Manual Findings (Mode B)

#### Secrets Archaeology

| Location | Type | Evidence | Severity |
|----------|------|----------|----------|
| — | — | deletion-only change + test migration; no new files with credentials | — |

#### Dependency Audit

| Dependency | CVE / Issue | Severity | Fix Available |
|------------|-------------|----------|---------------|
| — | none added; `task fe-check` (air-gap) green on the built bundle | — | — |

#### OWASP Spot-Check

| File | OWASP Item | Pattern | Evidence |
|------|------------|---------|----------|
| — | — | no API surface changed; no user-input path touched (deletions + test fakes) | diff `866bae7f..f717f685` |

**Security verdict:** PASS — 0 findings. No user-facing input in this change.

## Code Quality Gate

| Gate | Command | Threshold (config) | Actual | Result |
|------|---------|--------------------|--------|--------|
| Coverage (whole project) | not configured | 80 (default) | n/a | N/A |
| Changed-file coverage | not configured | 80 (default) | n/a | N/A |
| Mutation | not configured | 80 (default) | n/a | N/A |
| Lint (backend) | `uv run ruff check .` | errors only | 93 = T04-end baseline; 0 new vs base 866bae7f (pre-existing debt, W013/TASK-098) | PASS (no new) |
| Typecheck (backend) | `uv run mypy app` | errors only | 76 < 78 at base; 0 new (TASK-098) | PASS (no new) |
| Lint (frontend) | `task fe-build` (tsc + eslint + vite) | errors only | green at `f717f685` (fe-check air-gap green) | PASS |
| P0 pass rate | floor suites (pnpm, pytest, e2e) | 100% | 491/491 vitest, 761 pytest, 20/20 e2e (1 unhandled error = known TASK-097 flake, 0 failing tests) | PASS |
| P1 pass rate | floor suites | 95% | 100% | PASS |
| Trivy security | not configured | report only | manual, 0 findings | N/A |
| Duplication (jscpd) | `npx jscpd --health .` (full repo — the change's measure target) | report only | dead-code 0.56% (187 → 36); health 32/E → 55/C | PASS (advisory) |

**Quality config status:** not configured — using defaults (no `quality:`/`testing:` in
config.yaml).

## Duplication

**Command:** `npx jscpd --health --reporters ai .` (full repo, not changed-files — the
change's acceptance is the repo-wide measure)

**Result:** 2089 clones → reduced after deletions; no clone pairs remain in
`views/components`, `views/forms`, or `views/widgets` (T07 clone check PASS). Duplication
dimension 19.8 → 28.6.

| Files (lines) | Kind | Introduced? | Severity | Note |
|---------------|------|-------------|----------|------|
| `App.tsx` routing table + per-kind `*Data.tsx` family | exact | pre-existing | SUGGESTION | structural home: 2026-11-07-kind-catalog change |
| `backend/tests/api/test_*.py` per-kind test blocks | exact | pre-existing | SUGGESTION | out of scope for a frontend-heavy deletion chore |

No clone pairs were introduced by this change (the two jscpd false-positive regressions it
briefly introduced — `7a55bde3`, `17425c2f` — were caught in review and repaired in-branch).

## State Drift

Manual check (script `state-drift-check.mjs` available):

**Verdict:** DRIFT DETECTED (expected, pre-ship)

| Field | Stale (state.yaml) | Derived (spec zone) |
|-------|-------------------|---------------------|
| in_flight 2026-11-07-dead-code-cleanup.phase | `slicing` | qa (this report) |

**Fix applied:** updated at ship (phase → `shipped`, moved to completed_changes).

## Verification Scope

| Derivation | Scope | Stale? |
|---|---|---|
| Traceability matrix | COMPLETE (7/7 scenarios; all 11 commits read; per-task reports read) | none |
| Verification-gap audit | COMPLETE (full diff `866bae7f..f717f685` audited per-ticket + whole-branch review) | none |
| Deletion lists | COMPLETE (60 files enumerated; 12,967 lines; per-file grep recorded) | none |
| jscpd measure | COMPLETE (full repo run, controller re-ran independently) | none |
| State Drift | COMPLETE (manual) | none |

**Stale-verification:** `STALE: none` — the gate rests on `f717f685`'s floor (final tree)
plus the controller's independent re-measure on the same tree.

## Floor

| Dimension | Verdict |
|---|---|
| Goal-backward verification (weakest truth) | VERIFIED |
| Traceability (weakest scenario) | COMPLIANT (7/7 pass) |
| Verification-gap audit | SUGGESTION (3 named, all tracked) |
| TDD evidence (weakest ticket) | OK (deletion-chore model) |
| Assertion quality audit (weakest finding) | SUGGESTION (certmanager quirk pin) |
| Changed-file coverage (weakest file) | N/A (not configured) |
| Test quality audit | none |
| Code-quality gates (weakest gate) | PASS (lint debt pre-existing, 0 new) |
| Security audit | PASS |
| Verification scope (composite) | COMPLETE |

**FLOOR:** PASS-eligible — no dimension is below SUGGESTION-level; every scenario
compliant; scope COMPLETE.

## Findings

> Open WARNING/SUGGESTION findings auto-appended to `.skillgrid/WINDOWS.md` at gate-render
> time.

### CRITICAL (must fix before merge)

- None.

### WARNING (should fix before archive)

- W013 (existing, open): pre-existing backend lint debt — `ruff check .` 93, `mypy app` 76
  (both < base 866bae7f; 0 new in this range). Tracked TASK-098. No new window row (W013
  covers the debt; counts updated here).
- New: known pre-existing flake — `users.test.tsx` relatedTarget TypeError (unhandled
  error, 0 failing tests; verified on pristine tree). Tracked TASK-097.

### SUGGESTION (nice to have)

- New: certmanager stale-closure view quirk — re-scoped test pins real behaviour; the view
  fix is tracked TASK-096.
- New: dead `frontend/src/components/header/` chain (index.js barrel + 2 components, ~90
  lines) — pre-existing jscpd entry-point-heuristic miss (same class as the icons barrel);
  zero external refs, verified 2026-11-08. Tracked TASK-099.

## Gate Decision

**Verdict:** PASS

**Reasoning:** All 7 acceptance scenarios ran and passed with per-ticket evidence; all
truths R1–R5 VERIFIED by named evidence (not grep alone); the measurement landed as the
change's own acceptance criterion (dead-code 16.6% → 0.56%, floor green at every commit);
no CRITICAL findings in any audit. The open items are all pre-existing or tracked
follow-ups (W013 lint debt, TASK-096/097/099), matching the repo's established practice
for pre-existing debt carried as open windows (2026-11-03 session-object-navigation QA
PASS with W013 open; 2026-11-05 storage batch PASS with lint debt noted).

**Open items (if CONCERNS):** none — PASS.

**Waiver (if WAIVED):** n/a.

## Human Override

> A human decision always overrides this machine verdict.

**Human decision (fill in):** — (no override; machine PASS stands)

<!-- reflect completes this half at archive time -->

## Final-State Facts

**Shipped:** <what actually shipped>
**Base branch:** <base-branch> · **Chain strategy:** <strategy>
**Integration:** <merged @ <commit> | PR <url> | kept branch <name>> (from ship context)

## Gates

| Gate | Result |
|------|--------|
| Ship gate | ✅ success + `diff -r` empty (or: blocked — {reason}) |
| QA gate | ✅ PASS |
| Verdict gate (advisory) | {accepted \| accepted-with-open-items \| rejected} — recorded, not enforced |

## Decisions

**Every entry MUST cite a source** — a file:line, a commit, a ticket ID, or a scenario
name. No source = undiagnosed, not a learning.

| Decision | Tradeoff | Why | Source |
|----------|----------|-----|--------|
| <choice made> | <what was given up> | <why it won> | <source> |

## Lessons

| Lesson | Root Cause | Do Differently | Source |
|--------|-----------|----------------|--------|
| <what to do differently> | <why it went wrong — root, not symptom> | <the concrete change> | <source> |

## Patterns

| Pattern | Reuse | Source |
|---------|-------|--------|
| <named reusable approach / convention> | <when a future change should apply it> | <source> |

## Surprises

| Surprise | Signal | Source |
|----------|--------|--------|
| <non-obvious gotcha / edge case / behaviour> | <what the evidence shows> | <source> |

## Environment Retro

**Written by `skillgrid:environment-retro` (a reflect sub-phase), not qa.**

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| — | — | — | — |

## Acceptance Verdict

**Verdict:** <accepted | accepted-with-open-items | rejected>

**Grounding:** <goal from briefing.md + evidence>

**Reasoning:** <what drove the verdict>

## Open Items (→ next change)

- <item + path to resolution> (or "None")

## Web-cache promotion candidates

No web-cache promotion candidates — web cache disabled/empty.

## Prior-Change Follow-Through

| Prior open item (from previous archived change) | Addressed by this change? | Evidence |
|--------------------------------------------------|---------------------------|----------|
| <item> | yes / no / partially | <commit / file:line / scenario, or "still open"> |

## Move Evidence (from ship context)

**From:** `.skillgrid/specs/2026-11-07-dead-code-cleanup/` → **To:** `.skillgrid/archive/2026-11-07-dead-code-cleanup/`
**`diff -r` readback:** <empty → PASS | verbatim output → FAIL>

## Overrides / Waivers / Contradictions

- None recorded by qa.

## Lineage (observation IDs)

- briefing: <id>
- blueprint: <id>
- tasks: <id>
- ship: <id>
- report (QA half): <id>
- research / findings / ADRs: none
