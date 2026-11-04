# Report — Session Object Navigation

> Change: `.skillgrid/specs/2026-10-29-session-object-navigation/` (moves to `.skillgrid/xarchive/…` at ship)
> Generated: 2026-11-03 (qa) · Re-verified: 2026-11-04 (post C1 fix)
> Gate: **PASS** (re-verified 2026-11-04 — C1 fixed via the ADR-0040-amended
> server-session handoff; `task e2e` 19/19 incl. the R4 deep link)
>
> Two phases, one file: **qa** writes the QA half (through `## Gate Decision` +
> `## Human Override`). **ship** reads the `## Gate Decision` verdict PRE-MOVE,
> then moves the folder. **reflect** completes the retro half (from
> `## Final-State Facts` onward) IN PLACE in the archive folder.

**Tier:** T2 (blueprint header) → floor L2+L3 (full suite, build, lint/typecheck).
**Classification floor:** `standard` → L2. Applied floor: L2+L3 (tier selects
upward). **Quality config:** not configured — using defaults (p0 100 / p1 95;
no `testing.coverage` → coverage N/A; no mutation/trivy/jscpd commands → those
gates N/A).

**Scope:** base `98613f68` → tip `80f3bd0f`, branch `rebase`, 176 files
(36 view files + 4 new components/lib + `App.tsx` + 27 test/e2e files + spec
zone). Backend/cli/charts diff in range: **0 files** (R10). Dependency-file
diff: **0 lines** (no new dependencies, ADR-0020).

## Test Plan

### Risk Ranking

The novel seams are `objectRef.ts` (registry/relay/expiry) and the form-POST
cross-tab handoff (R4/R5) — everything else is mechanical view repointing.
The handoff is the one behavior that crosses a document boundary no unit test
can fully span (jsdom cannot POST-navigate a fresh tab), so it is tested
hardest at e2e level: a real new tab, real form submit, real relay
consumption. Second risk: the route merge (R6/R7) — old URLs must redirect
once and the merged route must dispatch list/detail on the ref.

### Plan

| # | Risk / Behavior | Seam | Layer | Test / Scenario | Priority | Cadence | Status |
|---|-----------------|------|-------|-----------------|----------|---------|--------|
| 1 | Cross-tab share deep link hydrates the new tab | form POST → 303 bounce → one-shot meta → `consumeIncoming` | e2e | `ui-smoke.spec.ts::deep link: share in a new tab renders the object with a clean URL` | P0 | pr | covered (C1 fixed; e2e 19/19 at 2026-11-04 re-run) |
| 2 | Old `/.../data?name=…` URL redirects to clean route, ref origin `link` | `OldDataRedirect` | unit + e2e | `App.test.tsx::old URL with ?name=/?namespace= lands on the clean route, ref origin link` + `ui-smoke.spec.ts::old URL redirect` | P0 | pr | covered |
| 3 | No identity in the URL after opening an object (R1) | list row click → `openObject` | unit | `priority_classes.test.tsx::click-name-renders-detail-with-clean-url` + 26 view test files asserting `location.search === ''` | P0 | pr | covered |
| 4 | Ref's namespace is authoritative (R8) | `ObjectRoute` detail props | unit | `secrets.test.tsx::secret-data-reads-the-ref-namespace-not-the-header` (captures the real API request's `namespace` param) | P0 | pr | covered |
| 5 | 15-min lazy expiry clears the active pointer (R3) | `getActiveRef` | unit | `objectRef.test.ts::backdated > 15 min: lazy expiry clears the active pointer and drops the entry` | P0 | pr | covered |
| 6 | One-shot relay: consume + self-delete; stale relay → list (R5) | `consumeIncoming`/`sweepRelay` | unit | `objectRef.test.ts::hydrates the relay into the registry + active pointer and self-deletes both keys`, `::expired relay (age > 60s) → null`, `::no ?o= param (plain GET) → null` | P0 | pr | covered |
| 7 | One route per kind; mismatched ref renders the list (R6) | `ObjectRoute` dispatch | unit | `object_route.test.tsx::renders the list when the active ref kind mismatches (R6)` + route-table audit (15 `/data` entries, all `OldDataRedirect`) | P0 | pr | covered |
| 8 | Back from detail returns to the list (R6) | browser history + ref clear | e2e | QA probe (throwaway, run at this gate): click → detail → `page.goBack()` → list renders — **passed** | P1 | pr | covered (probe) |
| 9 | `?selected=` hint replaced by the active ref (R9) | `Secret` list bolding | unit | `secrets.test.tsx::bolds-the-opened-secret-from-the-active-ref` (positive + negative row) | P1 | pr | covered |
| 10 | No new endpoint/migration/dependency (R10 as amended) | diff | diff | `git diff 98613f68..tip -- backend/` = exactly the SPA-fallback handoff plumbing (`app/core/object_handoff.py`, `app/__init__.py` catch-all, `tests/api/test_object_handoff.py`); cli/charts: 0 files | P0 | pr | covered |

### Edge-Case Matrix

| Requirement | Edge / Boundary | Expected Behavior | Test / Scenario | Status |
|-------------|-----------------|-------------------|-----------------|--------|
| R3 | ref backdated 16 min | list renders, pointer cleared | `objectRef.test.ts::backdated > 15 min…` | covered |
| R5 | guessed token, no relay | list (never a wrong object) | `objectRef.test.ts::absent relay for a guessed token → null` | covered |
| R5 | orphaned relay body without `_exp` | swept, never consumed | `objectRef.test.ts::an orphaned body without its _exp key is swept` | covered |
| R5 | relay expired (age > 60 s) | null + swept | `objectRef.test.ts::expired relay (age > 60s) → null` | covered |
| R6 | kind mismatch on route | list of the route's kind | `object_route.test.tsx::kind mismatches (R6)` | covered |
| R7 | legacy URL without `?namespace=` | header namespace fallback (4.1 parity) | `App.test.tsx::old URL without ?namespace= falls back to the header namespace` | covered |
| R8 | header `default`, ref `team-a` | API read for `team-a` | `secrets.test.tsx::secret-data-reads-the-ref-namespace-not-the-header` | covered |
| R2 | corrupt registry JSON | empty registry, no throw | `objectRef.test.ts::corrupt JSON degrades to an empty registry, not a throw` | covered |

### Out of Scope

- Pod exec/logs (ADR-0009 channel — its own spec), OIDC login flow (ADR-0025,
  clean by construction), row-expansion UI (briefing Non-goals).
- The 9 stub kinds (configmap, pvc, volumesnapshot, storageclass,
  snapshotclass, service, ingress, ingressclass/gatewayclass): their specs'
  `NAVIGATION-SUPERSEDED.md` tells their executors to build to this contract
  directly.
- statefulsets/daemonsets/replicasets: NOT yet landed (no `Workload/` view
  files, no App.tsx routes) → TICKET-08(a) is a no-op, verified.

## Goal-Backward Verification

**Stated goal** (from briefing.md): object identity never appears in the URL;
the open-object ref lives in tab-private `sessionStorage`; a share/copy action
opens the object in a new tab via a same-origin form-POST deep link.

**Assumption:** the goal was NOT achieved until the evidence below proves it.

| Level | Item | Evidence | Status |
|-------|------|----------|--------|
| Truth | R1 — no identity in any produced URL | 26 view test files assert `location.search === ''` after open; `grep -rn 'data?name=' frontend/src` = 0; e2e deep-link popup `location.search === ''` passed | VERIFIED |
| Truth | R2 — ref in sessionStorage only, no server store | `objectRef.test.ts::round-trips a token-keyed entry through sessionStorage` + `::no localStorage identity outside the kd_ref_ relay keys` + backend diff empty (no endpoint) | VERIFIED |
| Truth | R3 — refresh survives; 15-min lazy expiry | render-from-persistent-sessionStorage tests (`object_route.test.tsx::renders the detail when the active ref kind matches`) + `objectRef.test.ts::backdated > 15 min` | VERIFIED |
| Truth | **R4 — new tab hydrates the ref on mount and renders the object** | FIXED 2026-11-04 (ADR-0040 amendment, user decision): the SPA fallback accepts the share form's POST (`app/core/object_handoff.py`), 303s to the same clean path (token stays out of URLs — R1), stashes the token server-side under `obj_incoming:<sub>` (Redis, 60 s), and injects it as a one-shot `<meta name="kd-object-incoming">` into the fresh tab's document; `consumeIncoming()` reads the meta and resolves the relay. Evidence: e2e `ui-smoke.spec.ts::deep link` passed at re-run (popup URL clean, detail rendered, relay self-deleted); curl trace on the live stack: login 302 → POST 303 → GET injects meta → second GET plain | VERIFIED (re-run 2026-11-04) |
| Truth | R5 — one-shot handoff; GET never consumes | unit: plain-GET/stale/expired relay tests all pass; relay self-delete asserted in unit + e2e (popup relay read back null after hydration). Server side: 9 tests in `tests/api/test_object_handoff.py` pin the one-shot stash (set-on-POST, pop-on-GET, no double-inject, bogus-token never stashed, anonymous never stashed) | VERIFIED (unit + e2e at re-run) |
| Truth | R6 — one route per kind; back/forward moves list↔detail | route-table audit (no `/data` primary entries; 15 redirect entries) + kind-mismatch unit + e2e browser-back probe passed (list re-renders after `page.goBack()`) | VERIFIED |
| Truth | R7 — one-shot redirect, origin `link`, final URL clean | `App.test.tsx` redirect suite (registry entry asserted with `origin: 'link'`) + e2e `old URL redirect` passed at tip | VERIFIED |
| Truth | R8 — ref namespace authoritative | `secrets.test.tsx::secret-data-reads-the-ref-namespace-not-the-header` captures the real request's `namespace=team-a` with the header on `default` | VERIFIED |
| Truth | R9 — filters stay, `?selected=` goes | bolding-from-ref test; `grep` of real `useSearchParams` calls in migrated views = 0 (only comment mentions; live calls remain in AdminPermissions/Groups — genuine `?tab=`-style filters, out of this change's scope) | VERIFIED |
| Truth | R10 — no new endpoint/migration/dependency (as amended) | `git diff 98613f68..tip -- backend/` = exactly 3 files, all handoff plumbing (`app/core/object_handoff.py`, `app/__init__.py` catch-all, `tests/api/test_object_handoff.py`); no API endpoint, no migration, no log, no dependency; `cli/` + `charts/`: 0 files | VERIFIED |
| Artifact | `lib/objectRef.ts`, `components/{ObjectRoute,OldDataRedirect,ShareObjectButton}.tsx` exist, substantive, wired | all four read in full; `App.tsx` has 31 `ObjectRoute` references + 17 `OldDataRedirect` entries; 22 lib tests + 8 component tests run them | VERIFIED |
| Key Link | list row → `openObject` → ref → `ObjectRoute` detail render | `secrets.test.tsx::click-name-renders-detail-with-clean-url` + `App.test.tsx::list → click row → detail` end-to-end through the exact route wiring | VERIFIED |
| Data Flow | real data moves: detail fetches the ref's object | MSW-captured requests assert `name`/`namespace` of the ref in 26 view files; e2e redirect leg renders the secret's labels; cross-tab leg proven at re-run (new tab renders the CRD detail of the relayed ref) | VERIFIED |

**Note:** the R4 unit tests are green because they seed `?o=<token>` into
jsdom's URL directly (`renderAt(…, \`?o=${token}\`)`) — the browser never does
that for a form POST. The unit layer proves the relay contract; it cannot
prove the token reaches the new document. That is the gap.

## Traceability Matrix

Scenario names from `acceptance.feature` (16 scenarios, deterministic count).

| Scenario (from acceptance.feature) | Test / Scenario (from test plan) | Ran | Result |
|--------------------------------------|----------------------------------|-----|--------|
| opening an object from a list leaves the URL clean | `priority_classes.test.tsx::click-name-renders-detail-with-clean-url` + 26 view files + e2e deep-link URL assert | yes | pass |
| the data page never carries identity params | all 21 migrated data-view tests assert `location.search === ''` | yes | pass |
| the open object ref lives in sessionStorage only | `objectRef.test.ts::round-trips…` + `::no localStorage identity outside the kd_ref_ relay keys` + R10 diff | yes | pass |
| refreshing the tab keeps the open object | `object_route.test.tsx::renders the detail when the active ref kind matches` (render from persisted sessionStorage) + e2e deep-link new-document render | yes | pass |
| an expired ref renders the list | `objectRef.test.ts::backdated > 15 min…` + `object_route.test.tsx::stale relay renders the list` | yes | pass |
| **the share action opens the object in a new tab with a clean URL** | `ui-smoke.spec.ts::deep link…` | yes | **pass** (re-run 2026-11-04: popup URL clean, detail rendered, relay self-deleted — C1 FIXED) |
| the POST body and the relay carry no readable identity in the URL | `objectRef.test.ts::hidden form: POST to the list route, target _blank, single hidden input "o" = token` (+ negative asserts) + e2e popup URL asserts | yes | pass |
| a stale relay key is not consumed by a plain GET | `objectRef.test.ts::no ?o= param (plain GET) → null…` + `object_route.test.tsx::stale (expired) relay renders the list` | yes | pass |
| the relay self-deletes after consumption | `objectRef.test.ts::hydrates the relay into the registry + active pointer and self-deletes both keys` | yes | pass |
| one route per kind; detail renders only for a matching ref | `object_route.test.tsx::kind mismatches (R6)` + route-table audit (no `/data` primary) | yes | pass |
| back from the detail returns to the list | QA e2e probe (throwaway): detail → `page.goBack()` → list rendered; unit: `object_route.test.tsx::back to list clears the active ref` (breadcrumb) | yes | pass |
| an old data URL redirects to the clean route with the ref hydrated | `App.test.tsx::old URL with ?name=/?namespace= lands on the clean route, ref origin link` + e2e `old URL redirect…` | yes | pass |
| the ref's namespace wins over the header selector | `secrets.test.tsx::secret-data-reads-the-ref-namespace-not-the-header` | yes | pass |
| the selected bolding hint is replaced by the active ref | `secrets.test.tsx::bolds-the-opened-secret-from-the-active-ref` | yes | pass |
| a genuine filter param may remain a query param | none — permissive (MAY) scenario; the pods list it names is not implemented (in-flight `2026-10-28-pods-deployments-views`) | no | UNTESTED (permissive) |
| no new endpoint serves the object selection | `git diff … -- backend/` = 3 handoff-plumbing files, no API endpoint (R10 as amended); `cli/ charts/` = 0 files | yes (diff) | pass |

**Coverage:** 15/16 scenarios covered by a test that ran and passed (the R4
deep link passed at the 2026-11-04 re-run); 1 UNTESTED-permissive (R9
filter, forward spec).

## Verification-Gap Audit

| Gap | Location | Shape | Evidence | Smallest Regression |
|-----|----------|-------|----------|---------------------|
| The form POST never delivers the token to the new document's URL, so `consumeIncoming` cannot hydrate | `src/lib/objectRef.ts` (`consumeIncoming` reads only `location.search`) + `POST /cluster/crd` → 405 on the Flask dev server (curl-verified); nginx `try_files` would serve the index without `?o=` | broken-verification (unit) + missing mechanism (e2e) | e2e deep-link: popup URL clean but no detail render; `consumeIncoming` returns null on `location.search === ''` by construction | Remove the hypothetical server `?o=` bridge and nothing in the suite fails — the cross-tab handoff silently degrades to "new tab shows the list" (or a 405 page in dev) |
| `ui-smoke.spec.ts` (carries this change's R4/R7 e2e scenarios) is wired to no runner | `Taskfile.yaml` `e2e:` runs only `auth-smoke.spec.ts`; `.github/workflows/e2e.yaml` runs only `smoke.spec.ts` | missing-adoption | `grep -rn 'ui-smoke' Taskfile.yaml .github/workflows/` → 0 matches | The R4/R7 e2e scenarios regress (or break, as this run's stale-loginAs proved) with no CI signal |
| e2e login helper was stale against ADR-0025 before this run | `frontend/e2e/helpers.ts:93` asserted a `?token=` parked URL; the 302 carries HttpOnly cookies + bare `/` since ADR-0025 | broken-verification (latent) | first e2e run: 1 passed, every `loginAs` test failed with "auth/local 302 without a token param" | any future `loginAs`-based spec fails on boot; fixed this run (`helpers.ts:91-96`), `loginToken` (api-smoke) still stale |
| Deep-link e2e hardcodes a CRD fixture no script creates + omitted the selected-cluster precondition | `ui-smoke.spec.ts::deep link` expects `configmaps.example.com`; `dev/scripts/demo-data.sh` creates only ns+deployments; no cluster auto-select exists (store is `kd-cluster-scope` persisted, empty in a fresh context) | missing-adoption (test setup) | this run: CRD created manually + precondition patch required before the popup leg could be evaluated | the scenario is environment-fragile: green on one machine, red elsewhere, for setup reasons, not behavior |

**Re-verification (2026-11-04):** all four gaps closed — (1) the token now
reaches the new document via the server-session one-shot meta (C1 fix,
e2e-proven); (2) `ui-smoke` is wired into `task e2e` (19/19 green) — the CI
leg is tracked as W-5; (3) `loginAs` asserts the ADR-0025 cookie (previous
gate); (4) the CRD fixture is created by `dev/scripts/demo-data.sh` (§4) and
the selected-cluster precondition is seeded registry-driven in the test.

## TDD Evidence Audit

No execution ledger exists for this change (`.skillgrid/sdd/2026-10-29-session-object-navigation/` absent); each ticket is a single conventional commit with tests and implementation co-committed — the same shape the shipped `2026-10-28` batch used ("24/24 task units OK"). RED exit codes are not persisted; GREEN was re-verified by this run's full suite at tip.

| Task | SATISFIES | RED (commit + exit) | GREEN (commit + exit) | TRIANGULATE | REFACTOR (suite) | Verdict |
|---|---|---|---|---|---|---|
| TASK-055 | R2/R3/R5 (lib scenarios) | `0b4fdb97` (co-commit; RED-first per ticket plan, exit not persisted) | `0b4fdb97` exit 0 (re-run: 22/22 lib tests pass) | 22 tests, distinct inputs | exit 0 | OK |
| TASK-056 | R1/R4/R6 (template kind) | `ea3dd004` (co-commit) | `ea3dd004` exit 0 (re-run green) | object_route ×8 + priorityclass views | exit 0 | OK |
| TASK-057 | R1/R8/R9 (security) | `71c977ca` (co-commit) | `71c977ca` exit 0 (re-run green) | secrets + network-policy views | exit 0 | OK |
| TASK-058 | R1/R6 (cluster-permission) | `8f710f6a` (co-commit) | `8f710f6a` exit 0 (re-run green) | 5 view test files | exit 0 | OK |
| TASK-059 | R1/R6/R8 (cluster) | `b30f98dc` (co-commit) | `b30f98dc` exit 0 (re-run green) | 4 view test files incl. CrdData two-call contract | exit 0 | OK |
| TASK-060 | R1/R6/R8 (other-resource) | `89528a32` (co-commit) | `89528a32` exit 0 (re-run green) | 12 view test files | exit 0 | OK |
| TASK-061 | R6/R7 (route merge) | `23ac0607` (co-commit) | `23ac0607` exit 0 (re-run green) | App.test.tsx ×4 redirect scenarios | exit 0 | OK |
| TASK-062 | R4/R7 (e2e + docs) | `7234bda3` (co-commit) | `7234bda3` exit 0 (e2e ran at this gate — see C1) | deep-link + redirect scenarios | exit 0 | OK (e2e leg now FAILING — C1 is an implementation gap, not a discipline gap) |

**Summary:** 8/8 tasks have complete TDD evidence per the repo's co-commit
precedent. No MISSING_RED recorded as a discipline finding (co-commit shape
matches the shipped batch); no STALE. One SUGGESTION: persist an execution
ledger with RED exit codes (S-2).

## Assertion Quality Audit

All new test modules read in full (`objectRef.test.ts` 22 tests,
`object_route.test.tsx` 8, `App.test.tsx` 4, `secrets.test.tsx` key tests);
the 24 repointed view test files were sampled in full (priorityclass, crds,
service-accounts) + grep-verified for the `location.search === ''` assertion
(26 files).

| File | Line | Pattern | Evidence | Severity |
|---|---|---|---|---|
| `tests/components/object_route.test.tsx` | seam test | type-only assertion without value | `expect(navigate).toBeTypeOf('function')` + `expect(typeof navigate).toBe('function')` — no behavioral call-through of the seam | SUGGESTION |
| — | — | no tautologies, ghost loops, source-text or snapshot-only assertions, or pass-always tests found in the audited set; positive+negative pairs present (bolding, kind-mismatch, stale/fresh relay, HSTS-analogous clean/dirty URL) | — | — |

**Summary:** 0 CRITICAL, 0 WARNING, 1 SUGGESTION.

## Changed-File Coverage

**Coverage:** n/a — no coverage tool detected (`testing.coverage` not
configured; quality: not configured — using defaults).

## Test Quality Audit

| Test | Contract Violated | Evidence |
|------|-------------------|----------|
| `ui-smoke.spec.ts::deep link…` | test-claimed-path (latent, exposed by C1) | the committed test asserts the popup renders the object — the path it claims only holds if the server delivers `?o=`; the test is correct, the mechanism is missing. The unit tests, by contrast, seed `?o=` manually and cannot catch this |
| — | — | all other audited tests: real code (MSW-captured requests, real component mounts), no vacuous truths, no pass-always, complete mocks (MSW returns the shapes the views render), counter-tests present (negative bolding, mismatched kind, stale relay) |

## Test Strategy Audit

**Available layers:** unit, integration (kind-gated), e2e (Playwright).

| Behavior | Assigned Layer | Degrade? | Duplicate Coverage? | Rationale |
|----------|---------------|----------|---------------------|-----------|
| Registry/relay/expiry/token | unit | no | no | pure storage logic; router-free by design |
| Route dispatch, redirect | unit | no | no | in-process React + react-router |
| Cross-tab POST handoff | e2e | no | no | document boundary — only a real browser proves it (and it caught C1) |
| Route merge end-to-end | e2e (smoke) | no | no | URL-level redirect semantics |

**Layer distribution:** ~40 unit, 0 integration, 17 e2e (ui-smoke). The
distribution is right for this change — the one behavior that crosses a
document boundary sits at the only layer that can observe it, and it failed
there.

## Security Audit

**Mode:** Manual fallback (no `security.trivy.command` configured).

#### Secrets Archaeology

| Location | Type | Evidence | Severity |
|----------|------|----------|----------|
| — | — | no credential literals in the 36 changed view files or the 4 new modules; e2e `admin/admin` is the pre-existing dev bootstrap (Taskfile var) | none |

#### Dependency Audit

| Dependency | CVE / Issue | Severity | Fix Available |
|------------|-------------|----------|---------------|
| — | `package.json`/`pnpm-lock.yaml` diff in range: 0 lines (no new dependency, ADR-0020) | — | — |

#### OWASP Spot-Check

| File | OWASP Item | Pattern | Evidence |
|------|------------|----------|----------|
| `objectRef.ts` | A02 crypto / A01 injection | 32-bit relay token (`^[0-9a-f]{8}$`, test-asserted) | guessable within the 60 s relay window; a miss renders the list (token-keyed registry), a hit renders the object whose fetch still goes through API RBAC — low risk, S-1 |
| `objectRef.ts` | A03 session | identity JSON in `localStorage` for ≤60 s (relay) — same-tab JS can read it | stated ADR-0040 accepted cost (cross-tab handoff must be origin-shared); registry itself is `sessionStorage`-only (R2 verified) |
| migrated views | A03 XSS | names rendered through React text nodes / `KubeDataTable` (auto-escaping); no `innerHTML` added by this change | — |

**Security verdict:** PASS — CRITICAL: 0, WARNING: 0, SUGGESTION: 1 (S-1).

## Code Quality Gate

| Gate | Command | Threshold (config) | Actual | Result |
|------|---------|--------------------|--------|--------|
| Coverage (whole project) | not configured | 80 (default) | n/a | N/A |
| Changed-file coverage | not configured | 80 (default) | n/a | N/A |
| Mutation | not configured | 80 (default) | N/A | N/A |
| Lint (frontend) | `tsc --noEmit` + `eslint src` + `vite build` | errors only | 0 errors, built 11.5 s | PASS |
| Lint (backend) | `ruff check .` | errors only | 102 errors — **pre-existing** (this change's files clean after fixing 1 E501 in `test_object_handoff.py`; debt is test files + groups/ini/wsgi, in-flight work) | PASS for this change (branch debt → W-3) |
| Typecheck (backend) | `mypy app` | errors only | 78 errors / 16 files — this change's `object_handoff.py` clean after fixing 2 (untyped re-export import, werkzeug/flask Response) | PASS for this change (branch debt → W-3) |
| P0 pass rate | test-plan P0 rows | 100 | 6/6 (R4 deep link passed at re-run) | PASS |
| P1 pass rate | test-plan P1 rows | 95 | 100% | PASS |
| Trivy | not configured | report only | N/A | N/A |
| Duplication (jscpd) | not configured | report only | N/A | N/A |

**Quality config status:** not configured — using defaults.

### Fresh verification floor (re-run, at working tip, 2026-11-04)

| Check | Result |
|---|---|
| `uv run pytest -m "not integration" -q` | **550 passed, 10 deselected, 0 failed** (133 s; +10 vs the 2026-11-03 run = in-flight users/groups work landed on the branch since) |
| `corepack pnpm test` (full) | **295 passed / 12 failed (307)** — the 12 are exactly the W007 baseline files (`users` 7, `groups` 4, `admin_permissions` 1); nothing new |
| `tsc --noEmit` + `eslint src` + `vite build` | green (build 11.3 s; first pass caught 3 real tsc errors in this change's files — meta typing/narrowing + a missing `ORIGIN` export — all fixed, re-run green) |
| `task fe-check` (air-gap, ADR-0020) | exit 0 |
| `task e2e` (auth-smoke 3 + ui-smoke 16, wired 2026-11-04) | **19 passed / 0 failed** (31 s) — includes the R4 deep link; the auth-smoke Secure-cookie assertion was stale against ADR-0027 (TLS-era) and is now transport-conditional (fixed this re-run) |
| curl handoff trace (live stack, real session cookie) | login 302 → `POST /cluster/crd` 303 → GET injects `<meta name="kd-object-incoming">` → second GET plain (one-shot consumed) |
| `git diff 98613f68..tip -- backend/ cli/ charts/` | 3 backend files, all handoff plumbing (R10 as amended); cli/charts 0 |
| `git diff … -- frontend/package.json pnpm-lock.yaml uv.lock` | 0 lines (ADR-0020) |
| `grep -rn 'data?name=' frontend/src` | 0 matches |
| real `useSearchParams` identity reads in migrated views | 0 (live calls only in AdminPermissions/Groups — out of scope) |

## Duplication

**Command:** N/A — `duplication.command` not configured.

## State Drift

**Verdict:** DRIFT DETECTED — `state.yaml` `pipeline.current_phase` was `sliced`
and the `in_flight` entry for this change said `phase: sliced` with
"Chain strategy: pending" although all 8 tickets are executed (commits
`0b4fdb97`…`80f3bd0f`) and the backlog tasks are `✔ Done`.

| Field | Stale (state.yaml) | Derived (spec zone / git) |
|-------|-------------------|---------------------------|
| `pipeline.current_phase` | `sliced` | `qa` (execution complete; this gate) |
| `in_flight[0].phase` | `sliced` | `qa` |

**Fix applied:** state.yaml updated to `qa` in this commit. Scope: COMPLETE
(full state.yaml + spec folder + git range read).

## Verification Scope

| Derivation | Scope | Stale? |
|---|---|---|
| Traceability matrix | COMPLETE (all 16 scenarios of `acceptance.feature` read in full) | none |
| Verification-gap audit | COMPLETE (all 176 changed files enumerated from the range diff; 4 seam modules + 4 core test modules read in full; view files sampled + grep-verified) | none |
| State Drift (9.5) | COMPLETE (manual — see below) | n/a |
| Structure Drift (9.5) | UNSCOPED (qa-gate.mjs `ship_drift`: "skipped: no base ref in tasks.md" — the active-slug heuristic picked `2026-11-03-agents-md-rewrite`, which has no tasks.md) | n/a |

**qa-gate.mjs run:** 10 of 11 sub-checks `UNSCOPED` ("script not found" — the
repo-level check scripts (`traceability.mjs`, `tdd-evidence.mjs`,
`status-banner.mjs`, …) are not installed in this tree; the drift sub-scripts
resolve against a missing project-local path). `ship_drift` ran and skipped
(no base ref for the picked active slug). The audits above are therefore
manual, over the explicitly named change range `98613f68..80f3bd0f` — the
composite scope for this report's derivations is COMPLETE; the qa-gate script
itself is an UNSCOPED non-answer, noted per fail-closed rule (it would not
have changed any verdict: every finding it could have produced — drift,
banner, delivery guard — was checked manually and is reported above).

**Stale-verification:** `STALE: none` — first QA gate for this change; all
evidence in this run was generated at tip `80f3bd0f` (working tree = HEAD
`b30fd2b1`; the intervening commits are the shipped TLS change + docs, which
touch no file this change owns — re-verified by the in-range diffs above).

## Floor

| Dimension | Verdict |
|---|---|
| Goal-backward verification (weakest truth) | PASS (all truths VERIFIED; R4 proven e2e at re-run) |
| Traceability (weakest scenario) | PASS (15/16 pass; 1 UNTESTED-permissive) |
| Verification-gap audit | PASS (C1 mechanism + runner + fixture gaps all closed; residuals are tracked W/S) |
| TDD evidence (weakest ticket) | OK (8/8) |
| Assertion quality audit (weakest finding) | SUGGESTION |
| Changed-file coverage (weakest file) | N/A |
| Test quality audit | PASS (the deep-link test's claimed path now holds — e2e green) |
| Code-quality gates (weakest gate) | PASS (P0 6/6; branch lint/type debt pre-existing, 0 in this change's files → W-3) |
| Security audit | PASS (S-1 closed by the fix — 64-bit token) |
| Verification scope (composite) | COMPLETE |

**FLOOR:** every dimension PASS/COMPLETE at the 2026-11-04 re-run. The gate
renders **PASS**.

## Findings

### CRITICAL (must fix before merge)

- **C1 — R4 cross-tab deep link does not hydrate the new tab.** — **FIXED
  2026-11-04.** Originally: `consumeIncoming()` resolved the token only from
  `?o=` in `window.location.search`; a form POST's body never enters the new
  document's URL and `POST /cluster/crd` was **405** (curl-verified). Fixed
  per the ADR-0040 amendment (user decision, 2026-11-04) — a refinement of
  original path (a) that keeps R1's "token never in a URL": the SPA fallback
  (`app/core/object_handoff.py`, wired in `app/__init__.py`) accepts the
  share POST, validates the token (`^[0-9a-f]{8,16}$`), stashes it in Redis
  under `obj_incoming:<sub>` (60 s, the client relay window), 303s to the
  same clean path, and injects a one-shot
  `<meta name="kd-object-incoming">` into the next same-session GET;
  `consumeIncoming()` reads the meta and resolves the localStorage relay.
  Every miss path renders the list, never a wrong object (anonymous, bogus
  token, expired relay, second GET). Verified: 9 backend tests
  (`tests/api/test_object_handoff.py`); live curl trace (302 login → 303
  bounce → meta-injected GET → plain second GET); e2e deep link green in a
  real browser (new tab: clean URL, rendered detail, relay self-deleted).
  Test-side contract fixes found while re-running: the scenario's synthetic
  token was not hex (server rejects non-`[0-9a-f]` — now
  `a1b2c3d4e5f6a001`), and the detail title expectation used the resource
  name where `CrdData` titles by `spec.names.kind` ("CRD Data — ConfigMap").

### WARNING (should fix before archive)

- **W-1 — `ui-smoke.spec.ts` has no runner.** — **CLOSED 2026-11-04 (dev
  loop).** `task e2e` now runs `auth-smoke.spec.ts e2e/ui-smoke.spec.ts`
  (19/19 green). The CI leg (`.github/workflows/e2e.yaml` runs `smoke.spec.ts`
  only, mock-OIDC install with no bootstrap local admin and no CRD fixture)
  is tracked as **W-5**.
- **W-2 — e2e login helper was stale against ADR-0025.** `helpers.ts
  loginAs` asserted a `?token=` parked URL; the 302 now carries HttpOnly
  cookies + bare `/`. Fixed this run (`helpers.ts:91-96` — asserts the
  `kd_access` cookie, which authenticates the shared context). `loginToken`
  (api-smoke) is still stale — same one-line class of fix.
- **W-3 — pre-existing backend lint debt.** `ruff check .` → 102 errors,
  `mypy app` → 78 errors / 16 files; **0 in this change's files** (its 3
  backend files are clean after this re-run's fixes; debt provenance:
  in-flight users/groups/ini-config work — same ownership as W007). The
  branch would fail the CI lint floor; not owned by this change.
- **W-4 — deep-link e2e setup gaps.** — **CLOSED 2026-11-04.** The scenario
  hardcoded the `configmaps.example.com` CRD and omitted the
  acceptance-Background precondition "a bound cluster is selected in the
  header". Both closed: `dev/scripts/demo-data.sh` §4 now applies the CRD
  fixture (idempotent), and `ui-smoke.spec.ts` seeds the registry-driven
  `kd-cluster-scope` precondition.
- **W-5 — CI e2e leg for `ui-smoke` (opened 2026-11-04).**
  `.github/workflows/e2e.yaml` (push-to-main) runs `smoke.spec.ts` only
  against a mock-OIDC install with no bootstrap local admin and no CRD
  fixture. Wiring `ui-smoke` there needs: `--set` bootstrap-admin values in
  the helm install, the CRD fixture applied post-install (kubectl), and the
  playwright command extended — a CI-environment change only verifiable by
  running the job. Non-blocking: the dev loop (`task e2e`) is green and
  regression-safe for the C1 fix.

### SUGGESTION (nice to have)

- **S-1** — 32-bit relay token. — **CLOSED 2026-11-04:** the client now
  generates 64-bit hex tokens (`crypto.getRandomValues(8)` —
  `objectRef.ts:56-60`), the server accepts `^[0-9a-f]{8,16}$` (32-bit
  legacy + 64-bit current), and ADR-0040 was amended to record it.
- **S-2** — no execution ledger for this change (`.skillgrid/sdd/…`): RED
  exit codes unpersisted; TDD evidence rests on the co-commit shape + plan +
  green re-run (matches the shipped-batch precedent).
- **S-3** — `object_route.test.tsx` seam test asserts `typeof` twice with no
  behavioral call-through.
- **S-4** — `OldDataRedirect` mutates the registry during render (StrictMode
  double-render writes two tokens; harmless, but a `useState` initializer
  would be the idiomatic seam).
- **S-5** — dev-env: the `kubedash-test` metrics-server crash-loops
  (apiservice `MissingEndpoints` since before this session), which blocks
  `task dev-stack` at its `kind-up` gate; this gate started the backend via
  `backend-run` directly after recreating the pod.
- **S-6** — the R9 permissive filter scenario (pods `?labelSelector=`) is
  untestable until `2026-10-28-pods-deployments-views` lands — its executor
  should carry the scenario.

## Gate Decision

**Verdict:** PASS (re-verified 2026-11-04, after the C1 fix)

**Reasoning:** all 10 briefing truths are VERIFIED — R4, the headline
capability the 2026-11-03 gate failed, is now proven at the only layer that
can prove it: a real browser's new tab receives a clean-URL document with a
one-shot server-injected meta, hydrates the relay, and renders the object
(e2e green; live curl trace of the 302→303→inject→plain sequence). 15/16
scenarios pass (1 UNTESTED-permissive, forward spec). Floors at re-run:
backend 550/550, frontend green modulo the carried W007 baseline,
`task e2e` 19/19 (now the wired runner for both smoke suites), air-gap
check exit 0, R10-as-amended diff holds (3 handoff-plumbing files, no
endpoint/migration/dependency). This change's own lint/type surface is
clean (its earlier 1 ruff + 2 mypy findings fixed in the re-run).

**Open items (advisory, non-blocking):**
- W-3 — branch-level ruff/mypy debt (102/78), pre-existing, 0 in this
  change's files; owned by the in-flight users/groups work.
- W-5 — CI e2e leg for `ui-smoke` (bootstrap-admin values + CRD fixture +
  command extension in `.github/workflows/e2e.yaml`); fix before archive if
  the CI e2e job is to cover the deep link.
- W-2 (residual) — `loginToken` (api-smoke) still asserts the retired
  `?token=` shape; api-smoke is wired to no runner.
- S-2…S-6 — ledger persistence, seam-test call-through, render-time registry
  mutation, dev metrics-server crash-loop, R9 permissive scenario (forward
  spec).

## Human Override

> A human decision always overrides this machine verdict.
> An epic that fails its criteria with no human decision is recorded as
> **not accepted** — never as silently accepted.

**Human decision (fill in):** <accept / accept-with-open-items / reject> —
<name> — <date>

<!-- reflect completes this half at archive time -->

## Final-State Facts

**Shipped:** <what actually shipped>
**Base branch:** <base-branch> · **Chain strategy:** <strategy>
**Integration:** <merged @ <commit> | PR <url> | kept branch <name>> (from ship context)

## Gates

| Gate | Result |
|------|--------|
| Ship gate | <pending> |
| QA gate | ❌ FAIL (2026-11-03) |
| Verdict gate (advisory) | <pending> |

## Decisions

| Decision | Tradeoff | Why | Source |
|----------|----------|-----|--------|
| <pending reflect> | | | |

## Lessons

| Lesson | Root Cause | Do Differently | Source |
|--------|-----------|----------------|--------|
| <pending reflect> | | | |

## Patterns

| Pattern | Reuse | Source |
|---------|-------|--------|
| <pending reflect> | | |

## Surprises

| Surprise | Signal | Source |
|----------|--------|--------|
| <pending reflect> | | |

## Environment Retro

| Category | Finding | Fix lands in | Source |
|----------|---------|--------------|--------|
| <pending reflect> | | | |

## Acceptance Verdict

**Verdict:** <pending reflect>

**Grounding:** <pending reflect>

**Reasoning:** <pending reflect>

## Open Items (→ next change)

- <pending reflect>

## Web-cache promotion candidates

<!-- pending reflect -->

## Prior-Change Follow-Through

| Prior open item (from previous archived change) | Addressed by this change? | Evidence |
|--------------------------------------------------|---------------------------|----------|
| W008 — e2e REAL_ROUTES covers only the limit-range path (other-resource batch) | partially | the `/data` route entries dropped from the sweep per ADR-0040; the 10 real paths still not listed — still open |
| W009 — stale `/other-resource/priorityclass` `STUB_TITLES` entry | no | still present in `ui-smoke.spec.ts` (now a real view since 2026-10-27) — still open |

## Move Evidence (from ship context)

**From:** `.skillgrid/specs/2026-10-29-session-object-navigation/` → **To:** `.skillgrid/xarchive/2026-10-29-session-object-navigation/`
**`diff -r` readback:** <pending ship>

## Overrides / Waivers / Contradictions

- None recorded at QA. (The QA run's own test-infra fixes — `helpers.ts`
  loginAs ADR-0025 patch, deep-link cluster precondition — are committed with
  this report; they do not alter change behavior.)

## Lineage (observation IDs)

- briefing: `.skillgrid/specs/2026-10-29-session-object-navigation/briefing.md`
- blueprint: `…/blueprint.md`
- tasks: `…/tasks.md`
- adr: `.skillgrid/knowledge/decisions/04-adr-0040-session-object-navigation.md`
- ship: none yet
- report (QA half): this file
- research / findings / ADRs: ADR-0040; ADR-0025 (session cookies); ADR-0020 (air-gap)
