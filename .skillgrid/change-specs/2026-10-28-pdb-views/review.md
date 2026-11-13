# Review — PodDisruptionBudget Views (List + Data)

**Change:** `2026-10-28-pdb-views` · **Date:** 2026-11-13
**Diff:** 4 commits `5f1f9244` (backend kind) / `7a1ab3a5` (list view) / `305a44c6` (data view) / `7b3e35be` (routes + stub removal) — 12 files, +1167/−1. Pre-generated: `.skillgrid/meta/sdd/2026-10-28-pdb-views/review-diff`.
**Method:** 7-lens blind fan-out (standards / spec / security / edge / verification-gap / accessibility / performance) + red team over the merged findings. Grade-B blindness: no producer narrative, no prior verdicts. All lens claims re-grounded at the current tree by the red team.
**QA gate:** PASS (batch of 6, `2026-10-28-other-resource-views/qa-report.md`, 2026-10-29).
**Post-hoc context (separate changes, current tree cited):** ObjectRoute migration `89528a32` (ADR-0040) rewrote the data view from URL-driven to ref-driven; legacy `/data` URL = OldDataRedirect R7 (`NAVIGATION-SUPERSEDED.md` records this).
**Tree note:** gate ran at tip `0daaa63e` + uncommitted concurrent WIP (ha-status fix loop 16 files + KubeDataTable.tsx `onRowClick` + e2e/useCluster/Clusters WIP) — a parallel session, named wherever it intersects evidence, never filed as a change finding.

## Verdict

**PASS with fixes** — 8 findings triaged: 6 fixed in this commit, 2 parked (fleet convention), 1 dropped (false positive). 0 CRITICAL. Pattern fidelity to the sibling fleet (secrets / resourcequotas / networkpolicies) is byte-for-byte; both deviations from the spec are the expected ADR-0040 navigation-replacement class with behavior held.

## Spec axis

15/15 scenarios resolved: **13 PASS, 2 DEVIATION (expected class), 0 MISSING**. Both deviations: name cell is an openObject button (not `/data?name=` link) and `/data` route is OldDataRedirect — authorized by ADR-0040 + `NAVIGATION-SUPERSEDED.md`, behavior (row opens its budget's data view) verified held. All 7 ratified 4.1 deviations verified in code. The briefing R4 "computed floor" wording for the Desired row was resolved by the blueprint (Task 3 Step 3: `status.desired ?? '—'`, no client-side floor math) — `status.desired` is the controller-computed effective minimum, rendered verbatim.

## Findings (red-team-verified)

| # | Sev | Finding | Lens(es) | Disposition |
|---|-----|---------|----------|-------------|
| F1 | important | e2e `SMOKE_STUB_ROUTES` entry pinned the stub-era title `Pod Disruption Budget` = sidebar nav label, so the `exact: true` sweep proved nothing about the real view; the view docstring's claim was false | spec + verif-gap + standards + edge (4) | **FIXED** — retargeted to `Pod Disruption Budget List` + rq-style rationale comment (fleet yardstick `2f75a5f9`); docstring now holds |
| F2 | important | SAR-denied test did not pin "K8s client list call never made" (ADR-0004) — a SAR-after-read regression stays green, surfacing as 502 instead of 403 on an unreachable cluster | verif-gap + standards + edge (3) | **FIXED** — lazy `pdb_ns_calls` log in `FakeK8s.list_pod_disruption_budgets` + absence assert in `test_list_poddisruptionbudgets_sar_denied` (rq pattern) |
| F3 | minor | getter hit test's value-ignoring stub — a `(namespace, name)` transpose would 404 on every real cluster with all tests green | verif-gap + standards (2) | **FIXED** — value-recording stub + `assert seen == [("web", "team-a")]` |
| F4 | minor | R9 active-ref bold unpinned (no test seeds the ref + asserts `fw-bold`/`aria-current`) | verif-gap (1) | **FIXED** — `bolds-the-opened-pdb-from-the-active-ref` (sibling seed pattern) |
| F5 | minor | `?? 'default'` namespace fallback unpinned (no fetch-URL test with `selectedNamespace: null`) | verif-gap (1) | **FIXED** — `defaults-to-default-namespace-when-none-selected` |
| M2 | doc | stale comment in this change's test file: "The Name cell also carries the ADR-0040 share button" — no share button exists (`postObjectToTab` has zero callers) | red team (missed) | **FIXED** — comment corrected (fleet siblings carry the same stale comment — fold into a fleet-wide cleanup) |
| F6 | — | no `@pytest.mark.integration` kind-tier test + no demo PDB seed | verif-gap (1) | **PARKED** — kind tier is a carried broken baseline (QA report: ScopeMismatch / testcontainers teardown); no fleet kind has one (F5-class) |
| F7 | — | namespace-less ref (unvalidated sessionStorage) → query disabled → data branch renders all-N/A + empty JSON, no fetch/loading/error | edge (1) | **PARKED** — guard chain line-for-line identical to `ResourceQuotaData`; all legit ref writers (`openObject` row-namespace, `OldDataRedirect` `'default'` fallback) set namespace; repo-wide convention |
| F8 | — | edge claim "eviction policy is `[]string`; `[]` renders blank" | edge (1) | **DROPPED** — vendored client types it `Optional[StrictStr]` (a string, k8s ≥ 1.29); string-vs-list *wording* residue already parked by the batch review |
| M1 | minor | `expect(window.location.search).toBe('')` in the click test is a tautology (jsdom `window.location` is not mutated by MemoryRouter) | red team (missed) | **PARKED** — identical pattern shipped fleet-wide (`resource_quotas.test.tsx:146`, reviewed); the real pin is the detail-render assertion + e2e contract |

Clean lenses: **security** (10 candidates, nothing exploitable — SAR `policy` group, query-param validation, R7 redirect, air-gap all verified) and **performance** (1 SAR + 1 client call per request, no per-row reads, view never hits the all-ns branch). A11y: 4 lowest-severity repo-wide CoreUI conventions (plain-div states, h5 headings, nameless tables) + the genuinely-new Conditions table — same parking class as the siblings; the name cell button (`openObject`, `aria-current`) verified correct.

## Verification ledger

| Command | Result |
|---|---|
| `uv run pytest -q tests/services/test_k8s_client_poddisruptionbudgets.py tests/api/test_resources.py -k poddisruptionbudget` (pre-fix baseline) | 12/12 PASS |
| `corepack pnpm vitest run tests/views/pod_disruption_budgets.test.tsx tests/views/pod_disruption_budget_data.test.tsx tests/views/Stub.test.tsx` (pre-fix; data file via KubeDataTable WIP stash round-trip) | 17/17 PASS |
| same two commands (post-fix, incl. 2 new frontend tests + 3 new backend pins + comment fix) | backend 12/12 PASS · frontend 9/9 PASS (list file) |
| e2e `ui-smoke.spec.ts` retarget (F1) | not re-run — requires the dev stack; the sibling commit `2f75a5f9` shipped the identical retarget; the new title matches only the view's breadcrumb/card title, never the nav label |
| `tsc --noEmit` (full) | blocked by concurrent WIP (`KubeDataTable.tsx:44` JSX syntax error, parallel session); the edited test file ran green under vitest/esbuild |

## Commit

The F1–F5 fix hunks landed in the parallel session's `40df5929` (ha-status review fix loop, committed 2026-11-13 19:13 while this review's fix loop was in flight — shared working tree, its `git add` swept the pdb test/e2e edits in with it; verified present in HEAD). This review's own commit carries the M2 comment fix, this record, and the state pointer. The concurrent WIP that predates `40df5929` is fully committed there; nothing pdb-related remains uncommitted besides this commit.
