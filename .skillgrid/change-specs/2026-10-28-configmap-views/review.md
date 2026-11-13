# Review — ConfigMap Views (2026-10-28-configmap-views)

> Change: `.skillgrid/change-specs/2026-10-28-configmap-views/` (TASK-064)
> Generated: 2026-11-13 (parallel-code-review: 7 specialist lenses + red team)
> Diff: `41620987..c966685e` (branch `rebase`) — the change's 4 code commits
> (41620987 backend kind, 373e7042 list view, b08f22b0 data view, c966685e
> routes + stub removal). Post-hoc comment-only fix d6bf3c4f (the QA gate's
> own fix, in the change's scope) included as context.
> QA gate: PASS (report.md, 2026-11-12, re-verified at HEAD 2026-11-12).
> Rigor tier: T1 (blueprint header) — the review ran the full 7-lens +
> red-team topology anyway (fan-out cost was not tier-bound).
> Independence: Grade B per lens (fresh subagent contexts, no shared
> session history — same toolchain/model family as the implementer).

## Lens results

| Lens | Findings | Verdict |
|------|----------|---------|
| Standards | 1 Important / 1 Minor / 1 FYI | met-with-fixes |
| Spec | 17/17 scenarios PASS (2 recorded amendments); 1 Minor | met |
| Security | 0 exploitable; 12 candidates triaged out; 1 Low (intentional) | secure |
| Edge cases | 1 (potential reachability only) | pass |
| Verification gaps | 5 + 2 cross-lens confirmations | met-with-fixes |
| Accessibility | 0 | clean |
| Performance | 2 (ratified design) | pass |
| Red team | 1 (cross-cutting) | 1 parked |

## Findings

### Critical

None.

### Important

- [Standards + VerifGap→**FIXED**] `frontend/src/lib/types.ts:252-253`
  (`ConfigMapItem`) — `binaryData` declared camelCase with the comment "the
  kubernetes client preserves the API casing for non-metadata fields". The
  installed client's `to_dict(serialize=False)` (the default — all 78 repo
  call sites) emits snake_case `binary_data`
  (`.venv/.../kubernetes/client/models/v1_config_map.py`:
  `("binaryData" if serialize else "binary_data")`). No runtime break today —
  nothing reads the field and the `[key: string]: unknown` index absorbs the
  real key — but the first real consumer would silently read `undefined`.
  Fixed: property renamed `binary_data`, comment corrected; the MSW fixture
  key (`binaryOnly`), the `ConfigMap.tsx:40` comment, and the test comment
  updated to the wire shape. tsc + vitest green.

### Minor

- [Standards + Spec + VerifGap→**FIXED**]
  `frontend/src/views/Storage/ConfigMapData.tsx:39-41` (docstring) — still
  claimed "trimAnnotations is NOT replicated (annotations render verbatim,
  including last-applied-configuration)" while the code trims (replicated
  2026-11-05 per user request, `:72-79`) and the test pins the trim
  (`configmap_data.test.tsx:139`). The QA gate's comment fix (d6bf3c4f)
  refreshed the test-fixture comment but missed the docstring. Fixed:
  docstring now states the trim (two machine-managed keys trimmed before
  render). Spec zone: `acceptance.feature`'s
  `configmap-data-renders-detail` step "includes last-applied-configuration
  (verbatim, NOT trimmed)" was inverted relative to implemented-and-tested
  behavior — amended to "trims last-applied-configuration (2026-11-05 T2
  override — adr.md OVERRIDE note; the JSON block still renders the full
  object)". The amendment was already recorded in `adr.md`; the feature file
  now agrees with it.
- [Standards→**FYI**, no action] commit f7c8223d's message names the trimmed
  keys inaccurately (out of diff scope; message-only).

## Verification-gap fixes (VerifGap lens, all disposition: patch)

| Gap | Type | Fix |
|-----|------|-----|
| `get_configmap` argument order `(name, namespace)` unpinned — value-ignoring stubs would pass a transpose that 404s on every real cluster | regression | **FIXED (unit half)**: `test_get_configmap_hit_returns_one_item_with_data` records + asserts `seen == [("app-config", "team-a")]` |
| R9 active-ref bold (`fw-bold`/`aria-current`) untested, sibling views pin it | regression | **FIXED**: `bolds-the-opened-configmap-from-the-active-ref` added (sibling shape from `secrets.test.tsx:135-164`) |
| `?? 'default'` namespace fallback untested, sibling pins it | regression | **FIXED**: `defaults-to-default-namespace-when-none-selected` added (sibling shape from `secrets.test.tsx:166-181`) |
| e2e REAL_ROUTES mount-only sweep is indistinguishable from the catch-all redirect; the `App.tsx` Route registration is not pinned by any failing-able test | broken-verification | **FIXED**: `/storage/configmap` exact-title case (`Configmaps List`) added to the real-routes loop mirroring the `/storage/pv` special case — deleting the route or typos its `kind` now fails the e2e |
| scenario step "the K8s client list call was never made" not asserted by its own test | broken-verification | **FIXED**: `assert not getattr(fake_k8s, "configmap_ns_calls", [])` in `test_list_configmaps_sar_denied` (the call log is lazily initialized by the call itself — absence IS the proof) |

## Parked (Low / FYI / cross-cutting / ratified design)

- [RedTeam→**PARKED**, CROSS-CUTTING] the R9 bold is dead in the live flow:
  `ObjectRoute.tsx:59,72` renders the list only when `ref.kind !== 'configmap'`,
  and the list reads the same `getActiveRef()` — so whenever the list renders,
  `selected` is always null. `sessionStorage` is tab-private, so the
  cross-tab deep-link path can't reach it either (`postObjectToTab` has no
  callers today). The identical shape exists in every ADR-0040 sibling view
  (their bold tests render the view directly, not through ObjectRoute).
  Owner: the ObjectRoute/session-object-navigation change (one fix touches
  every kind). The new unit test pins the view-level contract per the sibling
  convention regardless.
- [VerifGap→**PARKED**, FOLLOW-UP] held-out kind-integration backstop for
  `get_configmap` (modeled on
  `test_demo_serviceaccount_with_secret_and_pullsecret`): no
  `@pytest.mark.integration` test references configmaps; siblings
  (serviceaccounts, priorityclasses) have one. The unit argument pin above
  covers the transpose class; the real-cluster 404→`[]` behavior was
  live-verified at the QA gate.
- [Security→**PARKED**, DOCUMENTED INTENT] the list read carries full `data`
  values for list-only users (unlike `list_secrets`, which strips). Matches
  kubectl semantics; the briefing ratifies it (the Data Keys count is free
  — data is on the list read, and `data` is public — it is the one field that
  distinguishes an empty ConfigMap from a populated one without a per-row
  payload read).
- [Performance→**PARKED**, RATIFIED DESIGN ×2] (1) the list serializes full
  `data`/`binary_data` per ConfigMap — wire cost scales with the namespace's
  total config data (1MiB-per-object apiserver cap); (2) the all-namespaces
  branch is unbounded and includes full values (no UI caller today — R1
  mandates the branch; same shape as the `list_secrets` branch). Both are
  scale considerations on an approved design; a projection change is a
  design change, not a fix.
- [EdgeCases→**PARKED**, POTENTIAL REACHABILITY] a namespace-less configmap
  ref renders the data view's success branch with `item === undefined` (the
  N/A detail page, not an error). Reachability is potential only: the only
  in-app writer for this kind is the list view's `openObject`, which always
  carries a non-empty namespace.

## Security (lens summary)

No exploitable issues. 12 candidates triaged through the four-part rubric
(auth, trust boundaries, input handling, error reflection) and excluded with
evidence. The SAR gate is asked BEFORE the client read with the core group
(`""`) and the query namespace; denial 403s naming the resource
(`test_list_configmaps_sar_denied` pins the load-bearing tuple — now also
pins that the client call never happens). The data view's single
`?name=&namespace=` fetch resolves through the same binding gate.

## Accessibility (lens summary)

Clean. Name cells are native `<button>` (keyboard operable, accessible name
= object name); `aria-current` is the exact ADR-0040 convention shared by the
12 other kind cells; bold + `aria-current` carry state, not color alone;
card title is a heading; breadcrumb is a nav landmark with `aria-label`;
loading/error/empty are plain-div states (`.p-0`-targeted, no live regions —
consistent with every sibling view); `DataTables` wrapper carries proper
`<thead>` column headers (row scope, pre-existing convention).

## Verdict

- **Standards:** met-with-fixes (1 Important + 1 Minor fixed this pass)
- **Spec:** met (17/17 scenarios PASS under the two recorded amendments; the
  feature-file amendment is now explicit in `acceptance.feature`)
- **Security:** secure
- **Edge / Accessibility / Performance:** pass
- **Verification gaps:** met-with-fixes (5/5 patched; 1 half parked)
- **Red team:** 1 cross-cutting parked
- **Overall:** met-with-fixes
- **Unfixed Important count (must be 0 to proceed):** 0

## Triage / fix loop (receiving-code-review — the ledger)

| # | Finding | Lens(es) | Severity | Disposition | Action |
|---|---------|----------|----------|-------------|--------|
| 1 | `binaryData` camelCase wire declaration | Standards + VerifGap | Important | FIX NOW | renamed `binary_data` + comment; fixture + 2 comments follow; tsc/vitest green |
| 2 | stale trim docstring | Standards + Spec + VerifGap | Minor | FIX NOW | docstring corrected to "IS replicated (2026-11-05)" |
| 3 | `acceptance.feature:108` inverted step | VerifGap (spec zone) | Minor | FIX NOW | step amended to the trim wording + OVERRIDE pointer |
| 4 | `get_configmap` arg order unpinned | VerifGap | Medium (regression) | FIX NOW (unit) | value-recording stub + `seen == [("app-config", "team-a")]` |
| 5 | held-out kind-integration backstop | VerifGap | Medium (regression) | PARK (follow-up) | unit pin covers the transpose class; live-verified at gate; integration test follows the serviceaccount precedent |
| 6 | R9 bold untested | VerifGap | Low (regression) | FIX NOW | sibling-shape test added |
| 7 | `?? 'default'` fallback untested | VerifGap | Low (regression) | FIX NOW | sibling-shape test added |
| 8 | e2e mount-only / App.tsx unpinned | VerifGap | Medium (broken-verification) | FIX NOW | exact-title case added to the real-routes loop |
| 9 | SAR "client call never made" unasserted | VerifGap | Medium (broken-verification) | FIX NOW | `getattr(...) == []` assert added |
| 10 | R9 bold dead in live flow | RedTeam | Low (cross-cutting) | PARK | owner: ObjectRoute/session-object-navigation change; identical in all sibling views |
| 11 | list read carries `data` for list-only users | Security | Low | PARK (documented intent) | briefing ratifies; kubectl-consistent |
| 12 | list wire cost / unbounded all-ns branch | Performance | Low ×2 | PARK (ratified design) | projection = design change, not a fix |
| 13 | namespace-less ref → N/A detail page | EdgeCases | Low | PARK (potential only) | only in-app writer always carries a namespace |
| 14 | f7c8223d commit message key names | Standards | FYI | no action | message-only, out of diff scope |

## Floor re-execution after fixes

- Targeted vitest (`configmaps` + `configmap_data`): **15/15** (two new
  tests: `bolds-the-opened-configmap-from-the-active-ref`,
  `defaults-to-default-namespace-when-none-selected`; the `binary_data`
  fixture rename is shape-only).
- `tsc --noEmit`: clean. `ruff check` (both touched backend test files):
  clean.
- Targeted pytest (`-k configmap`, services + api): **12/12** (the SAR
  assert initially failed on the lazily-initialized call log — corrected to
  `getattr`, absence-is-proof documented inline).
- `task fe-build` (tsc + eslint + vite build): green.
- `task fe-check` (air-gap): green. `task fe-sync`: synced (backend/static).
- e2e real-routes leg (`ui-smoke.spec.ts -g "real routes"`): **1/1 PASS**
  (7.7 s) — includes the NEW `/storage/configmap` exact-title case
  (`Configmaps List`), which fails if the `App.tsx` route is deleted or its
  `kind` is typos'd.
