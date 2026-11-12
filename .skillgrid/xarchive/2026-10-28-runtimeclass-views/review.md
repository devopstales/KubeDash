# Review — RuntimeClass Views (2026-10-28-runtimeclass-views)

> Change: `.skillgrid/specs/2026-10-28-runtimeclass-views/` (TASK-046)
> Generated: 2026-11-12 (requesting-code-review)
> Diff: `718eda35~1..786100f5` (branch `rebase`) — the change's 4 code
> commits (718eda35 backend kind, 7580d592 list view, 33adbbe7 data view,
> 786100f5 routes + stub removal). Out-of-scope interleaved commit e7536e83
> (chore(backlog), docs only) reviewed as context only. Post-hoc: the
> 2026-11-02 ADR-0040 ObjectRoute migration (89528a32, separate change
> 2026-10-29-session-object-navigation) migrated these views to
> session-scoped object refs — recorded in the spec zone
> (`NAVIGATION-SUPERSEDED.md`; backend `?name=` filtering param unchanged).
> Rigor tier: T2
> Independence: Grade B per axis (fresh subagent contexts, no shared
> session history — but the same toolchain/model family as the
> implementer; a T2 three-axis pass, per `_shared/planning/rigor-tiers.md`)
>
> The durable audit record of the code review. Next to the QA gate record
> (`qa-report.md` in `2026-10-28-other-resource-views`, which hosts the
> batch-of-6 QA report). The three review axes are reported **side by side,
> never merged** — that separation is the point.

## What Important means

- **Critical** — must fix before merge. Security, data loss, broken
  functionality, a `SATISFIES` scenario whose RED evidence is missing or
  whose code path does not match the Given/When/Then.
- **Important** — should fix before merge. Architecture drift from a term
  or in-force ADR, a hard standard breach, a missing/partial requirement,
  or behavior the spec never asked for (scope creep). Unfixed Important
  issues do not proceed.
- **Minor** — nice to have. Baseline smells, style, optimization, doc
  polish. Capped.

## Passes

> Three axes, side by side. Never merged into one verdict.

### Standards

- **Worst issue (within this axis):** the list view's docstring (and the
  test file's comment) claim e2e smoke coverage for the card title that
  does not exist — no runtimeclass entry in `ui-smoke.spec.ts` (Minor,
  FIXED).
- **Findings:** 0 Critical / 0 Important / 3 Minor
- **Verdict:** met-with-fixes (all 3 fixed this pass)

### Spec

- **Worst issue (within this axis):** the shared generic route's
  `?name=` branch coerces an absent `?namespace` to `"default"` before
  asking the get-SAR, so a cluster-scoped get verdict is asked (and
  cached) with namespace `"default"` rather than `None` (Minor, INHERITED
  — pre-existing shared route, the diff's declared scope is kind-wiring
  only; the K8s API server ignores namespace for cluster-scoped resources,
  so the verdict is correct; PARKED).
- **Findings:** 0 Critical / 0 Important / 2 Minor (1 inherited shared
  route, 1 test-coverage legs unasserted but 1:1 with the mandated
  priorityclass precedent — both PARKED)
- **Verdict:** met (11/11 scenarios PASS; real TDD RED→GREEN; spec zone
  committed before code)

### Security

- **Worst issue (within this axis):** SAR cache key built from
  `:`-delimited unescaped segments (Low, Confirmed at the target revision
  — a (namespace, name) tuple collision could return a wrong 403-vs-500
  outcome; no demonstrated data-leak path; already fixed at HEAD by the
  percent-encoded key segments) — PARKED as fixed-at-HEAD.
- **Findings:** 0 Critical / 0 High / 0 Medium / 1 Low (fixed at HEAD) /
  13 dropped candidates (each traced entry-point → sink, failed the
  four-part triage rubric; see `### Parked`)
- **Verdict:** secure

## Findings

### Critical

None.

### Important

None.

### Minor

- [Standards→**FIXED**] `frontend/src/views/OtherResource/RuntimeClass.tsx`
  (docstring) + `frontend/tests/views/runtime_classes.test.tsx` (comment)
  — "the e2e smoke (ui-smoke.spec.ts) asserts that string with `exact:
  true`" is false: `ui-smoke.spec.ts` had no `/other-resource/runtimeclass`
  entry (neither `SMOKE_STUB_ROUTES` nor `REAL_ROUTES`). Verbatim clone of
  the PriorityClass comment, where it was true (1bd5afab moved the smoke
  entry in the same commit); the runtimeclass stub was never in the smoke
  list, so there was nothing to move. The title was pinned only by the
  unit test. Fixed: `{ path: '/other-resource/runtimeclass', title: 'Runtime
  Classes' }` added to `SMOKE_STUB_ROUTES` (the sibling other-resource
  views' convention — hpa/vpa/pdb/resource-quota/priorityclass all carry
  title-asserting entries) — the docstring claim is now true and the view
  has e2e title parity. Verified by `task e2e`.
- [Standards→**FIXED**]
  `.skillgrid/knowledge/decisions/04-adr-0022-sidebar-nav-4-1-parity.md`
  (Other Resources → Runtime Class row) — still `stub` after the stub route
  was removed and real list+data views wired. The priorityclass-row
  precedent (1bd5afab) amended its row in the same commit; repo practice
  for the other delivered rows is mixed (several still `stub` at HEAD —
  debt of their own changes). Fixed: row amended to `implemented
  (feature)` with the dead-4.1-link note; `log.md` entry added (index.md
  unchanged — in-place amendment).
- [Standards→**FIXED**] `frontend/src/views/OtherResource/RuntimeClass.tsx`
  (`toRow`) — a present-but-empty `pod_level_overhead: {}` passed the
  truthiness check and joined to `''` (an empty cell), while
  `RuntimeClassData.tsx` renders `N/A` for the identical shape. Fixed:
  `[cpu?, memory?].filter(Boolean).join(' / ') || '—'` — absent AND
  present-but-empty both render the em dash (the pinned absent-case
  character, R3), never an empty cell. Regression test: `kata` fixture
  (`pod_level_overhead: {}`) added to `list-overhead-absent-state` — the
  assertion `kataRow.textContent contains '—'` fails against the old
  expression.

### Parked (Low / FYI / future-state)

- [Spec + Standards + Security→**PARKED**, SHARED ROUTE] the generic
  route's `?name=` branch forces `namespace = namespace or "default"`
  before the get-SAR even for cluster-scoped kinds. All three axes
  flagged it independently: the K8s API server ignores namespace for
  cluster-scoped resources, so the verdict is CORRECT (security
  live-verified: `?name=demo-runc` → 200; a namespaced `Role` grant can
  neither widen nor narrow a cluster-scoped verdict); the only effect at
  this revision was a namespace-segmented SAR cache key (the key is now
  percent-encoded at HEAD, so no cross-talk). Pre-existing shared-route
  behavior, identical for every cluster-scoped kind (priorityclasses,
  nodes, crds, storageclasses, …); the diff's declared scope is
  kind-wiring only ("No new HTTP route is added"). A fix (cluster-scoped
  normalization in the shared route) is a separate change touching every
  kind.
- [Spec→**PARKED**, TEST COVERAGE] two Then-clause legs are guaranteed by
  code path but not directly asserted: `runtimeclasses-list-200`'s "the
  body cluster is the bound cluster name" (the shared route returns
  `cluster.name`; the mandated `test_list_priorityclasses_200` precedent
  has the same gap) and `runtimeclasses-sar-denied`'s "the K8s client
  list call was never made" (the route asks `rbac.can` before
  `pool.get(...)` — verified structurally; the precedent test has the
  same shape). 1:1 with the precedent the spec mandates mirroring; the
  data view's single-fetch leg IS directly asserted (`data-renders-detail`
  pins exactly one request).
- [Security→**PARKED**, FIXED AT HEAD] SAR cache key `:`-delimiter
  ambiguity (CWE-649, A01:2025) as committed in 786100f5 — (ns=`a`,
  name=`b:c`) and (ns=`a:b`, name=`c`) collide, as do subs containing `:`
  (all local-login subs do: `local:admin@local`). No data path: the K8s
  read always runs with the real tuple, colon-namespaces 404 → `[]`; the
  observable delta is a wrong 403-vs-500/empty outcome under contrived
  `resourceNames` grants. Pre-existing (shared getters); fixed at HEAD —
  all key segments are `quote(str(x), safe='')` (`rbac.py:46-52`); the
  R3 security review already records the key as injective.
- [Security→**PARKED**, DROPPED CANDIDATES] `?name=` path
  injection/traversal into the k8s client (the client percent-encodes
  into a single path segment — `safe_chars_for_path_param` defaults to
  `''`; worst case 404 → `[]` or 400 → 502 fail-closed); XSS via the
  full-object JSON block (react-syntax-highlighter 16.1.2 renders hljs
  AST text nodes as React text — no `dangerouslySetInnerHTML` in
  `dist/esm`); XSS via CTable cells / error state / breadcrumb (all React
  text children); IDOR across clusters (binding gate 404, pinned by
  `test_runtimeclasses_binding_404`); mass data exposure via the JSON
  block (exactly the `to_dict` item the get-SAR authorized — by design,
  4.1 parity); `?namespace=` on a cluster-scoped kind (accepted-and-
  ignored by both client methods; SAR attribute only); hljs ReDoS /
  unbounded list (linear-time json grammar; crafting many RuntimeClasses
  needs cluster-write rights; client-side only); error-message reflection
  (structured JSON envelopes, React-escaped); auth on the new routes
  (app-wide `apply_auth` + `ProtectedRoute` hint gate, pre-existing);
  route/stub swap (exact-path routes, no wildcard shadowing); new
  `NodeV1Api` instance (shares the existing `api_client`/credentials);
  e7536e83 docs commit + fakes (no runtime exposure).

## Independence

| Axis | Grade | Rationale |
|------|-------|-----------|
| Standards | B | fresh `reviewer` subagent; saw only the diff range + glossary/ADR/standards sources; same toolchain family as the implementer |
| Spec | B | fresh general-purpose subagent; saw only the diff range + acceptance.feature/blueprint/briefing/adr/NAVIGATION-SUPERSEDED + the Backlog task file |
| Security | B | fresh `security-reviewer` subagent; saw only the diff range + OWASP skill references; verified live against the dev stack (read-only probes) |

**Reading the grade:** all three are **B** — independent contexts (no
implementer session history shared), but the same model family as the
implementer. Cross-axis corroboration compensates: the get-SAR
namespace-coercion note was flagged independently by the Spec, Standards,
and Security axes with the same root-cause analysis; the Standards and
Spec axes both verified the SAR-before-client ordering and the
`node.k8s.io` group assertion against the code.

## Verdict

- **Standards:** met-with-fixes
- **Spec:** met
- **Security:** secure
- **Floor (decides):** met-with-fixes
- **Worst issue (across all three axes):** false e2e-smoke coverage claim
  in the list view's docstring (Minor, FIXED — the smoke entry now
  exists and the claim is true)
- **Unfixed Important count (must be 0 to proceed):** 0 (all 3 Minor
  findings fixed this pass; parked items are pre-existing shared-route
  behavior or fixed at HEAD)

## Triage / fix loop (receiving-code-review)

| Finding | Severity | Disposition | Action |
|---------|----------|-------------|--------|
| false e2e-smoke claim + no smoke entry | Minor (Standards) | FIX NOW | `SMOKE_STUB_ROUTES` entry added (title-asserting, sibling-view convention); `task e2e` verifies |
| ADR-0022 parity row stale | Minor (Standards) | FIX NOW | row amended `implemented (feature)` + `log.md` entry (index.md unchanged) |
| present-but-empty overhead → empty cell | Minor (Standards, FYI) | FIX NOW | `|| '—'` fallback in `toRow` + `kata` regression fixture |
| get-SAR namespace "default" coercion | Minor (Spec/Standards/Security) | PARK | pre-existing shared generic route; verdict correct (K8s ignores ns cluster-scoped); key now percent-encoded; separate change to normalize |
| unasserted Then-clause legs (2) | Minor (Spec) | PARK | 1:1 with the mandated priorityclass precedent; behavior holds structurally |
| SAR cache key `:` delimiter | Low (Security) | PARK (fixed at HEAD) | `quote()` segments landed in a later commit; no data-leak path at the target revision |

## Floor re-execution after fixes

Backend untouched by this pass (all fixes are frontend + knowledge zone);
the standards axis re-ran the backend suite at HEAD (220 passed, 6
deselected — the kind-fixture Docker baseline) as part of its review.

- Targeted vitest (runtime_classes + runtime_class_data + Stub): **15/15**
  (the `kata` fixture extends the existing
  `list-overhead-absent-state` test, no new test count).
- `task fe-build` (tsc --noEmit + eslint + vite build): green.
- `task fe-check` (air-gap): green.
- `task fe-sync`: synced (backend/static).
- e2e: the full `task e2e` run is RED at ui-smoke's FIRST test —
  `getByText('Bound clusters')` (ui-smoke.spec.ts:125) — NOT this change:
  a parallel in-flight change committed mid-session (959a3833
  "feat(clusters): 4.1 Kubernetes Server List parity + edit endpoint",
  2026-11-12) re-titled the /clusters card to `Kubernetes Server List`
  without updating the four `Bound clusters` assertions
  (smoke.spec.ts:71,99; ui-smoke.spec.ts:125,315) — those belong to that
  change's e2e upkeep. The filtered run of the sweep my entry joins
  (`playwright test e2e/ui-smoke.spec.ts --grep "stub routes"`): **1/1
  PASS** — `/other-resource/runtimeclass` mounts the shell and renders
  `Runtime Classes` exact (6.4 s). Live API probes against the kind
  cluster: list → `kind: runtimeclasses, items: [demo-runc]`;
  `?name=demo-runc` → 1 item.
