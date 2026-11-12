# Review — Storage Views Batch (5 changes)

> Change: report home `.skillgrid/specs/2026-11-05-pv-views/` + the four
> `2026-10-28-{storageclass,snapshotclass,volumesnapshot,pvc}-views/` specs (batch
> of 5: TASK-052 storageclass, TASK-051 snapshotclass, TASK-053 volumesnapshot,
> TASK-065 pvc, TASK-066 pv).
> Generated: 2026-11-05 (requesting-code-review)
> Diff: `1d5bb5ba..87232e0a` (branch `rebase`) — the batch's 40 commits + the QA
> gate fixes (`ce6d0b19`, `6368cc8b`). Out-of-scope commits interleaved in the
> range (reviewed as context only): configmap views (TASK-064), test-security
> (TASK-067), housekeeping. The uncommitted ingressclass-gatewayclass WIP in the
> working tree was excluded from the review (separate change).
> Rigor tier: T2
> Independence: Grade B per axis (fresh subagent contexts, no shared session
> history — but the same toolchain/model family as the implementer; a T2
> three-axis pass, per `_shared/planning/rigor-tiers.md`)
>
> The durable audit record of the code review. Next to `qa-report.md` (which
> owns the QA gate). The three review axes are reported **side by side, never
> merged** — that separation is the point.

## What Important means

- **Critical** — must fix before merge. Security, data loss, broken
  functionality, a `SATISFIES` scenario whose RED evidence is missing or whose
  code path does not match the Given/When/Then.
- **Important** — should fix before merge. Architecture drift from a term or
  in-force ADR, a hard standard breach, a missing/partial requirement, or
  behavior the spec never asked for (scope creep). Unfixed Important issues do
  not proceed.
- **Minor** — nice to have. Baseline smells, style, optimization, doc polish.
  Capped.

## Passes

> Three axes, side by side. Never merged into one verdict.

### Standards

- **Worst issue (within this axis):** PV→PVC cross-kind ref kind mismatch —
  a registry kind no route accepts, so the claim link rendered the PVC LIST
  instead of the DETAIL (Critical, FIXED).
- **Findings:** 1 Critical / 0 Important / 3 Minor
- **Verdict:** met-with-fixes

### Spec

- **Worst issue (within this axis):** the same cross-kind kind mismatch,
  traced to a spec-set defect (the pv-views blueprint mandated
  `openObject('persistentvolumeclaim', …)` verbatim while the pvc route is
  registered `kind="pvc"`) — Wrong Implementation (FIXED with blueprint
  amendment).
- **Findings:** 0 Critical / 2 PARTIAL scenarios (both FIXED) / 0 scope creep
  (all three additions — PV Usage column, trimAnnotations companion, dev
  csi-hostpath — verified recorded in the spec zone before the code)
- **Verdict:** met (83/85 PASS at review; the 2 PARTIALs fixed this pass →
  85/85)

### Security

- **Worst issue (within this axis):** storageclasses SAR gate asked the core
  group `""` instead of `storage.k8s.io` (Low, FIXED) — a non-admin registry
  kubeconfig would 403 users holding the real grant (fail-closed,
  availability-only).
- **Findings:** 0 Critical / 0 High / 0 Medium / 2 Low (1 FIXED, 1 PARKED →
  W023). Dropped candidates (documented, not findings): `get nodes` vs
  `nodes/proxy` gate resource (both directions degrade honestly), SAR subject
  semantics (ADR-0004/0013 architecture, pre-existing), `pvcRef` missing-name
  KeyError (fixed defensively this pass), `collect-security.py` /tmp TOCTOU
  (advisory-only metrics push, pre-existing).
- **Verdict:** secure-with-fixes

## Findings

### Critical

- [Standards + Spec→**FIXED**] `frontend/src/views/Storage/Pv.tsx` +
  `PvData.tsx` — the cross-kind claim cell/link emitted
  `openObject('persistentvolumeclaim', …, '/storage/pvc')`, but the route is
  registered `ObjectRoute kind="pvc"` and `ObjectRoute.tsx` matches
  `ref.kind === kind` verbatim — so PV→PVC navigation rendered the PVC **list**
  (the claim's detail never rendered; the claim wasn't even bolded). Every
  other cross-kind open in the app uses the target route's registry kind.
  Fixed: both call sites emit `'pvc'`; the emit-side pin updated
  (`pvs.test.tsx`); new CONSUMER-side test `volumeclaim-cell-opens-pvc-detail`
  mounts both routes as in `App.tsx` and asserts the PVC detail (not the list)
  renders after the click — the single test that would have caught this at QA.
  The pv-views blueprint (2 places) amended to the registry kind with the
  rationale. **Root cause of the QA miss:** the QA e2e asserted shell-mount
  only, and the emit-side vitest pinned the written ref, not the consumer.

### Important

- [Spec→**FIXED**] `persistentvolumes-get-by-name` (scenario block 3) — the
  get-SAR-denial leg was implemented by the shared generic route but never
  asserted. Fixed: `test_list_persistentvolumes_get_by_name_sar_denied`
  (asserts `("get", "persistentvolumes", "default", "pv-a", "")` asked;
  client call never made).
- [Spec→**FIXED**] `pv-stub-removed-real-route` (Then clause 2) — the e2e
  REAL_ROUTES sweep asserted mount but not the exact title the blueprint's
  verification floor claims. Fixed: `ui-smoke.spec.ts` seeds the persisted
  `kd-cluster-scope` store (the list renders a no-cluster state otherwise)
  and asserts the heading `Persistent Volume List` exact.
- [Security→**FIXED**] `backend/app/api/resources.py` `_KINDS["storageclasses"]`
  — the SAR gate asked core group `""`; StorageClass is `storage.k8s.io`, so a
  core-group SAR never matches a `storage.k8s.io` grant (a non-admin registry
  kubeconfig → spurious 403 for users holding the real grant; fail-closed,
  availability-only, inert under the current admin-kubeconfig model). Fixed:
  group `storage.k8s.io` + test assertion + the spec zone (feature, blueprint ×4,
  adr.md manifest, briefing ×3) amended with dated fix notes — the spec set
  had encoded the same wrong group.

### Minor

- [Standards→**FIXED**] 5 stale docstrings contradicting the code after the
  2026-11-05 overrides: the four Data views (PvcData/StorageClassData/
  SnapshotClassData/VolumeSnapshotData) still said `trimAnnotations` is NOT
  replicated (f7c8223d replicates it), and `pvc_usage`'s docstring still said
  `json.loads` (9bba46d5 uses `_parse_stats_body`). All five corrected.
- [Standards→**FIXED**] (`Consider`) `pvc_usage` — `int(capacityBytes)` ran
  OUTSIDE the per-node try: a non-numeric value raised a bare `ValueError` →
  500 on an endpoint that declares only 404/502, instead of skipping the node
  per its own docstring. Fixed: aggregation moved inside the per-node try,
  byte counts converted BEFORE the merge (a bad node leaves no partial entry),
  plus a `pvcRef` missing-name skip guard (the Security axis's dropped
  KeyError candidate, same class). Regression test
  `test_pvc_usage_malformed_body_skips_node`.
- [Standards→**FYI**] commit atomicity — `ce6d0b19` (demo-data.sh PVC wait)
  also carried one typing line, whose sibling half sits in `6368cc8b`;
  reverting the demo-data fix would drag the typing line. Noted for the record;
  nothing to do before merge (both are on `rebase`, not yet integrated).

### Parked (Low / FYI / future-state)

- [Security→**PARKED**→W023] `GET /metrics/pvcs` fans out per-node kubelet
  proxy reads SEQUENTIALLY (`connect_get_node_proxy_with_path`, 2 s timeout
  each) on one gunicorn thread: ~2N s for N dead kubelets, capped ~30 s by the
  worker timeout (worker recycled). Read-only, bounded, only in the exact state
  where stats are unavailable. Defense-in-depth options (concurrency cap,
  stats/summary cache, per-request deadline) are a design decision — deferred.
- [Security→**PARKED**] SAR subject semantics — the SAR is a
  `SelfSubjectAccessReview` issued with the shared registry kubeconfig (no
  impersonation): the verdict is per-registry-identity, constant across users
  bound to one cluster. ADR-0004/ADR-0013 architecture (bind-time
  Role/RoleBinding); all new routes consume it identically to pre-existing
  ones. Not introduced by this batch.
- [Security→**PARKED**] the pvcs gate checks `get nodes` while the proxy read
  strictly needs `nodes/proxy` — both directions degrade honestly (grant on
  `nodes` only → per-node 403 → `metrics_available: false`; `nodes/proxy` only
  → `metrics_denied: true`). Documented design; no leak.
- [Security→**PARKED**→W022, CROSS-CHANGE] same group class as the
  storageclasses fix, on a row OUT of this diff: `_KINDS["horizontalpodautoscalers"]`
  uses core group `""` — HPA is `autoscaling.k8s.io` (TASK-050, the
  `2026-10-28-other-resource-views` change, still awaiting its own review).
  Recorded in WINDOWS.md for that change's review to fix.

## Independence

| Axis | Grade | Rationale |
|------|-------|-----------|
| Standards | B | fresh `reviewer` subagent; saw only the diff range + glossary/ADR/standards sources; same toolchain family as the implementer |
| Spec | B | fresh general-purpose subagent; saw only the diff range + the five acceptance.features/blueprints/briefings + NAVIGATION-SUPERSEDED notes + backlog TDD notes |
| Security | B | fresh `security-reviewer` subagent; saw only the diff range + OWASP skill references |

**Reading the grade:** all three are **B** — independent contexts (no
implementer session history shared), but the same model family as the
implementer; the Critical finding's consumer-side regression test + the
re-executed floor are the compensating controls.

## Verdict

- **Standards:** met-with-fixes
- **Spec:** met (2 PARTIALs fixed this pass)
- **Security:** secure-with-fixes
- **Floor (decides):** met-with-fixes
- **Worst issue (across all three axes):** PV→PVC cross-kind ref kind mismatch
  (Critical, FIXED + consumer-side regression test)
- **Unfixed Important count (must be 0 to proceed):** 0 (all 3 Important + the
  Critical fixed this pass)

## Triage / fix loop (receiving-code-review)

| Finding | Severity | Disposition | Action |
|---------|----------|-------------|--------|
| PV→PVC cross-kind ref kind | Critical | FIX NOW | both call sites emit `'pvc'`; emit pin updated; consumer test `volumeclaim-cell-opens-pvc-detail`; blueprint amended (2 places) |
| PV get-SAR-denial untested | Important (PARTIAL) | FIX NOW | `test_list_persistentvolumes_get_by_name_sar_denied` |
| e2e pv exact title missing | Important (PARTIAL) | FIX NOW | ui-smoke sweep: seed `kd-cluster-scope` + assert heading exact |
| storageclasses SAR core group | Low (security) + spec-set | FIX NOW | `_KINDS` group `storage.k8s.io` + test + feature/blueprint/adr/briefing amended with dated notes |
| 5 stale docstrings | Minor | FIX NOW | all corrected |
| pvc_usage int() outside try | Consider (minor) | FIX NOW | aggregation in per-node try; convert-before-merge; pvcRef name guard; `test_pvc_usage_malformed_body_skips_node` |
| commit atomicity ce6d0b19 | FYI | PARK | noted; nothing before merge |
| pvcs sequential fan-out | Low | PARK | W023; bounded by gunicorn 30 s; degraded-kubelet state only |
| HPA SAR core group (cross-change) | Low | PARK → W022 | belongs to `2026-10-28-other-resource-views`' review |
| nodes/proxy gate nuance | FYI | PARK | documented design; honest degrade both directions |
| SAR subject semantics | FYI | PARK | ADR-0004/0013 architecture, pre-existing |

## Floor re-execution after fixes

Re-executed after the fix commits `f2cf8a2a`/`feb36175`/`9601ed62`
(post-fix, dev stack live; the QA gate's floor numbers in `qa-report.md`
remain the pre-review record):

- Backend unit: **670/670** (was 648 at the QA gate; +20 from the
  in-flight gateway-api commits on `rebase`, +2 from this pass's
  `test_pvc_usage_malformed_body_skips_node` +
  `test_list_persistentvolumes_get_by_name_sar_denied`; the 3 configmap
  tests red at `b29f97ac` green again after `f2cf8a2a`).
- Vitest full: **377 passed / 12 failed** — the 12 are exactly the W007
  baseline set (count airtight: 388→389 total, the +1 pass is the new
  consumer test); targeted storage+Stub files 73/73 within the run.
- `task fe-build` (tsc + eslint + vite): green.
- `task fe-check` (air-gap): green.
- ruff on the touched backend files: only pre-existing E501s (inside the
  102 flat baseline); mypy: **75 < 78** ceiling (was 73; +2 from the
  in-flight gateway-api commits).
- `task e2e` (auth-smoke + ui-smoke vs the dev stack): **19/19**, now
  including the `/storage/pv` exact-title assertion.

## Post-review bug fix (2026-11-05, user-reported, pre-ship)

**Symptom:** PVC list (and PV list) Usage column stuck at "—" on first
visit; populated only after navigating away and back (remount).

**Root cause:** `datatables.net-react` binds Column render fns to the
table instance only at initialisation and re-renders cells only when
the `data` prop changes. The Usage cell's render fn closed over
`usageQuery.data`'s Map — captured empty at table init. When the usage
fetch (kubelet fan-out) resolved after the list (informer cache),
`query.data`'s reference never changed → no redraw → "—" until
remount. The vitest fake KubeDataTable masked it: it re-rendered cells
from the CURRENT children, not the captured render fns.

**Fix:** `500e13e4` — join usage (PVC: the active-ref selected bold
too) into the rows on every render (the Nodes.tsx pattern); render fns
are pure functions of the row. The pvcs/pvs fakes now replicate the
init-time capture; new
`list-usage-late-resolution-updates-in-place` regression tests in both
files fail against the old code, pass against the fix.

**Floor (post-fix):** storage test files 27/27; vitest full — same
377+/12 as the W007 baseline above (no new failures); `task fe-build`
+ `task fe-sync` green; `task e2e` 19/19; verified live in the browser
(fresh load, no cache: demo-pvc Usage 26.1% on `/storage/pvc` and
`/storage/pv`).

Related pre-ship fix: `8822c410` — sidebar nav clicks clear the active
object ref (a nav click to a list route while a detail was open
re-rendered the detail instead of the list); regression test in
`tests/nav.test.tsx`.
