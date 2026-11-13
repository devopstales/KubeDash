# Code Review — ResourceQuota Views (List + Data)

**Change:** `2026-10-28-resourcequota-views` · **Reviewer:** 7-lens fan-out
(standards, spec, security, edge-cases, verification-gap, accessibility,
performance) + red team on the merged findings · **Gate date:** 2026-11-13
**Diff:** 4 commits — `783cff0a` backend kind extension, `1448a3f2` list
view, `d3d4067a` data view, `0b3b97bf` routes + stub removal — 12 files,
+1071/−1 squashed (1296 diff lines). The spec zone (briefing/blueprint/adr/
acceptance/NAVIGATION-SUPERSEDED) is excluded from this review; the
pre-generated diff at
`.skillgrid/meta/sdd/2026-10-28-resourcequota-views/review-diff` (gitignored)
is the read-only diff, and the lenses verified against the current tree where
the
two differ (the ObjectRoute migration `89528a32` rewrote `ResourceQuotaData`
URL-driven → ref-driven after this diff).
**Tree:** `rebase`, work tree clean except the `.DS_Store`/`.obsidian`
untracked noise. No uncommitted WIP at review time (the ha-status-page WIP
was committed as `959a3833`/`b2330f69`/`e00024fc`/`298415df`/`6963fc83` + the
gate fixes `039f7d89`/`73fdf640`).

## Verdict

**MET-WITH-FIXES.** 0 CRITICAL. 1 IMPORTANT (stale e2e smoke title + its
companion false docstring claim) + 4 verification-gap patches (SAR
call-absence assert, getter arg-order pin, R9 bold test, `?? 'default'`
test) — all fixed and re-verified at the gate (this file). All other findings
are parked cross-cutting items with named owners (fleet-wide convention,
post-hoc ObjectRoute migration, shared generic route) — none owned by this
diff.

## Lens Results

| Lens | Result |
|---|---|
| Standards | 1 Important (stale e2e title pin + false docstring claim), 2 Minor (fixture duplication, shared dimension constants), 1 FYI (ADR-0022 row). `list_resource_quotas`/`get_resource_quota` are byte-for-byte clones of the sibling pattern (incl. `_unreachable` + `AssertionError('unreachable')` tail); ADR-0004 SAR-before-read asserted behaviorally via the recorded SAR calls. |
| Spec | MET — 11 PASS + 3 DEVIATION (all three = the recorded ADR-0040 navigation replacement, no missing/partial scope); the trimAnnotations deviation stays accurate (grep count 0). |
| Security | CLEAN — 10 candidates triaged, none exploitable (query/name untrusted data on the existing generic route; SAR core group `""` + query ns asserted). |
| Performance | CLEAN — one SAR + one client call, no per-row reads, pagination set at the shared method, all-branches branch single-namespace-only in this view. |
| Accessibility | 4 findings — all repo-wide CoreUI convention (plain-div states, h5 card title, h5 page heading, h5-starting headings), verbatim from 12+ sibling views; not newly exposed by this diff (see PARKED). |
| Edge cases | 2 findings — shared-route `?name=`-without-namespace 'default' coercion (pre-existing, documented briefing R2); namespace-less active-ref phantom N/A detail (potential reachability only; the only app writer `openObject` always carries a namespace). |
| Verification gap | 6 gaps (5 patched here, 1 deferred) + 2 companion findings (the stale e2e claim, the `/data` sweep note). |
| Red team | 2 findings — R9 bold unreachable through the app flow (cross-cutting, same as the configmap red team); browser back no-op on the ref-driven same-route detail (post-hoc migration, ADR-0040 promise). |

## Fixed at the gate (verified)

1. **`e2e/ui-smoke.spec.ts:53` — stale SMOKE_STUB_ROUTES title pin (the
   Important).** The entry `title: 'Resource Quota'` asserted the stub's
   title with `exact: true` — the sidebar nav label satisfies it, so a
   regression that renders an empty card (no route) would pass the smoke.
   Retargeted to `title: 'Resource Quota List'` (the view's card title; the
   sidebar label cannot satisfy an exact match) with the sibling comment
   (runtimeclass precedent, `ui-smoke.spec.ts:63-66`). This makes the
   view's docstring claim (`ResourceQuota.tsx:90-91`) and the unit test
   comment (`resource_quotas.test.tsx:173`) TRUE — no doc edits needed.
   Verified: e2e stub-routes sweep 1/1 PASS (6.5s).
2. **`test_resources.py` — SAR-denied client-call-absence (VerifGap).**
   `test_list_resourcequotas_sar_denied` asserted 403 + `RBAC_DENIED` + the
   SAR tuple but never that the client list call was skipped (ADR-0004
   ordering); `FakeK8s.list_resource_quotas` had no call log. Added the
   lazy `resourcequota_ns_calls` log (sibling idiom, cf.
   `storageclass_ns_calls`) + `assert not getattr(fake_k8s,
   "resourcequota_ns_calls", [])`. Verified: 12/12 `-k resourcequota` PASS.
3. **`test_k8s_client_resourcequotas.py` — getter arg-order pin (VerifGap).**
   `test_get_resource_quota_hit_returns_one_item` stubbed
   `read_namespaced_resource_quota` with a value-ignoring lambda, so a
   transpose to `(namespace, name)` passes every unit test while 404-ing on
   every real cluster. Now records `seen` and asserts
   `seen == [("compute", "team-a")]`. Verified: PASS.
4. **`resource_quotas.test.tsx` — R9 bold test (VerifGap).** The active-ref
   `fw-bold`/`aria-current` pair (diff-added, `ResourceQuota.tsx:109-112`)
   was diff-added behavior with no test. Added
   `bolds-the-opened-resource-quota-from-the-active-ref` (sibling shape from
   `secrets.test.tsx` + a local `seedQuotaRef` mirroring the data test's
   helper). Verified: PASS. (Red-team note: through the app flow the bold
   is currently unreachable — ObjectRoute renders the detail whenever a
   same-kind ref is active; the test pins the view-level contract, same
   treatment as the configmap R9 pin — see PARKED.)
5. **`resource_quotas.test.tsx` — `?? 'default'` fallback test (VerifGap).**
   Added `defaults-to-default-namespace-when-none-selected` (selected
   cluster, `selectedNamespace: null` → fetches `?namespace=default`;
   sibling shape from `secrets.test.tsx`). Verified: PASS.
6. **`e2e/ui-smoke.spec.ts:436` — branch-level tsc red (pre-existing,
   ha-status-owned).** `document.querySelector('meta[name="kd-csrf"]')`
   (added by `039f7d89`, ha-status gate fixes) fails `tsc --noEmit`
   (`Property 'content' does not exist on type 'Element'`) — proven red at
   HEAD with this review's diff stashed. One-line fix:
   `querySelector<HTMLMetaElement>(…)`. Verified: `tsc --noEmit` clean
   branch-wide. (Named here so the ha-status gate record can note the
   correction landed with this change's review commit.)

Re-verification after the fixes: backend `ruff check` clean + 12/12
`-k resourcequota` (API + service); frontend 18/18 across
`resource_quotas`/`resource_quota_data`/`Stub` (was 16/16, +2 new); e2e
stub-routes sweep 1/1; `tsc --noEmit` clean; eslint over all sources clean
(`eslint . --ignore-pattern dist`: 0 errors — the full `pnpm lint` is red
only on the gitignored local `dist/` build artifacts, 132 prettier errors in
`dist/assets`; the flat config has no `dist` ignore and CI lints before the
build, so CI never sees `dist/`).

## Parked (cross-cutting, owners named)

- **R9 bold unreachable through the app flow** (red team). `ObjectRoute`
  renders the detail whenever a same-kind ref is active, and the list reads
  the same tab-private ref — so `selected` is non-null only while the list
  is unmounted. Fleet-wide (every ADR-0040 kind on a same-route list/detail);
  the configmap review parked the identical finding. Owner: the
  ObjectRoute / session-object-navigation change.
- **Browser back no-op from the ref-driven detail** (red team). `openObject`
  pushes the same URL after setting the ref; on pop, `ObjectRoute` re-reads
  the still-active ref and re-renders the detail — ADR-0040:94-95
  "Back/forward moves list↔detail" is unmet on same-route kinds. Introduced
  by the post-hoc migration `89528a32`, not this diff (at `0b3b97bf` the
  `/data` URL was distinct and back worked). Owner: the
  session-object-navigation change.
- **A11y: plain-div state regions, h5 card/page headings, h5-starting
  headings ×4** (a11y lens). Repo-wide CoreUI convention, verbatim from 12+
  sibling views (p-0 target, no live region, no per-page h1). The configmap
  a11y verdict: pre-existing, not newly exposed. An app-wide a11y pass is a
  separate change; fixing only these two views would break sibling parity.
- **Shared generic route: `?name=` without namespace coerces to 'default'**
  (edge lens). Pre-existing shared-route behavior, documented (briefing R2);
  pinned for kinds that test it, not for this kind. A normalizing fix is a
  separate change (same treatment as the runtimeclass review's parked
  coercion finding).
- **Namespace-less active-ref → phantom all-N/A detail** (edge lens).
  `ResourceQuotaData.tsx:66-117`: an unvalidated sessionStorage ref without
  a namespace renders a N/A detail (query disabled, no error state) —
  potential reachability only (the only in-app writer `openObject` always
  carries a namespace; a hand-edited sessionStorage entry is the trigger).
  Same parking as the configmap edge finding.
- **Standards Minor ×2 (judgment calls).** (a) The `compute` fixture is
  byte-identical in `resource_quotas.test.tsx:58` and
  `resource_quota_data.test.tsx:34` — a shared fixture module is a clean
  dedup but a test-data refactor across both files; the fixture is stable
  test data. (b) The four 4.1 dimension keys are literals in both views
  (`ResourceQuota.tsx:146-174`, `ResourceQuotaData.tsx:34`) in different
  order — a shared constant is a low-risk dedup of stable API names.
  Deferred, consistent with the runtimeclass review's Minor deferral.
- **VerifGap: no kind-integration backstop for resourcequotas + no
  ResourceQuota in the kind demo data.** Same disposition as the configmap
  parking (integration layer is the per-kind backstop fleet; demo data is a
  separate concern).
- **`/other-resource/resource-quota/data` absent from both e2e sweeps**
  (VerifGap). Fleet-consistent: no kind's `/data` route is swept, and at
  HEAD the URL is an R7 redirect, not a primary route. Coverage note, not a
  gap.
- **Standards FYI: ADR-0022's Resource Quota row still says `stub`.**
  Systemic doc drift (all landed kinds); first flagged at the configmap
  ship. A fleet ADR refresh is a separate change.

## Security (lens summary)

No new endpoints, trust boundaries, config, or IaC. `name`/`namespace` are
untrusted query data on the existing SAR-gated generic route (client
library validates, not regex); JSON block + per-row cells render
server-provided data through React's HTML-escaping + `String(...)`
coercion; no `dangerouslySetInnerHTML`; the data page's `useSearchParams`
reads are redirect-only (R7). SAR: core group `""` + query namespace
asserted in the API test.

## TDD / Evidence Note

Batch execution (2026-10-29 storage batch) — tests and code co-committed per
task; the execution progress ledger was not retained (the sibling pvc-views
spec zone — now archived — shows the same co-commit batch shape; the batch
QA gate was PASS per state.yaml), so the RED/GREEN audit is N/A by the same
class; behaviour coverage is complete
(14 scenarios in `acceptance.feature`, all proven by named tests per the
spec lens at the current HEAD, +5 verification pins added by this review).
