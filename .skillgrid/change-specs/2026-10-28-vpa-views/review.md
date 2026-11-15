# Code Review — VerticalPodAutoscaler Views (List + Data)

**Change:** `2026-10-28-vpa-views` · **Reviewer:** 7-lens fan-out
(standards, spec, security, edge-cases, verification-gap, accessibility,
performance) + red team on the merged findings · **Gate date:** 2026-11-15
**Diff:** 4 commits — `c0616f4a` backend kind extension, `638acca3` list
view, `ecd6e98a` data view, `6bb35dd9` routes + stub removal — 12 files,
+1341/−1 (base `1a510cb4`). The spec zone (briefing/blueprint/adr/
acceptance/NAVIGATION-SUPERSEDED) is excluded from this review; the
pre-generated diff at
`.skillgrid/meta/sdd/2026-10-28-vpa-views/review-diff` (gitignored) is the
read-only diff, and the lenses verified against the current tree where the
two differ (post-diff: the ObjectRoute migration `89528a32` rewrote
`VerticalPodAutoscalerData` URL-driven → ref-driven; the bounds `—`
present-but-empty fix `98613f68`; the shared KubeDataTable fake migration
`1802d456`; the breadcrumb back-affordance `debdf9e6`; the share-button
removal `7ba9bf75`; an unused-import drop `35469827` — none change
vpa-views-specified behavior per the spec lens).
**Tree:** `rebase`; the only uncommitted work at review time is this review's
fix set (9 files). The ha-status-page WIP was committed mid-review as
`448db3d4`/`30ee933f` (its ruff/mypy floor debt is noted in the Floor note,
not owned by this change).

## Verdict

**MET-WITH-FIXES.** 0 CRITICAL. 2 IMPORTANT — stored XSS via the shared
`KubeDataTable`/DataTables cell sink (security Medium; the sink is
pre-existing and repo-wide, the fix belongs at and lands in the shared
component, covering all ~20 consumer views) and the literal `'<br/>'` text
in multi-resource Min/Max Allowed cells (edge + a11y, newly exposed by this
diff) — plus 6 verification pins (list 502 at both tiers, served-version
authority, list-error-state, SAR call-absence assert, scope-authority,
`?? 'default'` fallback) and 3 minors (orphaned comment, duplicate React
keys ×2, stale docstring claim). All 12 accepted findings fixed and
re-verified at the gate (this file). All other findings are parked
cross-cutting items with named owners (fleet-wide convention, ADR-0040
ObjectRoute mechanics, shared sessionStorage lib) — none owned by this diff.

## Lens Results

| Lens | Result |
|---|---|
| Standards | 3 Minor — orphaned VPA comment stranded above the `gatewayclasses` entry by a later change (fixed); list-path error-map test missing (subsumed by the verif 502 pin); absence-sentinel drift `N/A` vs `—` vs the PDB sibling (parked — the 4.1 literal is documented in the view header). FYI: ADR-0041 kind catalog is the already-decided consolidation of the per-kind seam; one flaky sibling test + SimpleBar/jsdom noise off-surface. The Cilium seam is verbatim-ratified; ADR-0004/0009/0010/0020/0021/0022 verified honored. |
| Spec | MET — 18 acceptance scenarios: 16 PASS + 2 DEVIATION, both the recorded ADR-0040 navigation replacement (name button instead of `/data` link; `/data` now `OldDataRedirect`; identity as props). 1 Minor — the e2e smoke's card-title pin never retargeted from the stub-era nav label 'VPAs' (fixed). No scope creep; no wrong implementation. |
| Security | 1 MEDIUM — stored XSS: `spec.targetRef.kind`/`name` (plain-string CRD fields, no pattern; accepted verbatim by the API server, proven by `kubectl create` on the live kind cluster) reach the DOM through DataTables `writeCell` → `cell.html(val)`. 12 candidates triaged, 11 not exploitable — the full-object JSON block is genuinely escaped (element-based highlighter, no `innerHTML`); name/namespace allowlisted before SAR and client call; SAR fail-closed. |
| Performance | CLEAN — 2 uncached API round trips per request (CRD served-version read + the object read), the verbatim ~20-kind sibling pattern on the ratified per-request spine (informer cache is the deferred target); no N+1, no per-row reads, no new vendor weight. |
| Accessibility | 1 newly exposed (the `join('<br/>')` literal — fixed) + 3 fleet-wide (ObjectRoute focus management; plain-div async states with no live region; first Back press no-op, AAA) — parked. Contrast clean: the two sub-AA hljs tokens are not emitted by the JSON grammar. |
| Edge cases | 4 findings — 3 fixed (`'<br/>'` literal; duplicate policy keys on empty `containerName`; duplicate condition keys on repeated `type`) + 1 parked (namespace-less active ref → query disabled → all-N/A detail; potential reachability only, see PARKED). |
| Verification gap | 3 gaps fixed (502 contract unpinned at both tiers — deleting the `except ApiException` block passes all 12 VPA tests; served-version authority unprovable — stub and assertion share `"v1"`; list-error-state the only other-resource view missing it) + SAR call-absence assert fixed + 2 fleet-wide findings parked (vacuous `window.location.search` R1 assertion under MemoryRouter; per-kind App.tsx wiring path-level-only). |
| Red team | 7 findings — 2 fixed (scope-authority branch unpinned: the `_client` stub hardcodes `"Namespaced"` while the VolumeSnapshot sibling pins the cluster-scoped case; the data-view docstring's stale "sole producer" claim) + 2 constraints on the XSS fix honored (escape string outputs only — element returns take the portal path and zero renderers return intentional HTML; preserve `data` prop identity — the fix clones columns, not rows) + 3 parked (ObjectRoute cross-tab deep link pins the detail past `clearActiveRef`; name-cell bold/aria-current provably dead while the list is mounted; `kd_object_refs` grows unbounded per tab). |

## Fixed at the gate (verified)

1. **`frontend/src/components/KubeDataTable.tsx` — shared-sink XSS escape
   (the security Important).** Plain-string cell values and renderer string
   returns are escaped at the one place DataTables calls `cell.html()`:
   `escapeString` (string-only; elements and numbers pass through exactly as
   before) applied as a column renderer for plain `data` columns and as an
   arity-preserving `escapeRenderer` wrapper for function children (the
   wrapper's slotRenderer dispatches on renderer arity — the wrapper exposes
   4). `data` prop identity is untouched (columns are cloned, rows are not —
   the red-team identity constraint). Verified: 4 new tests in
   `tests/components/KubeDataTable.test.tsx` against the REAL component (not
   the view-test fake, which would mask the display path): plain-data
   escape, string-renderer escape, element renderers kept as DOM nodes,
   text/number passthrough — 4/4 PASS; the security lens's live-DOM probe
   (a real `<img>` born from the payload pre-fix) is the RED evidence.
2. **`VerticalPodAutoscalerData.tsx` — real `<br />` line breaks in bound
   cells (the rendering Important; edge + a11y newly exposed).** The 4.1
   port's `bounds(...).join('<br/>')` rendered the literal string as visible
   text (and screen-reader vocalized it, WCAG 1.3.1) for the standard
   cpu+memory shape. Replaced with `boundLines` (Fragment + `<br />` element,
   the PDB sibling idiom). TDD: `vpa-data-multi-resource-bounds-render-real-
   line-breaks` RED on the join (no `<br>` element; literal `<br/>` text
   present), GREEN on the element form. Verified: data tests 10/10 PASS.
3. **`VerticalPodAutoscalerData.tsx` — duplicate React keys ×2 (edge
   Minor).** Two containerPolicies with empty `containerName` (the valid
   default policy) and two conditions sharing a `type` both produced
   duplicate keys (`'' ?? i` keeps `''`). Composite keys
   `` `${i}:${…}` `` — unique by the index, content-stable.
4. **`backend/tests/services/test_k8s_client_verticalpodautoscalers.py` —
   3 new pins (verif gaps + red team).** (a) `…_maps_502_to_unreachable` —
   a transport error on the custom-object LIST maps to
   `ClusterUnreachableError` (the list body's `except ApiException` had no
   VPA-named test; deleting it passed all 12 VPA tests pre-fix). (b)
   `…_serves_served_version_not_hardcoded` — `get_crd_served →
   ("v1beta1", …)` is forwarded to the custom-object call (stub and
   assertion previously shared `"v1"`, so a hardcoded literal passed). (c)
   `…_cluster_scoped_revision_ignores_namespace` — a cluster-scoped CRD
   revision lists via `list_cluster_custom_object` (the scope-authority
   branch the VolumeSnapshot sibling pins; the red team flagged the
   hardcoded `"Namespaced"` stub). Verified: 9/9 PASS (was 6).
5. **`backend/tests/api/test_resources.py` — API-tier 502 + SAR call-
   absence.** `test_list_verticalpodautoscalers_502_on_unreachable` (new
   `vpa_unreachable` switch on `FakeK8s`, sibling idiom from
   `cilium_unreachable`; 502 `CLUSTER_UNREACHABLE`, the 500-body shape with
   no `items` never reaching the empty state) + `assert not getattr(
   fake_k8s, "vpa_ns_calls", [])` in the SAR-denied test (the docstring
   claimed "the SAR is asked BEFORE the read"; 8 sibling kinds pin it, VPA
   didn't). Verified: 7/7 PASS (was 6).
6. **`frontend/tests/views/vertical_pod_autoscalers.test.tsx` — list-error-
   state + `?? 'default'` fallback.** (a) A 403 body carries no `items`, so
   without the `queryFn` throw the page renders the empty state — pinned
   now (the only other-resource view missing the sibling test). (b)
   `defaults-to-default-namespace-when-none-selected` (selected cluster,
   `selectedNamespace: null` → fetches `?namespace=default`; sibling shape
   from `resource_quotas.test.tsx` — the spec lens noted the fallback
   preserved at `resources.py:281`, now pinned). Verified: list tests 9/9
   PASS (was 7).
7. **`frontend/e2e/ui-smoke.spec.ts:51` — stale SMOKE_STUB_ROUTES title
   pin (the spec Minor; the same finding class the resourcequota review
   rated Important).** The entry `title: 'VPAs'` asserted the sidebar nav
   label with `exact: true`, so a regression that renders an empty card
   (no route) would pass the smoke; no e2e assertion of the card title
   existed. Retargeted to `title: 'Vertical Pod Autoscaler List'` (the view's
   card title; the nav leaf `leaf('VPAs', …)` in `_nav.tsx` cannot satisfy an
   exact match) with the sibling comment block. This makes the list view's
   docstring e2e claim TRUE — no doc edit needed. Verified: e2e stub-routes
   sweep 1/1 PASS (7.8s) against the dev stack with the rebuilt + synced
   bundle (`task fe-build` + `task fe-sync`).
8. **`backend/app/api/resources.py` — orphaned VPA comment (standards
   Minor).** A later change (`ingressclass-gatewayclass-views`) inserted its
   own comment + entry between the 4-line VPA comment and the
   `verticalpodautoscalers` entry; the comment now reads as GatewayClass's
   documentation. Moved to sit directly above its entry.
9. **`VerticalPodAutoscalerData.tsx` — stale docstring (red team).** The
   header claimed the list view's name links were the sole producer of the
   `?name=&namespace=` query strings; post-migration identity arrives as
   props from ObjectRoute (the active ref) and the legacy `/data` redirect
   passes the query params through. Reworded.

Re-verification after the fixes: backend unit floor **916 passed**
(10 deselected; baseline 912 + the 4 new tests) with this review's files
ruff- and mypy-clean; frontend `tsc --noEmit` + eslint over all touched
files + full vitest suite green (520 tests; the only pre-existing noise is
the flaky `network_policies` deep-link test + SimpleBar/jsdom
`getComputedStyle` errors, both off-surface per the standards lens);
e2e stub-routes sweep 1/1.

## Parked (cross-cutting, owners named)

- **Edge: namespace-less active ref → all-N/A detail.** The data view's
  query is `enabled` on a non-empty namespace; a ref without one renders the
  table of `N/A` cells + an empty JSON block (query disabled, not an error
  state). Potential reachability only — both in-app ref writers carry a
  namespace (`openObject` from a row; `OldDataRedirect` backfills one), a
  hand-edited sessionStorage entry is the trigger. Same parking as the
  identical resourcequota/configmap edge finding.
- **Standards Minor: absence-sentinel drift.** The data view mixes `N/A`
  (metadata table) and `—` (Created via `formatTimestamp`) within one
  table; the PDB sibling splits metadata → `N/A`, spec/status → `—`. The
  4.1 port literal is documented in the view header; a cross-sibling
  alignment pass is a separate change.
- **A11y fleet ×3.** ObjectRoute list↔detail swaps with no focus
  management (WCAG 2.4.3); plain-div async states with no live region
  (4.1.3); the first TopMenu Back press is a visible no-op (3.2.5, AAA —
  `openObject`'s same-path push). All shared by every ADR-0040 kind; the
  VPA nameCell is byte-identical to the PDB sibling. Owners: the
  session-object-navigation / ObjectRoute change and an app-wide a11y pass.
- **Red team: ObjectRoute cross-tab deep link pins the detail.** The cached
  `incoming` ref survives `clearActiveRef`, so the breadcrumb back link
  no-ops until remount. Latent while sharing has no UI producer (the
  share-button removal `7ba9bf75` postdates this diff, shrinking the
  surface). Owner: the session-object-navigation change.
- **Red team: name-cell bold/aria-current is dead.** ObjectRoute renders
  the list only when no same-kind ref is active, so `selected` is always
  null while the list is mounted (fleet-identical in HPA/PDB/Service). Same
  treatment as the configmap R9 parking. Owner: the
  session-object-navigation change.
- **Red team: `kd_object_refs` grows unbounded per tab.** Every
  `openObject`/redirect/consume adds a token; only the active token is
  deleted (a per-tab sessionStorage leak, no correctness impact). Owner:
  the `objectRef` lib (session-object-navigation).
- **Verif fleet ×2.** (a) `expect(window.location.search).toBe('')` under
  MemoryRouter can never fail (jsdom URL untouched) — the R1
  URL-cleanliness half is unobserved in three views. (b) Per-kind App.tsx
  `ObjectRoute`/`OldDataRedirect` wiring is covered at path level only
  (Stub.test) — a kind-prop typo would hydrate a mismatched ref; the shared
  mechanics are tested through the `secret` kind in App.test. Both are
  fleet patterns; a harness-level pin is a separate change.
- **Security context: the XSS sink is pre-existing and repo-wide.** The
  one-place fix at `KubeDataTable` covers all ~20 consumer views; no
  per-view action is needed, and zero renderers return intentional HTML
  strings (red-team inventory of all 41 consumer views).

## Security (lense summary)

New endpoint rides the shared SAR-gated generic route: binding gate →
name/namespace allowlist (`fullmatch`) → SAR **before** the read with group
`autoscaling.k8s.io` (403 `RBAC_DENIED`; transport failure → 502 fail-
closed) → client call. CRD-absent → `[]` only after the SAR gate (no
auth bypass via an absent operator). The one finding is the stored XSS via
the shared DataTables cell sink, fixed at the sink (item 1); the
explicitly-focused full-object JSON block is element-escaped (no
`dangerouslySetInnerHTML` anywhere in the highlighter's dist). Session
transport unchanged (ADR-0025); no new dependencies (ADR-0020, air-gap
check green).

## TDD / Evidence Note

Batch execution (2026-10-29 storage batch) — tests and code co-committed
per task, same shape as the resourcequota record; the RED/GREEN audit is
N/A by the same class, with the exception of this review's own TDD:
`vpa-data-multi-resource-bounds-render-real-line-breaks` (RED on the 4.1
`join('<br/>')`, GREEN on the element form) and the security lens's live-
DOM XSS probe (a real `<img>` pre-fix, deleted after the run). Behaviour
coverage is complete: 18 scenarios in `acceptance.feature` all proven by
named tests at the current HEAD (spec lens), +10 tests/pins added by this
review (4 sink, 3 service, 1 API 502, 2 list). Process note (spec lens):
the spec zone appears in git history only via `7f249163` (the repo-wide
`.skillgrid` restore-from-backup) — spec-before-code in the current
history is an artifact of that documented wipe/restore, not a violation by
this change.

## Floor Note

The branch's committed floor is red through no fault of this change or its
review: `ruff check` (62 errors, 14 test/app files) and `mypy app` (66
errors, 14 files) fail identically with this review's 9 files stashed —
introduced by the ha-status window-closure commits `448db3d4`/`30ee933f`
that landed mid-review (e.g. `tests/test_ini_config.py` E501 ×13,
`app/api/groups.py` mypy ×30). This review's own files are ruff- and
mypy-clean. The ha-status gate record should note the debt.
