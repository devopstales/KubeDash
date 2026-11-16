# Code Review - HPA Views (List + Data)

**Change:** `2026-10-28-hpa-views` · **Reviewer:** 7-lens fan-out
(standards, spec, security, edge-cases, verification-gap, accessibility,
performance) + red team on the merged findings · **Gate date:** 2026-11-16

**Diff:** 4 commits - `0178df05` backend kind extension, `233e827c` list
view, `954e7a0b` data view, `3aabed9d` routes + stub removal - 12 files,
+1294/-1 (1430 diff lines), base `29ee7c8d`. The spec zone (briefing /
blueprint / adr / acceptance / NAVIGATION-SUPERSEDED) is excluded from
this review; the pre-generated diff at
`.skillgrid/meta/sdd/2026-10-28-hpa-views/review-diff` (gitignored) is
the read-only diff, and the lenses verified against the current tree
where the two differ (the ObjectRoute migration `89528a32` rewrote
`HorizontalPodAutoscalerData` URL-driven -> ref-driven after this diff;
the user format fix `61227de3` matched the Key/Value sub-tables to 4.1
wrapping).

**Tree:** `rebase`, HEAD `9dac4620` (the vpa-views review record). Work
tree at review time: clean except pre-existing unrelated WIP (AGENTS.md,
`.obsidian` noise, untracked `.DS_Store`/`.claude`). No uncommitted WIP
belonging to this change (all four commits are on the branch; the
post-diff commits touching the HPA surface - `61227de3`, `89528a32` -
belong to other changes).

## Verdict

**MET-WITH-FIXES.** 0 CRITICAL. 1 IMPORTANT (SAR group pinned to core -
the test protected the bug) + 1 confirmed availability bug (object-valued
legacy-annotation condition field unmounts the SPA, security-LOW) +
5 verification pins + 3 minors - all fixed in the companion code-zone
commit and re-verified at the floor below.

## Findings

### IMPORTANT - SAR group pinned to core (`""`); HorizontalPodAutoscaler is autoscaling

- **Location:** the `horizontalpodautoscalers` entry in `_KINDS`
  (backend/app/api/resources.py) - SAR group `""` (core) as-diffed and at
  HEAD. HPA is `autoscaling/v1` - its resource path is
  `/apis/autoscaling/v1/...` (the **autoscaling** group).
- **Mechanism:** `rbac.can(..., api_group)` omits the `group` key from
  the SelfSubjectAccessReview when the group is falsy (app/services/
  rbac.py) - K8s then defaults the SAR to the core group. A core-group
  SAR for `horizontalpodautoscalers` never matches an autoscaling grant:
  every user with the correct
  `apiGroups:["autoscaling"], resources:["horizontalpodautoscalers"]`
  grant got 403 `RBAC_DENIED`.
- **The test protected the bug:** `test_list_horizontalpodautoscalers_
  sar_denied` asserted the SAR tuple `(..., "")` - pinning the wrong
  group; it would have *failed* on the fix.
- **Demonstration (live, kind cluster):** as-diffed behaviour asks the
  core-group SAR -> 403 for the correctly-granted user; with group
  `"autoscaling"` the same request -> 200.
- **Fix:** group `"autoscaling"` in `_KINDS`; the test now pins
  `("list","horizontalpodautoscalers","team-a",None,"autoscaling")`.
  Same class as the 2026-11-05 storageclasses review fix.

### IMPORTANT (security-LOW, availability) - object-valued legacy-annotation condition field unmounts the SPA

- **Location:** the Conditions table (frontend/src/views/OtherResource/
  HorizontalPodAutoscalerData.tsx) - `conditionsOf()` passed the parsed
  `autoscaling.alpha.kubernetes.io/conditions` annotation through with an
  inline `c as {type?: string, ...}` cast; the row rendered
  `cond?.type ?? 'N/A'` directly as a React child.
- **Mechanism:** the annotation is untrusted, user-written cluster
  metadata - a field may hold an object (e.g. `[{"type": {}}]`). `?? 'N/A'`
  does not catch objects; React throws "Objects are not valid as a React
  child", and the app has **no error boundary** (createRoot -> `<App/>`,
  frontend/src/index.tsx) - the whole SPA unmounts (white screen,
  re-crashes on revisit; the object ref persists in session state).
- **Fix:** `normalizeCond` + `scalarOf` coerce every condition field to a
  scalar (string/number -> string, anything else -> the row's `N/A`) for
  both the `status.conditions` and the annotation path; the render uses
  the normalized shape. Pinned by the new
  `data-conditions-legacy-object-field` test (fixture
  `[{type:{},status:'True'}]` -> cells `N/A / True / N/A / N/A / N/A`,
  full render completes).

### Verification pins (5) - designated but unpinned, now pinned

1. **e2e card-title contract** (spec lens IMPORTANT):
   `ui-smoke.spec.ts` line 50 still carried the stub-era
   `title: 'HPAs'` (pre-existing entry `c6653a24`, untouched by the four
   commits) while the shipped view docstring *claims* the e2e asserts that
   string with `exact: true` - the sidebar label cannot exact-match the
   card title, so the claim was false and the route registration was
   unpinned. Retargeted to `'Horizontal Pod Autoscaler List'` (the VPA
   pattern, `edce3865`); the docstring is then true.
2. **SAR-denied acceptance Then-clauses** (verification-gap lens): the
   scenario designates "403 naming the horizontalpodautoscalers resource"
   + "the K8s client list call was never made" - the test asserted
   neither. Added `assert "horizontalpodautoscalers" in
   error["message"]` + `assert not getattr(fake_k8s, "hpa_ns_calls", [])`
   (the resourcequota-review pin pattern; the sibling
   `test_apply_sar_denied_is_atomic_before_apply` demonstrates it in-repo).
3. **camelCase legacy `lastTransitionTime`** (verification-gap lens): both
   fixtures used the snake_case to_dict shape; the live 4.1 annotation
   shape is camelCase (Go JSON tag) and only the fallback branch renders
   it. New `data-conditions-legacy-camelcase-timestamp` fixture asserts
   the timestamp in the conditions table cell (scoped to the table - the
   JSON block would also match).
4. **absent-field fallback literals** (verification-gap lens): every
   fixture fully populated metadata+spec+status; the `?? '—'` /
   `?? 'UNKNOWN'` literals were unpinned, weaker than sibling VPA
   (`vpa-data-missing-policy`) and PDB (`pdb-data-missing-status`). New
   `data-missing-status` fixture (fresh HPA, `status: {}`) asserts
   `— Current / — Desired` and `UNKNOWN / 80 %`.
5. **object-valued condition field** - the pin for the availability fix
   above.

### Minors (3) - all fixed

1. **Spec-zone gap** (spec lens): `61227de3`'s 4.1-parity wrapping (50/50
   Key/Value columns, no `text-break`, responsive scroll) was recorded in
   commit + docstring + test but had no spec-zone entry (contrast the
   `46929a10` trim, which got OVERRIDDEN clauses). Added to adr.md as a
   ratified deviation.
2. **Stale test comment** (spec lens): `horizontal_pod_autoscalers.
   test.tsx` "Name cell also carries the ADR-0040 share button" - the
   share was removed in `7ba9bf75`; test logic was unaffected. Rewritten
   to the ObjectRoute ref-driven open.
3. **Stale "core-API model" wording**: the `k8s_client.py` comment and the
   list-test fixture comment called the HPA model "a generated core-API
   model"; the data-view docstring said "autoscaling/v1, core,
   snake_case". HPA is autoscaling, not core - all three now say what is
   true (the `k8s_client.py` read call was also re-wrapped for the line
   limit).

## Lens Summary

- **Standards:** clean - no findings (module/seam/layering per the
  ratified `_KINDS` + view-folder conventions).
- **Spec:** MET-WITH-FIXES - all **17** BDD scenarios in
  `acceptance.feature` PASS against the current tree (6+6 backend, 7+7
  frontend + Stub, 7 App R7-redirect tests, all green); 3 scenarios carry
  recorded ADR-0040 deviations (list data-links as button+ref with the
  legacy URL via OldDataRedirect pinned in App.test.tsx; data identity
  via ref not URL; routes wired as ObjectRoute + one-shot /data
  redirect; the nav leaf is byte-identical - `git diff` on `_nav.tsx` = 0
  lines). Scope creep noted, no conflict: `codeTagProps` on the JSON
  block (in-diff, not in the blueprint Global Constraints), the
  camelCase fallback (justified by the live 4.1 annotation shape), the
  index signature on `HorizontalPodAutoscalerItem` (de minimis).
- **Security:** 1 LOW (confirmed) - the object-valued condition field
  above (availability only). Verified safe: JSON-block XSS (hljs
  `escapeHTML` unconditional in the vendored 10.7.3 core.js); string
  cells through the KubeDataTable `escapeString` sink (the `edce3865`
  shared-sink fix verified present at HEAD); name/namespace injection
  (DNS-label/subdomain regexes enforced before the SAR, kind
  exact-match whitelist, constant `_GETTERS` table); the SAR cache key
  carries a distinct namespace segment and the binding gate precedes it;
  data-view identity via the session ref (encodeURIComponent fetch URL,
  no credentials in storage); no new dependencies (air-gap holds).
- **Edge cases:** no findings (malformed/absent annotation -> `[]` /
  "No conditions", never throws; not-found -> pinned copy, no error
  styling; missing name -> no fetch).
- **Verification gap:** the SAR-group finding (the test pinned the bug -
  "broken-verification" class) + the five pins above; the real
  `to_dict` wire shape is exercised only via kind integration tests
  (none for HPA - the mock-only convention ratified across sibling
  kinds).
- **Accessibility:** 5 findings, ALL fleet-wide convention (verbatim
  ratified sibling pattern; none newly exposed by this diff) - parked:
  focus loss on the ObjectRoute list->detail swap, `text-danger`
  3.69:1 light / 4.13:1 dark, page heading starting at h5 with no h1 in
  the shell, loading/error/empty divs without live regions, the btn-sm
  p-0 name button at ~21px. Verified clean: native-button nameCell,
  breadcrumb aria-label + real back link, DataTables search input
  labelled via label/for, `th scope="row"` definition tables,
  text-muted 5.1:1 / text-primary 5.65:1, the anOldHope dark JSON theme
  self-contained.
- **Performance:** no findings - list = 1 DB binding + 1 SAR cache read +
  1 K8s list call (zero per-row reads, pooled client); no pagination =
  verbatim ratified sibling pattern; detail = single read by name;
  frontend O(n) toRow, DataTables pageLength 25 in-place, hljs per-render
  on a ~1-5 KB object, lazy routes, deduped JSON chunk.
- **Red team (last, on the merged findings):** no downgrades - the fix
  list above is the post-red-team set.

## Floor / Verification (all re-run at the gate)

- **Backend unit:** `uv run pytest -m "not integration"` - **916
  passed**, 10 deselected.
- **ruff:** 61 errors branch-wide - all in files this review did not
  touch (groups, kubeconfig, permissions, CRD, limitrange, metrics,
  ini-config tests); this review's files (`resources.py`,
  `k8s_client.py`, `test_resources.py`) are clean. Pre-existing branch
  floor, owned by those changes.
- **mypy:** 66 errors at HEAD, 66 after the fix (no new; stash-verified
  in this review) - pre-existing branch floor.
- **Frontend:** `tsc --noEmit` clean; eslint 0 errors (4 "file ignored"
  warnings for `tests/e2e` - config scope); `fe-check` (air-gap) green.
  Full vitest: **530/530 tests passed** in every run (77 files). 4
  unhandled errors (vitest exit 1) originate from files this review did
  NOT modify - `Clusters.test.tsx` x3, `gateway_api_data.test.tsx` x1 -
  and reproduce in isolated runs of those two files; the HPA files pass
  isolated with zero errors; an earlier full run this session (pre-fix)
  exited 0 on the same files. Load-sensitive unhandled-rejection class,
  pre-existing (machine under load during the gate).
- **e2e:** `task e2e` - **20/20 passed**, including the retargeted
  `Horizontal Pod Autoscaler List` title assertion and the real-routes
  sweep. Environment note (not this change): the dev-stack backend was
  running stale code from 2026-11-15 11:03 (before the ha-status
  `warnings` schema field landed at `448db3d4` 13:09) - restarted via
  `task backend-stack-run` equivalent before the gate; the kind
  `csi-provisioner` container is in an Error loop (32 restarts, exit
  255 - pre-existing churn) and does not affect the e2e read-only
  assertions.

## Parked (cross-cutting, owners named)

- **a11y fleet x5** (above) - same pattern on LimitRange / PDB / VPA /
  ResourceQuota; owner: a fleet a11y pass, not per-kind fixes.
- **Gherkin wording** - the sar-denied scenario's Given says "(core,
  namespace team-a)"; HPA is autoscaling. Spec zone stays frozen; the
  deviation is recorded in adr.md (ADR-0004 row).
- **Real `to_dict` wire shape** - mock-only verification is the ratified
  sibling-kind convention; a kind integration test creating a real HPA
  would settle the snake_case wire shape.
- **Branch lint floors** - 61 ruff / 66 mypy pre-existing reds (other
  changes' files) - branch-owner concern at rebase.
- **kind `csi-provisioner` Error loop** - dev-env quirk (exit 255, 32
  restarts over 7 days); dynamic provisioning only - the e2e assertions
  read pre-existing objects.

## TDD / Evidence Note

Batch execution (2026-10-29, the other-resource batch) - tests and code
co-committed per task; the execution progress ledger was not retained
(the sibling pvc-views / resourcequota-views spec zones show the same
co-commit batch shape; the batch QA gate was PASS per state.yaml), so
the RED/GREEN audit is N/A by the same class. Spec-before-code holds
(spec 2026-10-28, code 2026-10-29; the original spec commit is
unrecoverable - the 2026-11-12 `.skillgrid` wipe `7f249163` is a history
artifact). Behaviour coverage is complete: all 17 scenarios in
`acceptance.feature` proven by named tests at the current HEAD (spec
lens), +5 verification pins added by this review.
