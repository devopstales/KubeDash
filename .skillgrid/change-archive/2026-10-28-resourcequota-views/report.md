# Report — ResourceQuota Views (List + Data)

**Change:** `2026-10-28-resourcequota-views` (TASK-047) · **Gate:** batch
QA 2026-10-29 + ship re-verification 2026-11-13 at the integrated tip
(`2f75a5f9` + `c0bcad59`)
**Original gate:** batch-of-6 QA 2026-10-29 — **PASS** at tip `aead16a7`;
record: `.skillgrid/change-specs/2026-10-28-other-resource-views/qa-report.md`
(batch entry #2, TASK-047).
**Gate history:** executed 2026-10-28 (4 code commits `783cff0a`/`1448a3f2`/
`d3d4067a`/`0b3b97bf`) → batch QA PASS 2026-10-29 (`aead16a7`, re-executed
floor) → ADR-0040 ObjectRoute migration (`89528a32`, separate change
`2026-10-29-session-object-navigation`, QA PASS 2026-11-04/05 — rewrote the
data view URL-driven → ref-driven) → 7-lens + red-team review 2026-11-13
(MET-WITH-FIXES, 0 CRITICAL; fixes at `2f75a5f9`, record `review.md`) →
**ship 2026-11-13**: integration floor re-run on the integrated tip (this
report).
**Integration:** kept branch `rebase` (repo rule: the ship phase does not
merge into `main` — the work branch is the deliverable and the rollback
unit).
**Effective tier:** T1 (blueprint header) — additive view pair on the
existing generic `/resources` route; `low-risk` classification floor (L1 +
runtime verification) met and exceeded (batch gate, review, and this
re-verification all ran at T2 evidence practice).
**Quality config:** `quality:`/`security:`/`duplication:` blocks absent from
`.skillgrid/config.yaml`; `testing:` defines runner + layers + `tdd: true`.
Gates ran per the blueprint Verification Floor + AGENTS.md commands (repo QA
practice; coverage % untracked, no coverage command configured).

## Test Plan

### Risk Ranking

- **P0** (production/data): R1 list endpoint contract (200 /
  `kind: resourcequotas` / cluster + to_dict items / SAR-before-client on
  core group `""` + query ns / 403 `RBAC_DENIED` names the resource /
  binding 404 / all-namespaces branch / singular `resourcequota` rejected),
  R2 `?name=` lookup (0/1-item, `[]` on miss, non-404 →
  `ClusterUnreachableError`). A broken read or wrong SAR group fails every
  ResourceQuota consumer and the Request/Limit columns.
- **P1** (experience): R3 list rendering (title EXACTLY `Resource Quota
  List`, 4.1's four dimensions as `used / hard`, missing-key `—`, pinned
  states), R4 data rendering (single fetch, CTable + Status table, JSON
  block, not-found as state, missing-name error), R5 routing / stub
  removal / `_nav.tsx` unchanged.

### Plan — scenario → named test (all ran PASS at the integrated tip)

| # | Behavior | Scenario | Named test (layer) | Status |
|---|----------|----------|--------------------|--------|
| 1 | List 200, kind, to_dict, ns forwarded | resourcequotas-list-200 | `test_list_resourcequotas_200_in_namespace` (API) + service `test_list_resource_quotas_in_namespace` (unit) | PASS |
| 2 | All-namespaces branch (no `?namespace=`) | resourcequotas-list-all-namespaces | `test_list_resourcequotas_all_namespaces_without_param` (API, FakeK8s receives `None`) + service all-ns test | PASS |
| 3 | SAR deny 403, client call absent | resourcequotas-sar-denied | `test_list_resourcequotas_sar_denied` (SAR tuple `("list","resourcequotas","team-a",None,"")` recorded + `resourcequota_ns_calls` absent — the review pin) | PASS |
| 4 | Binding gate 404 | resourcequotas-binding-404 | `test_resourcequotas_binding_404` (API) | PASS |
| 5 | Singular kind rejected | resourcequota-kind-singular-rejected | `test_resourcequota_kind_singular_rejected` (API) | PASS |
| 6 | `?name=` hit / miss (0/1-item, `[]`) | resourcequotas-get-by-name | `test_list_resourcequotas_get_by_name` (API) + service hit/404 tests (hit test pins the `(name, namespace)` arg order — the review pin) | PASS |
| 7 | Transport 500 → ClusterUnreachableError | R1 client contract | service `test_list_resource_quotas_maps_500_to_unreachable` + `test_get_resource_quota_other_api_error_maps_to_unreachable` | PASS |
| 8 | List rows, fetch URL, ns scoping | resourcequota-list-renders-rows | `list-renders-quota-rows` (RTL/MSW: exact path + `team-a` header) | PASS |
| 9 | R9 active-ref bold (never a param) | resourcequota-list-active-ref-bold | `bolds-the-opened-resource-quota-from-the-active-ref` (the review pin, sibling `secrets` shape) | PASS |
| 10 | `?? 'default'` namespace fallback | resourcequota-list-default-namespace | `defaults-to-default-namespace-when-none-selected` (the review pin, sibling `secrets` shape) | PASS |
| 11 | Empty list state | resourcequota-list-empty-state | `list-empty-state` (pinned copy, no error style) | PASS |
| 12 | Data: single fetch, CTable, Status, JSON | resourcequota-data-renders-detail | `data-renders-detail` (pins EXACTLY one request) | PASS |
| 13 | Miss = not-found STATE; missing name | resourcequota-data-not-found + missing-name | `data-not-found-state` + `data-missing-name` (pinned copies, no `.text-danger`) | PASS |
| 14 | Stub removed, routes wired, e2e title, nav unchanged | resourcequota-stub-removed-and-routes-wired | `Stub.test.tsx` + `ui-smoke.spec.ts` SMOKE_STUB_ROUTES entry (retargeted to the card title `Resource Quota List` — the review pin; e2e leg ran 1/1) + commit scope (`_nav.tsx` absent) | PASS (e2e 17/17) |

## Traceability

14/14 scenarios in `acceptance.feature` (13 body + 1 trace) mapped to named
tests at the current HEAD (spec lens, review 2026-11-13): 11 PASS + 3
DEVIATION — all three are the recorded ADR-0040 navigation replacement
(URL-driven `/data?name=&namespace=` → ref-driven clean route), no
missing/partial scope creep; the trimAnnotations deviation stays accurate
(grep count 0). No UNTESTED, no FAILING, no PARTIAL. The review added 5
verification pins (SAR call-absence, getter arg-order, R9 bold, `?? 'default'`,
e2e title retarget).

## TDD Evidence

Batch execution 2026-10-28 (TASK-047 T1–T4) — tests and code co-committed
per task; the batch traceability recorded 24/24 task units OK (RED before
GREEN per task, commit hashes resolve) across the six changes, and the
execution progress ledger was not retained (sibling spec zones show the same
co-commit batch shape), so a per-commit RED/GREEN audit is N/A by the same
class as the batch's.

## Review (2026-11-13)

7-lens fan-out (standards/spec/security/edge/verif-gap/a11y/performance) +
red team — **MET-WITH-FIXES, 0 CRITICAL** (full record: `review.md`).
Fixed at the gate (`2f75a5f9`): stale e2e SMOKE_STUB_ROUTES title retargeted
to the view's card title; SAR-denied client-call-absence assert + lazy fake
call log; `get_resource_quota` arg-order pin; +2 view tests (R9 bold,
`?? 'default'`); pre-existing ha-status-owned tsc red (039f7d89) fixed via
`querySelector<HTMLMetaElement>`. Parked with named owners: R9-bold-
unreachable + browser-back no-op (ObjectRoute / session-object-navigation),
a11y fleet convention ×4, shared-route `?name=` default coercion,
namespace-less-ref phantom N/A detail, fixture/constant dedup,
kind-integration backstop + demo data, `/data` sweep note, ADR-0022 `stub`
row (systemic FYI).

## Findings

- 0 CRITICAL (gate + review).
- 1 IMPORTANT fixed at the gate (stale e2e title pin + its false docstring
  claim — multi-lens: Standards + VerifGap).
- Parked (out of scope, owners named in `review.md`): the batch's F5 (e2e
  REAL_ROUTES covers only limit-range for the six kinds — fleet follow-up)
  and F6 (stale `/other-resource/priorityclass` SMOKE entry — the
  resourcequota entry is fixed by this change; priorityclass remains), the
  a11y fleet convention, and the session-object-navigation-owned ObjectRoute
  items.
- Carried baselines (not findings): the pre-existing frontend failures
  owned by the in-flight users/groups pages (W007) and the ha-status-page
  change (its own gate) — adjudicated below in the Gate Decision.

## Gate Decision

**PASS** (ship re-verification, integrated tree `2f75a5f9` + `c0bcad59`).

Basis: batch gate PASS 2026-10-29 (re-executed floor: backend 532 passed;
targeted frontend 70/70; `fe-build` + `fe-check` green; `_nav.tsx`
byte-identical; zero dependency-file diff) + review 2026-11-13
MET-WITH-FIXES with every fix re-verified at the gate + this ship
re-verification on the integrated tip:

- backend `uv run pytest -m "not integration" -q` (4m47s): **884 passed,
  10 deselected, 15 red** — 11 setup ERROR + 4 FAILED, ALL the same
  `ConfigError: missing required config 'admin_kubeconfig'` in
  `test_security_headers.py` (8) / `test_static.py` (3) /
  `test_ini_config.py` (4 — order-dependent: the file is 18/18 green
  standalone) — see adjudication; this change's own surface 12/12
  (`-k resourcequota`)
- frontend `corepack pnpm test` (full, 88s): **505 passed, 1 failed** —
  `Clusters.test.tsx > admin creates a cluster from the add dialog` (see
  adjudication); this change's own surface 18/18 (resource_quotas /
  resource_quota_data / Stub)
- e2e `playwright test e2e/ui-smoke.spec.ts` (full, dev stack live): **17/17
  PASS** (59.3s) — includes the retargeted `Resource Quota List` title
  assertion on the real route
- `tsc --noEmit` clean (branch-wide, after the review's tsc fix); eslint
  over all sources clean (`--ignore-pattern dist`; the full `pnpm lint` red
  is the gitignored local `dist/` only — CI lints pre-build)
- `ruff check` clean on the changed backend files

**Red-set adjudication (none owned by this change).** All 16 red items
(15 backend + 1 frontend) trace to the in-flight `2026-11-10-ha-status-page`
change (phase review, its own gate open, W042-W045): (a) the 11
`admin_kubeconfig` setup errors — `admin_kubeconfig` is a long-standing
REQUIRED key (ADR-0021/0028); the app-fixture tests in
`test_security_headers.py`/`test_static.py` build the app without the
`config_overrides` supply that `tests/conftest.py:78` documents; the error
count is consistent with the ha-status gate's own "888 passed" floor record
(888 + 11 = the current 899 total), so the errors pre-date this ship and
post-date the 2026-10-29 batch gate (which ran 532/532 with zero errors) —
i.e., introduced during ha-status development (e00024fc/959a3833/6963fc83
config + clusters work), not by any of this change's 4 commits (which touch
only the resourcequotas kind + views + their tests). (b) the 4
`test_ini_config.py` failures — order-dependent flakes in the same config
area (18/18 standalone). (c) the 1 vitest failure — `Clusters.test.tsx` is
the ha-status WIP test committed in `959a3833` (clusters 4.1 parity),
already flagged out-of-scope/ha-status-owned by the 2026-11-12 configmap
re-verification. Precedent: the configmap (2026-11-12) and runtimeclass
(2026-11-12/13) changes shipped on this branch with the same named, owned,
pre-existing red set; the failures are tracked by the ha-status change's own
gate. This change's diff shares zero files with the red set.

No MISSING_RED/STALE (N/A by class, above). No CRITICAL findings. No human
override.

## Security Audit

Read-only kind on the existing SAR-gated generic route (core group `""`);
no new endpoints, trust boundaries, config, or dependencies
(`package.json`/`pnpm-lock.yaml`/`pyproject.toml`/`uv.lock` untouched by the
4 commits). Server-provided data renders through React's HTML escaping; the
JSON block is `JSON.stringify` inside a `<pre>` — no `dangerouslySetInnerHTML`
anywhere in the two views. Air-gap: no new external references (the
`fe-check` bundle assertion holds — bundle unchanged by this ship's test- and
e2e-only changes).

---
## Final-State Facts
(reflect)
...
(reflect)
[retro sections filled in by the reflect phase]
