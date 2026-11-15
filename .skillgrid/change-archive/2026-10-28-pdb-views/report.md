# Report — PodDisruptionBudget Views (List + Data)

**Change:** `2026-10-28-pdb-views` (TASK-048) · **Gate:** batch QA 2026-10-29 + ship re-verification 2026-11-15 at the integrated tip (`6b9d8f16`)
**Original gate:** batch-of-6 QA 2026-10-29 — **PASS** at tip `aead16a7`; record: `.skillgrid/change-specs/2026-10-28-other-resource-views/qa-report.md` (batch entry #3, TASK-048).
**Gate history:** executed 2026-10-28/29 (4 code commits `5f1f9244`/`7a1ab3a5`/`305a44c6`/`7b3e35be`) → batch QA PASS 2026-10-29 (`aead16a7`, re-executed floor) → ADR-0040 ObjectRoute migration (`89528a32`, separate change `2026-10-29-session-object-navigation` — rewrote the data view URL-driven → ref-driven) → 7-lens + red-team review 2026-11-13 (PASS with fixes, 0 CRITICAL; fixes at `40df5929` + `6b9d8f16`, record `review.md`) → **ship 2026-11-15**: integration floor re-run on the integrated tip (this report).
**Integration:** kept branch `rebase` (repo rule: the ship phase does not merge into `main` — the work branch is the deliverable and the rollback unit).
**Effective tier:** T1 (blueprint header) — additive view pair on the existing generic `/resources` route; `low-risk` classification floor (L1 + runtime verification) met and exceeded (batch gate, review, and this re-verification all ran at T2 evidence practice).
**Quality config:** `quality:`/`security:`/`duplication:` blocks absent from `.skillgrid/config.yaml`; `testing:` defines runner + layers + `tdd: true`. Gates ran per the blueprint Verification Floor + AGENTS.md commands (repo QA practice; coverage % untracked, no coverage command configured).

## Test Plan

### Risk Ranking

- **P0** (production/data): R1 list endpoint contract (200 / `kind: poddisruptionbudgets` / cluster + to_dict items / SAR-before-client on `policy` group + query ns / 403 `RBAC_DENIED` names the resource / binding 404 / all-namespaces branch / singular `poddisruptionbudget` rejected), R2 `?name=` lookup (0/1-item, `[]` on miss). A broken read or wrong SAR group fails every PDB consumer and the Min/Max/Allowed Disruptions columns.
- **P1** (experience): R3 list rendering (title EXACTLY `Pod Disruption Budget List`, exactly-one min/max certainty rule, missing-status `—`, pinned states), R4 data rendering (single fetch, CTable + Status + Conditions tables, JSON block, not-found as state, missing-name error), R5 routing / stub removal / `_nav.tsx` unchanged.

### Plan — scenario → named test (all ran PASS at the integrated tip)

| # | Behavior | Scenario | Named test (layer) | Status |
|---|----------|----------|--------------------|--------|
| 1 | List 200, kind, to_dict, ns forwarded | poddisruptionbudgets-list-200-in-namespace | `test_list_poddisruptionbudgets_200_in_namespace` (API) + service `test_list_pod_disruption_budgets_in_namespace` (unit) | PASS |
| 2 | All-namespaces branch (no `?namespace=`) | poddisruptionbudgets-list-all-namespaces-without-param | `test_list_poddisruptionbudgets_all_namespaces_without_param` (API, FakeK8s receives `None`, team-b distinguisher) + service all-ns test | PASS |
| 3 | SAR deny 403, client call absent | poddisruptionbudgets-sar-denied | `test_list_poddisruptionbudgets_sar_denied` (SAR tuple `("list","poddisruptionbudgets","team-a",None,"policy")` + `pdb_ns_calls` absent — the review pin F2) | PASS |
| 4 | Binding gate 404 | poddisruptionbudgets-binding-404 | `test_poddisruptionbudgets_binding_404` (API) | PASS |
| 5 | Singular kind rejected | poddisruptionbudget-kind-singular-rejected | `test_poddisruptionbudget_kind_singular_rejected` (API) | PASS |
| 6 | `?name=` hit / miss (0/1-item, `[]`) | poddisruptionbudgets-get-by-name | `test_list_poddisruptionbudgets_get_by_name` (API) + service hit/404 (hit test pins the `(name, namespace)` arg order — the review pin F3) | PASS |
| 7 | List rows, fetch URL, ns scoping | pdb-list-renders-rows-with-data-links | `list-renders-pdb-rows-with-data-links` (RTL/MSW, exact path + `team-a`) — DEVIATION: name cell is an openObject button, not a link (ADR-0040, behavior held) | PASS |
| 8 | Exactly-one min/max certainty rule | pdb-list-min-max-cells | `list-min-max-cells` (exact cell triples, absent one `—`) | PASS |
| 9 | Missing status → `—` (fresh PDB) | pdb-list-missing-status | `list-missing-status` (4.1 would UndefinedError) | PASS |
| 10 | Empty list state | pdb-list-empty-state | `list-empty-state` (+ no-cluster + error states pinned in the same view) | PASS |
| 11 | Data: single fetch, CTable, Status, Conditions, JSON | pdb-data-renders-detail | `data-renders-detail` (pins EXACTLY one request; loading arrives via the ADR-0040 ref) | PASS |
| 12 | Selector + eviction policy rows | pdb-data-selector-and-eviction-policy | `data-selector-and-eviction-policy` (match_labels lines; `unhealthy_pod_eviction_policy` string) | PASS |
| 13 | Miss = not-found STATE; missing name | pdb-data-not-found-state + pdb-data-missing-name | `data-not-found-state` + `data-missing-name` (pinned copies, no `.text-danger`) | PASS |
| 14 | Stub removed, routes wired, e2e title, nav unchanged | pdb-stub-removed-and-routes-wired | `Stub.test.tsx` + `ui-smoke.spec.ts` SMOKE_STUB_ROUTES entry (retargeted to the card title `Pod Disruption Budget List` — the review pin F1; e2e leg 17/17) + commit scope (`_nav.tsx` absent from the diff) — DEVIATION: `/data` route is OldDataRedirect R7 (ADR-0040) | PASS (e2e 17/17) |
| 15 | R9 active-ref bold (never a param) | (R9, added by review) | `bolds-the-opened-pdb-from-the-active-ref` (the review pin F4) | PASS |
| 16 | `?? 'default'` namespace fallback | (R1 delta, added by review) | `defaults-to-default-namespace-when-none-selected` (the review pin F5) | PASS |

## Traceability

15/15 scenarios in `acceptance.feature` mapped to named tests at the current HEAD (spec lens, review 2026-11-13): 13 PASS + 2 DEVIATION — both the recorded ADR-0040 navigation replacement (URL-driven `?name=&namespace=` → ref-driven clean route + one-shot redirect), no missing/partial scope creep. No UNTESTED, no FAILING, no PARTIAL. The review added 5 verification pins (SAR call-absence, getter arg-order, R9 bold, `?? 'default'`, e2e title retarget) — all now in the suite (rows 3, 6, 14, 15, 16).

## TDD Evidence

Batch execution 2026-10-28/29 (TASK-048 T1–T4) — tests and code co-committed per task; the batch traceability recorded 24/24 task units OK (RED before GREEN per task, commit hashes resolve) across the six changes, and the execution progress ledger was not retained (sibling spec zones show the same co-commit batch shape), so a per-commit RED/GREEN audit is N/A by the same class as the batch's.

## Review (2026-11-13)

7-lens fan-out (standards/spec/security/edge/verif-gap/a11y/performance) + red team — **PASS with fixes, 0 CRITICAL** (full record: `review.md`). Fixed: F1 stale e2e SMOKE_STUB_ROUTES title retargeted to the view's card title (4-lens corroboration); F2 SAR-denied client-call-absence pin + lazy fake call log; F3 getter `(name, namespace)` arg-order pin; F4 R9 bold-from-active-ref test; F5 `?? 'default'` fetch-URL test; M2 stale "share button" comment. The F1–F5 hunks landed in the parallel session's `40df5929` (shared working tree — its broad `git add` swept the in-flight hunks in); M2 + this record's review commit at `6b9d8f16`. Parked with named owners (`review.md`): F6 kind-integration backstop + demo PDB seed (kind tier is a carried broken baseline; no fleet kind has one), F7 namespace-less-ref stuck data page (guard line-for-line identical to `ResourceQuotaData`; all legit ref writers set namespace), M1 `window.location.search` tautology (fleet-shipped pattern, `resource_quotas.test.tsx:146`). Dropped: F8 eviction-policy `[]string` premise (vendored client types `unhealthy_pod_eviction_policy` `Optional[StrictStr]` — a string).

## Findings

- 0 CRITICAL (gate + review).
- 5 fixed at the gate (F1–F5) + 1 doc fix (M2) — each re-verified by this ship's floor run (backend 12/12 `-k poddisruptionbudget`; e2e includes the retargeted title).
- Parked (out of scope, owners named in `review.md`): F6, F7, M1 + the a11y fleet convention (plain-div states, h5 headings, nameless tables — lowest severity, verbatim from the sibling views).
- Carried baselines (not findings): the first backend floor run of this ship was interrupted by the dev-stack Postgres restart (started concurrently); the re-run below is the record. The one frontend full-suite failure (`network_policies.test.tsx > route-consumes-incoming-meta-and-renders-policy-detail`) is a confirmed flake — 8/8 standalone; this change's diff shares zero files with network_policies.

## Gate Decision

**PASS** (ship re-verification, integrated tree `6b9d8f16`).

Basis: batch gate PASS 2026-10-29 (re-executed floor; `_nav.tsx` byte-identical; zero dependency-file diff) + review 2026-11-13 PASS-with-fixes with every fix re-verified at the gate + this ship re-verification on the integrated tip:

- backend `uv run pytest -m "not integration" -q` (3:49): **902 passed, 10 deselected, 0 failed**; this change's own surface 12/12 (`-k poddisruptionbudget`)
- frontend `corepack pnpm test` (full, 87s): **509 passed, 1 failed** — the flake named in Findings (8/8 standalone); this change's own surface 17/17 (pod_disruption_budgets 9 + pod_disruption_budget_data 5 + Stub 3)
- e2e `playwright test e2e/ui-smoke.spec.ts` (full, dev stack live, kind + demo PDB fixture): **17/17 PASS** (44.4s) — includes the retargeted `Pod Disruption Budget List` title assertion on the real route
- `task fe-build` up to date (last build `40df5929`-verified; only test-file + markdown changes since) + `task fe-check` (air-gap bundle assertion) green
- `ruff check` + `ruff format --check` clean on the changed backend test files

No MISSING_RED/STALE (N/A by class, above). No CRITICAL findings. No human override.

## Security Audit

Read-only kind on the existing SAR-gated generic route (`policy` group); no new endpoints, trust boundaries, config, or dependencies (`package.json`/`pnpm-lock.yaml`/`pyproject.toml`/`uv.lock` untouched by the 4 commits). Untrusted query data (`name`/`namespace`) validated by fullmatch regexes before the typed SDK (422 on failure); all k8s-derived values render through React's HTML escaping; the JSON block is `JSON.stringify` inside the hljs `json` grammar — no `dangerouslySetInnerHTML` in either view. Air-gap: no new external references (the `fe-check` bundle assertion holds).

---
## Final-State Facts
(reflect)
...
(reflect)
[retro sections filled in by the reflect phase]
