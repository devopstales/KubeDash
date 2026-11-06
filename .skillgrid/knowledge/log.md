# KubeDash — Knowledge Base Log

> Journal of knowledge-base writes, newest last. Every write appends here in
> the same edit as the concept + `index.md`.

## 2026-10-26

- Bundle restructured: `.skillgrid/artifacts/` → `.skillgrid/knowledge/`.
  - 13 ADR files (0014..0026) → `decisions/`
  - `01-business-terms.md`, `02-technical-terms.md` → `glossary/`
  - Created `invariants/`, `workflows/`, `reference/` (empty)
  - Created `index.md`, `log.md`, `reverse-index.md`
  - `config.yaml` `conventions.artifacts` → `.skillgrid/knowledge`
  - Path references updated: `AGENTS.md`, `ARCHITECTURE.md` (§2 tree, §12, §13, header), `ASSUMPTIONS.md` (header + LOCKED paths). Archive/spec/backlog files kept as history.

## 2026-11-04 — decisions/04-adr-0040-session-object-navigation.md amended

- ADR-0040 amended (user decision): the cross-tab deep-link token is now
  delivered through the server session (SPA-fallback 303 POST bounce +
  `obj_incoming:<sub>` Redis TTL-60s stash + one-shot
  `<meta name="kd-object-incoming">` injection) instead of `?o=` in the
  document URL — proven non-functional in a real browser by the QA gate
  (2026-11-03, FAIL). R10 carved to "no new API endpoint / migration /
  cookie"; token entropy 32 → 64 bits.
- New module: `app/core/object_handoff.py` (SPA-fallback handoff plumbing).
- `index.md`: ADR-0040 row added (index rows for ADR-0027..0039 remain
  open — pre-existing gap, not backfilled here).

## 2026-11-06 — bundle initialized from current source and tests

- **Restored** the working-tree deletion of `.skillgrid/knowledge/`
  (`git restore` — all 24 tracked files returned; content unchanged).
- **Backfilled ADR-0001..0013** (13 new files in `decisions/`, open
  task per the 2026-10-17 onboarding notes): authored from
  `ARCHITECTURE.md` §12 + §3–§7, verified against current source
  2026-11-06 (`backfilled: 2026-11-06` in each status block). Notable
  records inside: ADR-0004 carries the 2026-10-21 cache-key amendment;
  ADR-0010 records the base-structure deferral (no watch-based module
  exists yet — reads are per-request REST; the seam docstring is the
  pin); ADR-0013 records `rbac_drift.py` as a stub no-op.
- **Tracker copies** (`.backlog/decisions/`): created
  `decision-001..013` + `decision-040`; recopied the three drifted
  copies (0022, 0024, 0028 — artifacts were newer: implementation
  status, H1 heading, KUBEDASH_HOME contract) and fixed 10 stale
  `Source:` paths (`.skillgrid/artifacts/` → `.skillgrid/knowledge/`).
  All 29 artifacts now have in-sync copies.
- **Invariants** (8 new, `invariants/`): session-cookie-transport,
  leader-only-rq-worker, config-fail-fast, services-integration-boundary
  (records the one function-local `from flask import g` carve-out),
  sar-verdict-cache-key, air-gap-bundle, object-nav-no-url-identity,
  security-header-layer. Every claim literal grep-verified 2026-11-06.
- **Workflows** (4 new, `workflows/`): oidc-login-session,
  object-deep-link, leader-task-execution, frontend-build-serve.
- **Reference** (2 new, `reference/`): live-architecture (pointer +
  known-staleness notes: ARCHITECTURE.md header still says PROPOSED /
  React 18, §3.8 still env-driven config), feature-roadmap (pointer).
- **Glossary**: 4 terms added to `02-technical-terms.md` (object ref,
  deep link, object handoff, SPA fallback — ADR-0040 vocabulary).
- **Reverse index** populated (first pinned concepts).
- `ASSUMPTIONS.md`: the "0001..0013 files not yet authored" note marked
  done.

## 2026-11-06 — KB updated for 235aa001..547fd93f (storage + network + PV batches, SSO login fix)

- **Invariants** (1 new): `object-view-annotation-trim.md` — the 4.1
  `trimAnnotations` shape is now the contract for every object data
  view (overrides the 2026-10-28 "render annotations verbatim"
  deviation; HPA 2026-11-04 `46929a10`, storage 2026-11-05 `f7c8223d`,
  network 2026-11-06). Claim literals grep-verified 2026-11-06.
- **Gotchas** (2 new, folder was scaffolded-empty):
  `datatables-react-stale-render-closure.md` (datatables.net-react
  binds Column render fns at init only — join late query data into the
  row, the Nodes.tsx pattern; the `window.location`-as-inert-memo-dep
  sibling class; `500e13e4` / `d75d6f1f` / `813b9026`) and
  `kube-pvc-bounded-phase-not-condition.md` (`--for=condition=Bound`
  can never pass on a PVC — wait on
  `jsonpath='{.status.phase}'=Bound`; `ce6d0b19`, QA gate F1).
- **Reference** (1 revised): `feature-roadmap.md` — recorded the
  four 2026-11-06 research-only spec folders
  (`2026-11-06-mcp-server`, `-ai-investigations`, `-change-timeline`,
  `-workload-map` — the latter with a draft briefing) as in-flight
  roadmap research; roadmap items themselves unchanged.
- **Glossary**: `observed tier` term added to
  `02-technical-terms.md` (late-resolving metrics view; ADR-0003
  degrade-don't-fail).
- **Recorded, no concept needed:** the SSO login flow completion
  (`c59dd4a9`) — the six breaks (GET-vs-POST `/auth/login`, IdP
  authorize redirect, `redirect_uri`, exchange kwargs, mock IdP gaps,
  e2e localStorage poll) were pre-QA implementation gaps inside the
  existing ADR-0025 flow, fixed with 2 regression tests; no new
  invariant (the contract already held). The PV consumer-side
  ref/SAR-group review fixes (`feb36175`) are test/edge corrections,
  not contract changes. No ADRs were minted in the window (next
  number remains 0041; the 2026-11-06 research findings feed it).
- `index.md` + `reverse-index.md` updated in the same edit
  (same-edit rule). `kb index` (scanned=46) + `kb lint: clean` after
  the writes.
- **Engine note:** `kb validate` reports `unresolved` for *every*
  ripgrep-anchored page in this project (pre-existing pages included,
  e.g. `invariants/session-cookie-transport.md`); `config.json`
  carries `anchor_engine: ""` (engine field empty in the scaffold), so
  the pin-check resolves no anchors here. The new pages' claim
  literals were grep-verified against the working tree by hand
  instead (each literal above appears in its anchor file). If the
  engine's anchor resolver is ever wired for this project, re-run
  `kb validate` on the three new pages to confirm.
