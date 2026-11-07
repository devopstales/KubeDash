# Dead-Code Cleanup — Template Leftovers + Unused Code (Change D) — Briefing

> Companion to `blueprint.md`. The *why*: jscpd dead-code pass (2026-11-07,
> health 32/E, dead-code 22): 187 findings — 81 unused files (12,854 lines),
> 79 unused imports, 20 unused symbols, 7 unused exports. The bulk is the
> CoreUI React template's demo material, committed as scaffolding and never
> wired into KubeDash. Interview `q15` settled this as a separate chore
> (zero behaviour change) landing **before** change B so the registry work
> doesn't touch template files.

## What

Delete the confirmed dead code (pure deletions) + one test-hygiene migration (pure test-file edits):

- **Frontend CoreUI template demo files** (58 files, 12,571 lines):
  `views/components/**` demo pages (Tables, Cards, Widgets, Modals,
  InputGroup, …), `views/forms/**`, `views/widgets/**`, `views/dashboard/`,
  `views/authentication/**`, `views/charts`, `views/icons/**`,
  `views/error-pages/**`, `DocsComponents*`, `AppContent`, `store.js` —
  each verified import-free (static + dynamic) before deletion.
- **`views/Cluster/Pods.tsx`** (77L) — a pod view never referenced by any
  route (verified import-free).
- **Unused imports** (79 findings, repo-wide) — eslint/ruff.
- **Safe unused exports/symbols** (verified individually):
  `gateway_convert` leftovers (`PROVIDERS`, `_REGEX_CHARS`,
  `_tls_secret_by_host`), dead `KIND`/`LIST_ROUTE` constants in six data
  views, unused types in `lib/types.ts`/`lib/groupTypes.ts`,
  `wsgi.py` `_rq_worker_main`/`_build_worker_app` (only after the leader-RQ
  path is verified not to reference them), the migration's `_has_unique`,
  `scripts/prometheus-push.py` `_METRIC_RE`.
- **KubeDataTable test-fake fleet migration** (moved from change B, user
  decision 2026-11-07): the ~20 view tests that fake `KubeDataTable`
  inline get one shared fake (`tests/components/kube-data-table.test-utils.tsx`
  — the faithful init-time-capture variant the PV/PVC usage-join tests
  depend on); tests keep their canned data; any behaviour change is a
  stop-and-report, not a silent adaptation.
- **The 23 backend "unused files"** (`app/aggregated/*`, `app/models/*`
  request/SCIM models, `app/services/*` access/grafana/loki/prometheus/tempo/
  scim/…, `app/sockets/*`, `app/tasks/*`) are **verification-only** in this
  change: RQ tasks, sockets, and models are dynamically wired (name strings,
  blueprint registration, ORM metadata), so each is checked for dynamic
  references and the result recorded — deletions happen only for the
  grep-proven-dead, and any doubt is a note for a follow-up, not a deletion.

Test-only exports (`resetRefreshForTests`, `setLoginRedirectForTests`,
`getRegisteredNavigate`) are **kept** — they exist for the test graph
(`getRegisteredNavigate` dies with change C, not here).

## Requirements

- **R1.** Every deleted file has a recorded verification: zero static/dynamic
  import references (grep) + the build still green.
- **R2.** Zero behaviour change: `corepack pnpm test`, `task fe-build`,
  `task fe-check`, `uv run pytest -m "not integration"` green at every commit.
- **R3.** No edits to files outside the deletion list except the
  import-cleanup lines.
- **R4.** The 23 backend files get a verification note (dynamic-wiring
  verdict per file) in the tracker; deletions only when grep-proven.
- **R5.** The fleet fake migration changes no test behaviour: the shared
  fake is the faithful variant; `corepack pnpm test` green with the test
  expectations unedited.

## Success

- jscpd dead-code percentage drops from 16.6% toward ~1% (template bulk +
  unused imports gone); no clone pairs left in `views/components|forms|widgets`.
- The repo has no unwired template demo page left.

## Out of scope

- Any behaviour change. Refactors of live code. The 23 backend files
  (verification only). Backend architecture (change A).

## Fast-Track Waiver
- Class: small
- Skips: none exercised — full pipeline ran (blueprint + critics authored 2026-11-07)
- Reason: pure deletions + import cleanup, no behaviour change, L1 verification floor
- Approved by: user (2026-11-07)
