# Report — HA Status page (admin endpoint + settings view)

**Change:** `.skillgrid/change-specs/2026-11-10-ha-status-page`
**Gate:** 2026-11-13 — first QA gate (executed + dev-verified 2026-11-11, `ebf93a5f`
"executing -> qa"; no prior gate record)
**Gate-start tree:** `d00f42fb`; final tree = gate-start + this gate's fix commit
(referenced below as "the gate fix commit")

**Change commits:** `1d401eac` (route rename) · `2e1b76cc` (route amendment back to
`/settings/cluster-status`) · `e00024fc` (API + service + 480 test lines) ·
`298415df` (view + 231 test lines + stub removal) · `6963fc83` (probe fix:
lazy-proxy str contract + keyword DSNs) · `b2330f69` (cards + replica-count
fallback + Lease-shaped rows + 40 test lines) · `959a3833` (the `/clusters`
4.1-parity rewrite — committed in this change's execution window; source of the
W037 e2e break)

## Gate Decision

**PASS** — re-rendered after the gate fix loop. First render **FAIL** on three
findings, all fixed and re-verified at the gate:

1. **CRITICAL (acceptance):** scenario `ha-status-node-unreachable-down`
   required `node_unreachable:n2`; the live probe returned the bare
   `node_unreachable:` — a dead node cannot report its own local name
   (`probe_node` first statement never runs), and `derive_database_status`
   used the probe's empty `node_name` while `build_report` knew the member
   name from `spock.node`. Fixed: name backfill in the `build_report` merge
   (`replace(probe, node_name=name)`) + regression test
   `test_build_report_failed_probe_reason_carries_member_name`. Live
   re-verified (docker stop kdpg-n2 → `down` + `node_unreachable:n2`).
2. **CRITICAL (e2e, W037 re-confirmed → closed):** the ui-smoke serial chain
   was broken at `login → /clusters` — `ui-smoke.spec.ts:125`/`:333` expected
   the pre-rewrite "Bound clusters" heading; `959a3833` ships
   "Kubernetes Server List". Fixed both assertions → full chain 20/20.
3. **CRITICAL (e2e, newly exposed):** the deep-link test
   (`ui-smoke.spec.ts:378`) was stale — its hand-rolled form omits the
   `csrf` echo that `object_handoff.post_bounce` requires (contract since
   `9c9c9954`, 2026-11-11; the test dates from `7234bda3`, 2026-11-03).
   Without it the POST is a 403, nothing is stashed, and the fresh tab
   renders the list. The staleness was masked because W037 broke the chain
   upstream first. Fixed: the test form now echoes the `kd-csrf` meta exactly
   like `postObjectToTab`. Standalone pass (4.5 s), chain 20/20.

## Verification Floor (re-run after the fix loop)

| Dimension | Result |
|-----------|--------|
| Backend unit floor (`-m "not integration"`) | **890 passed**, 10 deselected, 0 failed (274 s) |
| Targeted (`tests/services/test_ha_status.py`) | **35 passed** (incl. the new regression) |
| Frontend full vitest | 503/504 — the 1 failure is the load-dependent flake W042 (W037's named edit-flow test; standalone **6/6 in 1.47 s**) |
| `task fe-build` + `task fe-check` | green (air-gap passed, bundle byte-identical) |
| `ruff check` (ha_status.py + admin.py + test) | **0 findings** |
| `mypy` (ha_status.py) | **0 findings in the file** (repo baseline 63 in 13 other files, unchanged) |
| `task e2e` (full auth-smoke + ui-smoke chain) | **20/20** (29.7 s) — incl. the `/settings/cluster-status` REAL_ROUTES leg |
| Trivy (`fs . --scanners vuln --severity CRITICAL`) | **0 CRITICAL** (backend, frontend/pnpm-lock.yaml, cli/go.mod) |

## Live Verification (kubedash.dev.local:8080, two-node pgEdge dev cluster)

| Probe | Result |
|-------|--------|
| Admin `GET /api/v1/admin/ha-status` | 200, `status: healthy`, `spock_version 5.0.1`, both nodes, leader + queue sections |
| Both replication directions | n1 reports `sub_n1n2: replicating`, n2 reports `sub_n2n1: replicating` (per-node local state, F2/F3) |
| Lock cross-check | `held on n1 (pid …, idle)`, n2 `lock_held_locally: false` (F12/F13) |
| Non-admin | **403** (temp local `role: user` created for the probe, deleted after) |
| Unauthenticated | 401 |
| `docker stop kdpg-n2` | **200** `down` + `node_unreachable:n2` (post-fix) + `subscription_not_replicating:n1`; n2 entry `reachable: false`, `probe_error: connection_refused`, 45 ms |
| `docker start kdpg-n2` | back to `healthy`, no reasons (~8 s) |
| Leader stopped (gunicorn kill) | via worker-only probe instance on :8081: **200** `degraded` + `no_leader` + `leader_heartbeat_stale` (106.9 s), `lock_verdict: not seen on any reachable node`, fence held at 5 |
| Leader restarted | `healthy`, **fence 6** (exactly +1 — the election counter), lock re-acquired |
| DSN override (R3/F8) | n2 probed via `localhost:16433` (INI override) — reachable from the host; response shows `host:port` only, no credentials |
| Browser (admin, `/settings/cluster-status`) | real view: per-node cards (name, reachable, replication, lag, workers, conflicts, leader-lock marker), Leader Election section (holder, acquire/renew, duration, fence 6, heartbeat age, lock verdict, "1 leader of 1"), Task Queue section — not the stub |

## Traceability — 21/21 scenarios

| Scenario | Evidence | |
|----------|----------|-|
| ha-status-admin-200 | live 200 + `test_healthy_baseline` | ✓ |
| ha-status-both-directions-reported | live (both sub names on their owning nodes) + `test_probe_node_healthy` | ✓ |
| ha-status-non-admin-403 | live 403 (admin hook, same as `/admin/*` siblings) | ✓ |
| ha-status-probe-is-read-only | `test_probe_node_healthy` (executed-statement DML-free assertion) | ✓ |
| ha-status-node-unreachable-down | live (post-fix) + `test_down_node_unreachable` + new regression | ✓ (gate-fixed) |
| ha-status-node-recovers | live (~8 s to healthy) | ✓ |
| ha-status-subscription-not-replicating-down | live (n1's sub while n2 down) + `test_down_subscription_not_replicating` | ✓ |
| ha-status-lag-exceeded-degraded | `test_degraded_lag_exceeded` + `test_f17_zero_bytes_lag_is_not_lag` (bytes-AND-interval, F17) | ✓ |
| ha-status-exceptions-degraded | `test_degraded_exceptions_pending` | ✓ |
| ha-status-stale-heartbeat-degraded | live (`leader_heartbeat_stale` during the stop) + `test_degraded_no_leader` | ✓ |
| ha-status-worst-verity-wins | live (down with both reasons) + `test_overall_is_worst_section_reasons_db_first` | ✓ |
| ha-status-leader-election-report | live (replica_id, token, tenure, heartbeat age, fence, lock verdict w/ pid+state) — see W044 for the `candidates` contract refinement | ✓ |
| ha-status-backend-stop-no-leader | live full cycle (degraded + `no_leader`; restart → healthy + fence +1) + `test_degraded_no_leader` + `test_election_failure_is_never_down` | ✓ |
| ha-status-lock-lease-mismatch | `test_degraded_lock_lease_mismatch_all_reachable` | ✓ |
| ha-status-lock-node-down-no-false-alarm | `test_f12_no_alarm_while_a_node_is_unreachable` + live partial (n2 down, lock on n1, election stays healthy, no lock reason) | ✓ |
| ha-status-candidates-in-cluster | `test_candidate_count_full_chain` + 4 failure-path unit tests + `test_build_report_detected_replicas_win_over_configured` (in-cluster live N/A: kind has no KubeDash Deployment — F14) | ✓ |
| ha-status-dsn-override-honored | live (n2 via :16433) + `test_dsn_overrides_parse` + `test_build_report_merges_overrides_and_assembles` | ✓ |
| ha-status-dsn-override-malformed-fails-fast | `test_dsn_overrides_malformed_raises` (ConfigError, ADR-0028) | ✓ |
| ha-status-page-renders-healthy | live browser (full page) + MSW `healthy-report-renders-node-cards-leader-queue` | ✓ |
| ha-status-page-shows-degraded-reasons | MSW `down-report-renders-reason-and-unreachable-node` + `no-leader-renders-degraded-banner-with-reasons` | ✓ |
| cluster-status-route-replaced-the-stub | live browser (real view at `/settings/cluster-status`) + `stubRoutes` entry removed in `298415df` + Stub suite green + e2e REAL_ROUTES leg | ✓ |

## TDD Evidence

Co-commit shape: `e00024fc` (service + 480 test lines), `298415df` (view + 231),
`b2330f69` (cards + 40) all pair code with tests in the same unit; `6963fc83`
is a fix without a new test (W045). No execution ledger (`.sdd/`) — retrofit
class of W015/W021/W030/W039/W040 (W045). All cited hashes resolve; no
MISSING_RED, no STALE against the acceptance file.

## Assertion Quality

Backend 35 + frontend 5 view tests + the e2e legs read in full: no tautology,
no ghost loop, no assertion-without-code-call. The new regression asserts the
**named** reason string (`node_unreachable:n2`) plus an explicit
`no bare "node_unreachable:"` guard — consumer-visible, not a shape check.

## Security Audit

- **RBAC:** `require_admin()` (same hook as the other `/admin/*` routes); live
  403 non-admin + 401 anonymous.
- **Credential leak:** the response carries `host:port` + node name only
  (`_dsn_display` strips user/password) — verified in the live JSON; the DSN
  string itself never appears.
- **Config (ADR-0028):** `[ha] node_dsn_overrides` optional, empty default,
  malformed → `ConfigError` at boot (fail-fast, unit-pinned).
- **Read-only (R6):** the probe SQL set is a closed SELECT/function set;
  `test_probe_node_healthy` asserts DML-free on executed statement texts
  (`autoddl` would replicate an app write).
- **Trivy:** 0 CRITICAL, all lockfiles. **Dependencies:** no new entries in
  `pyproject.toml`/`pnpm-lock.yaml`/`go.mod`. **Air-gap (ADR-0020):** probes
  reach only the cluster's own nodes.
- **Best-effort fields:** `candidates` can never fail the report (any K8s
  failure → null/fallback, F14).

## Findings

| ID | Severity | Finding |
|----|----------|---------|
| F1 | CRITICAL — **fixed at gate** | `node_unreachable:` reason carried an empty node name (acceptance `ha-status-node-unreachable-down` unmet). Backfill + regression test + live re-verification. |
| F2 | CRITICAL — **fixed at gate** | W037: stale "Bound clusters" e2e assertions (×2) broke the serial chain; 16+ downstream tests never ran. Closed W037. |
| F3 | CRITICAL — **fixed at gate** | Deep-link e2e test stale vs the `csrf`-echo contract (`9c9c9954`); masked by W037. Fixed the test form. |
| **W042** | WARNING | `Clusters.test.tsx › admin creates a cluster from the add dialog` (W037's named edit-flow test, rewritten by `959a3833`) is a **load-dependent flake**: failed 2/2 full-suite runs (1753 ms, waitFor on the POST), standalone 6/6 in 1.47 s. Local floor only (vitest is not in CI). Follow-up: harden the test (explicit waits / no load-sensitive pastes). |
| **W043** | WARNING | Blueprint Task 5 artifact `backend/tests/integration/test_ha_status_pgedge.py` was never created (no git history). The T5 alternative — dev-stack e2e — WAS executed live at this gate (real SQL: both directions, stop/recover, no_leader, lock cross-check). Residual gap: the **in-cluster keyword-DSN probe path** (`_probe_engine` keyword parse, `user=pgedge` no password) has no unit test and is masked in dev by the URL overrides. Empirically de-risked: `psql host=localhost user=pgedge` (no password) authenticates and spock functions run as pgedge on this image. Follow-up: T5 Testcontainers test or a keyword-DSN unit test. |
| **W044** | SUGGESTION | Acceptance text lag: `ha-status-leader-election-report` says "candidates null (host-run dev)"; `b2330f69` deliberately refined the contract to the configured-replica-count fallback (dev: 1; two unit tests pin it). Update the feature text at review. |
| **W045** | SUGGESTION | `6963fc83` (lazy-proxy str contract + keyword DSN parse) has no regression-test pin, and the change has no execution ledger (W015/W040 class). |

**Design note (for review ratification):** the in-cluster probe runs as
`user=pgedge` (the interface DSN's user) rather than substituting the app's
credentials as the blueprint text described. Empirically verified functionally
equivalent-or-better on this image (pgedge has trust auth and owns the spock
catalog functions). If pg_hba changes for `pgedge` host connections, the probe
would classify `auth` and report `reachable: false` — W043's T5 test would
catch that.

## Verification Scope

**COMPLETE** — four levels: unit (890 floor + 35 targeted + derivation matrix
incl. F16/F17 edge rules), component (MSW healthy/down/no-leader/error/non-admin),
e2e (full chain 20/20 after fixes), live (API probes + failure modes +
browser rendering on the real two-node cluster). No scenario left to a later
gate; W043's in-cluster path is the single documented residual (T5 class).

## Gate Decision (render)

**PASS** — goal verified at all four levels; 21/21 scenarios traceable; TDD
evidence co-commit-consistent; assertion quality clean; 0 open CRITICAL; code
quality gates green (the vitest floor carries the documented W042 flake);
layer selection justified (seam-unit for spock SQL per F10, MSW for the view,
e2e for the route, live for the sick-cluster modes). Route: **code-review**.

---
*QA gate 2026-11-13 — first gate for this change; fix loop closed F1–F3 in-gate.*
