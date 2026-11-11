---
prototype: 001
name: spock-probe-visibility
type: standard
topic: 2026-11-10-ha-status-page
verdict: VALIDATED
tags: [pgedge, spock, ha-status, leader-election, prototype]
---

# Prototype 001: spock probe visibility + down-node probe mechanics

## What This Validates

**Given** a 2-node pgEdge active-active cluster (kdpg-n1 :5432, kdpg-n2 :16433,
app credentials `kubedash:kubedash` valid on both nodes) and a host-run
throwaway process that opens a short-lived SQLAlchemy engine per node DSN
(`connect_timeout=3`), **when** it runs the blueprint's probe catalog
(spock local node, `sub_show_status` per local subscription, `lag_tracker`,
`get_apply_worker_status`, `get_channel_stats` totals, `exception_status`,
`pg_locks` advisory cross-check) on each node, **then**:

1. (data shape) either one node's spock views expose BOTH replication
   directions (fan-out can collapse to one DSN + liveness checks), or at
   least one required data point is only visible from the node that hosts
   it (per-node fan-out required);
2. (down-node mechanics) a probe against a stopped node returns within the
   3 s bound with a classifiable error (never hangs the report), the
   engine create/dispose is clean, and the executed statement set is
   provably SELECT-only (blueprint Threat 1).

This is the claim the HA Status blueprint's architecture rests on: the
whole per-node fan-out (Tasks 1-2, the `[ha] node_dsn_overrides` map, the
R4 per-node matrix) exists because each node is assumed to be a half view.
If that assumption is wrong, the design simplifies; if the down-node probe
can hang, the "200, never 500" contract breaks.

## Research

No external library beyond what the app already runs (SQLAlchemy 2.0 +
psycopg3, spock 5.0.1 schema read live from `information_schema`). The
spock probe catalog comes from blueprint Task 2 (`sub_show_status`,
`get_apply_worker_status`, `get_channel_stats` are spock **functions**,
verified present; column names confirmed by calling them — the blueprint's
`wo_state`/`remote_addr` guesses were wrong: real columns are
`worker_status` / `provider_node`).

**Chosen approach:** direct per-node DSN probes from a stdlib HTTP server
(shortest path to a felt result; the UI drives re-probes and node
stop/start so the down case is exercised on demand).

## How to Run

```bash
# dev stack up (task dev-up / docker compose in dev/), then:
cd backend
uv run python ../.skillgrid/meta/.prototype/001-spock-probe-visibility/probe.py
# UI: http://127.0.0.1:8099  — Re-probe button; Stop node / Start node per card
# API: GET /api/probe · POST /api/node/stop|start {"name": "n2"}
```

## What to Expect

- **Both nodes up:** green `HEALTHY` banner; lease line (replica, fence,
  heartbeat age); lock verdict `held on <node> (pid <N>, <state>)`; one
  card per node (reachable, direction lag B/s, apply workers, conflicts,
  exceptions, advisory-lock sighting, subscription status); each card says
  `8 SELECTs`.
- **Stop a node** (button): red `DOWN` banner with `node_unreachable:<name>`
  + `subscription_not_replicating:<peer>` chips; the down card shows the
  classified probe error and `≤ 3 s bound` elapsed; the lock verdict stays
  truthful (no false `no_leader` while the heartbeat is fresh).
- **Start the node:** back to `HEALTHY` within one re-probe.

## Liftable Module

`../../specs/2026-11-10-ha-status-page/modules/ha_derive.py`
(path: `.skillgrid/specs/2026-11-10-ha-status-page/modules/ha_derive.py`)

- `derive_status(nodes: list[NodeProbeData], lease: LeaseState, *,
  lag_exceeded_s=60.0, heartbeat_stale_s=10.0) -> StatusDerivation`
  — the R4 matrix as a pure function: per-node reachability/subscription/
  lag/exceptions + lease freshness + lock verdict →
  `StatusDerivation(status, reasons, leader)`.
- Input dataclasses `NodeProbeData` (one node's probe result — the shape
  the real `probe_node` must fill) and `LeaseState` (the `leader_lease`
  row). No dependencies beyond the stdlib. Thresholds injected (no
  prototype constants). The real build (blueprint Task 2,
  `backend/app/services/ha_status.py`) copies this file and wires the I/O
  around it; its `derive_status(report)` signature maps 1:1.
- Everything else in this directory is throwaway.

## Investigation Trail

- **Attempt 0 (schema survey):** listed `spock.*` views + functions on
  both nodes as the app user → both nodes accept `kubedash:kubedash`;
  `spock.node`/`spock.node_interface` exist (member list + DSNs); the
  blueprint's `spock.status` view does NOT exist (the probe catalog is
  views + functions, not a single status view).
- **Attempt 1 (data shape, both nodes up):** ran the catalog per node →
  each node shows EXACTLY ONE direction: one `lag_tracker` row (the
  direction INTO itself), one local subscription (`sub_n1n2` on n1,
  `sub_n2n1` on n2, both `replicating`), one apply worker
  (`worker_status=running`), one channel's totals. Member list +
  `node_interface` DSNs are identical on both (replicated). →
  **fan-out required** for directional metrics. Surprise: the member
  DSNs use `user=pgedge` (spock's internal admin) + compose service
  hostnames — the blueprint's credential-substitution + host/port
  override plan (line 109 / F8) is confirmed necessary, not optional.
- **Attempt 2 (lock cross-check, first run):** probe derived
  `lock_lease_mismatch` (fresh heartbeat, lock seen on no node) — but the
  leader's lock IS held (pid 7899 on n1). Root cause: the real `pg_locks`
  row is `classid=4294967295, objid=2565736957, objsubid=1` — single-
  bigint advisory locks record **objsubid = 1**, and `objid` is the raw
  key cast to oid (`hashtext('local')::oid` — no second hash;
  `hashtext(hashtext('local'))` = 3176555083 ≠ observed). Fixed the
  filter to `objsubid = 1` → lock found on n1 only, not n2 (session-
  local, as ADR-0031 says) → `HEALTHY`, verdict `held on n1 (pid 7899,
  idle)`. (Yesterday's F12 psql match worked because it filtered
  classid+objid only, without an objsubid clause.)
- **Attempt 3 (down node):** `docker stop kdpg-n2` via the API (882 ms) →
  probe: n2 `reachable: false`, elapsed **4 ms** (2 ms on the re-test),
  0 statements executed, engine created+disposed without hang; n1's
  subscription flipped `replicating` → `down`; derivation `down` +
  [`subscription_not_replicating:n1`, `node_unreachable:n2`]; lock verdict
  still `held on n1` — **no false `no_leader`** (fresh heartbeat gates the
  lock reasons, per the R4 matrix). First classification came back
  `other:OperationalError`: psycopg folds the low-level
  `ConnectionRefusedError` into its message ("could not receive data from
  server: Connection refused") — the exception chain ends at
  `psycopg.OperationalError`. Fixed the classifier to message-match →
  `connection_refused`.
- **Attempt 4 (recovery):** `docker start kdpg-n2` (528 ms) → re-probe:
  both reachable, both subs `replicating` again within ~15 s, `HEALTHY`.
- **Attempt 5 (idle/stale lag semantics):** while n2 was DOWN, n1's
  direction row grew to **72.5 s interval at 0 bytes** — the interval
  tracks freshness of the last remote WRITE, not apply delay. With n2
  back, a 90 s no-new-writes window did NOT grow the interval (2.4 s →
  0.6 s, LSN advanced 0/CCF36B0 → 0/D03EF00 — spock's own traffic keeps
  the direction alive on a live cluster). → thresholding on the interval
  alone false-alarms on any starved/idle direction; the build must require
  `replication_lag_bytes > 0` AND `interval > N` (the module does).
- **UI runs:** screenshots at 08:43 (healthy, both nodes) and 08:45 (DOWN
  + chips + classified error) — the page renders both states correctly,
  re-probes on demand, and the Stop/Start buttons drive the whole
  down/recovery cycle in the browser.

## Results

**Verdict:** VALIDATED ✓ (both questions, multiple edge cases)

**Evidence:**

- Data shape: n1 probe row `lag_tracker = [n2→n1 only]`, n2 probe row
  `[n1→n2 only]`; member list identical on both nodes; `sub_show_status`
  returns the local sub only (attempt 1).
- Lock match: `pg_locks` row `(7899, 4294967295, 2565736957, 1, True)` on
  n1, none on n2; `hashtext('local')::oid = 2565736957` exact match
  (attempt 2).
- Down node: `probe_error=connection_refused`, `elapsed_ms=4` (bound 3000),
  `statements=0`, derivation `down` + 2 reasons, lock verdict
  `held on n1 (pid 7899, idle)` — 200-shaped data, no raise, no hang
  (attempt 3). UI screenshot of the DOWN state at 08:45.
- Recovery: both subs `replicating` again, `HEALTHY`, within one re-probe
  ~15 s after `docker start` (attempt 4).
- Lag semantics: 72.5 s interval @ 0 B while starved; 2.4 s → 0.6 s with
  live traffic (attempt 5).

**Surprises:**

1. `objsubid = 1` (not 0) for single-bigint advisory locks, and `objid` is
   the raw key as oid (no re-hash) — the cross-check filter silently
   matches nothing with `objsubid = 0`.
2. `replication_lag` (interval) is remote-write freshness, not apply
   delay; it grows without bound on a starved direction while
   `replication_lag_bytes` stays 0.
3. psycopg hides `ConnectionRefusedError` in the message — error
   classification must match message text, not the exception chain.
4. The blueprint's guessed column names (`wo_state`, `remote_addr`) don't
   exist; real: `worker_status`, `provider_node` (and no `spock.status`
   view at all).

**Constraints for the build:** see Signal below — the approach is valid
with the exact-match and thresholding rules, not a PARTIAL in the
"workaround" sense.

## Signal for the Build

- **Fan out per node** for `lag_tracker` / subscription status / apply
  workers / channel totals / lock sighting — a single node is a half view.
  The **catalog** (member list, `node_interface` DSNs, `spock_version`,
  `leader_lease`, tasks) is replicated: read it **once** from the app's
  own DSN, then probe each member.
- Member DSNs are `user=pgedge` + service hostnames: substitute the app's
  credentials and, for host-run dev, map host/port (F8 override map).
- Lock cross-check (exact): `locktype='advisory'`,
  `classid=4294967295::oid`, `objid=hashtext(:rid)::oid`, **`objsubid=1`**.
- Down-node probe: `connect_timeout=3` in `connect_args` suffices
  (ECONNREFUSED path returns in ~4 ms; the timeout bounds the
  firewalled/unreachable-host path); classify by message
  (connection refused / timed out / password / server closed);
  `engine.dispose()` in `finally`; the statement set is closed and
  SELECT-only by construction (8 statements per node).
- `lag_exceeded:<node>` fires only when `replication_lag_bytes > 0` AND
  the interval exceeds the threshold (starved/idle directions otherwise
  false-alarm).
- UI wording: channel conflicts are a **cumulative** counter (n2 showed
  23,395); apply-worker health = `worker_status='running'` (not
  `streaming` — that's `pg_stat_replication` vocabulary).
