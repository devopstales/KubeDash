# Findings — HA Status page

Live-probed 2026-11-10 against the dev two-node pgEdge cluster
(`kdpg-n1` :5432, `kdpg-n2` :16433; `pgedge/pgedge:pg17-latest`).
Every claim below was verified with a `psql` call; the command and the
observed value are shown.

## F1 — spock 5.0.1 is the replication engine; the catalog lives in the `spock` schema

```sql
select spock.spock_version();
-- 5.0.1
select n.nspname, c.relname from pg_class c join pg_namespace n on ...
-- spock.node, spock.node_interface, spock.replication_set,
-- spock.subscription, spock.lag_tracker, spock.local_node,
-- spock.exception_status, spock.exception_log, spock.channel_summary_stats,
-- spock.local_sync_status, spock.progress, spock.queue, ...
```

## F2 — Replication is bidirectional via one subscription per node; status is per-node LOCAL

Each node runs a subscription that pulls from its peer. On n1:

```sql
select sub_name from spock.subscription;
-- sub_n1n2
select subscription_name, status, provider_node, slot_name
from spock.sub_show_status('sub_n1n2');
-- sub_n1n2 | replicating | n2 | spk_kubedash_n2_sub_n1n2
```

`sub_show_status` can only be meaningfully called **on the node that owns
the subscription** ("subscriber n1 not found" when probed with a foreign
name) — the other direction's status lives on the other node.

## F3 — Replication lag is per-node LOCAL (each node tracks only what IT receives)

```sql
-- on n1:
select * from spock.lag_tracker;
-- n2 | n1 | <commit_ts> | 0/47413C8 | 0/4741470 | 0 | 00:00:01.938393
-- on n2:
-- n1 | n2 | <commit_ts> | 0/3B14AB0 | 0/3B14AB0 | 0 | 00:00:00.55123
```

Columns: `origin_name, receiver_name, commit_timestamp, last_received_lsn,
remote_insert_lsn, replication_lag_bytes, replication_lag (interval)`.
n1 never sees the n1→n2 direction — a full view requires querying both
nodes.

## F4 — Apply-worker state is a per-node function

```sql
select * from spock.get_apply_worker_status();
-- 7234 | 33894 | 3293941396 | running
-- (worker_pid, worker_dboid, worker_subid, worker_status)
```

## F5 — Cumulative per-relation change counters (conflict tracking input)

```sql
select subid, relid, n_tup_ins, n_tup_upd, n_tup_del, n_conflict
from spock.get_channel_stats();
-- 0 | 34282 | 3 | 0 | 0 | 0   (relid → pg_class for the table name)
```

## F6 — Conflict/exception state

`spock.exception_status`
(`remote_origin, remote_commit_ts, retry_errored_at, remote_xid, status,
resolved_at, resolution_details jsonb`) + `spock.exception_log`.
Clean cluster: `select count(*) from spock.exception_status; → 0`.

## F7 — Per-node DSNs are discoverable from any node (replicated catalog)

```sql
select if_name, if_nodeid, if_dsn from spock.node_interface;
-- n1 | 49708 | host=kdpg-n1 dbname=kubedash user=pgedge port=5432
-- n2 | 26863 | host=kdpg-n2 dbname=kubedash user=pgedge port=5432
```

Keyword-format DSNs; user is `pgedge` (the spock internal-admin, password
**not** in the DSN string — the app cannot use this DSN as-is and must
substitute its own DB credentials).

## F8 — From the dev HOST, the compose service names do not resolve

```
python3 -c "socket.gethostbyname('kdpg-n1')" → [Errno 8] nodename nor servname
```

The dev backend runs on the host and reaches n1 via `localhost:5432`;
n2 is reachable only at `localhost:16433` (the fixed alt port from
`dev/docker-compose.yml`). In-cluster (prod) the `spock.node_interface`
hostnames resolve via service DNS. ⇒ a per-node probe needs an
optional DSN-override escape hatch for the host-run dev backend.

## F9 — The KubeDash control-plane HA state is a plain replicated table, readable from any node

```sql
select * from leader_lease;
-- id=1 | replica_id=local | token=<uuid> | acquired_at=... | heartbeat_at=<fresh> | fence=2
select status, count(*) from tasks group by status;
-- pending | 1
-- done    | 207
```

## F10 — The spock SQL cannot run on sqlite

`sub_show_status`, `get_channel_stats`, `get_apply_worker_status` etc.
are C functions of the extension — a sqlite tier has none of them.
Unit tests must seam the probe layer (inject per-node results); the real
SQL gets integration coverage (Testcontainers `pgedge/pgedge`) or the
dev-stack e2e.

## F11 — Route state

`/settings/cluster-status` exists only as a stub: `frontend/src/views/Stub/routes.ts`
(admin: true) + the `_nav.tsx` leaf (already titled "HA Status") +
`e2e/ui-smoke.spec.ts` smoke list. No backend endpoint exists
(`grep cluster_status backend/app` → no matches). The Stub test
(`tests/views/Stub.test.tsx`) derives its expectations from the nav, so
the rename self-adjusts.

## F12 — The leader's advisory lock is observable, and matchable, in `pg_locks`

```sql
select l.granted, a.pid, a.state, a.backend_start
from pg_locks l join pg_stat_activity a on a.pid = l.pid
where l.locktype = 'advisory' and l.classid = 4294967295::oid
  and l.objid = hashtext('local')::oid;
-- t | 7899 | idle | 2026-11-10 08:18:44.215403+00
```

`hashtext()` returns signed int4; `pg_locks.objid` stores the two's-complement
unsigned form — the `::oid` cast bridges them (`hashtext('local') =
-1729230339` → objid `2565736957`). `classid = 4294967295` (0xFFFFFFFF)
selects single-int4-key locks. The holder's `backend_start` (08:18:44)
equals `leader_lease.acquired_at` — the lock session is the leader's
dedicated `_advisory_conn`, kept open for the lease lifetime
(`leader.py` `acquire_once`/`stop`). Steady-state count of granted
advisory locks: **exactly 1** (the leader's) — followers return from
`acquire_once` before any lock attempt while the lease is fresh and
foreign.

## F13 — The lock key is PER-REPLICA; the fence is the cross-node arbiter

`leader.py`: `_binds() = {"rid": self.replica_id}` — the key is
`hashtext(<own replica_id>)`, deliberately not a fixed constant
(docstring: a fixed key would let a second `Leader` object on the same
engine report spuriously non-leader and break failover). ADR-0031
(docstring, quoted): the advisory lock is **session-local — NOT a
cross-node mutex** ("two peers on different Postgres nodes can both hold
their local session's lock"); the `leader_lease.fence` upsert
(`fence = fence + 1`, every leader write fenced `WHERE fence = :f`,
0 rows → demote) is the cross-node LWW tiebreaker. Consequences for the
page:

- The `pg_locks` cross-check must run **on every node** (per-node probe
  set) — under active-active the leader's lock session lives on whichever
  node its pool routed it; one node's `pg_locks` is a half view.
- Followers hold NO lock in steady state (they never reach the lock
  attempt) — candidate/follower count is NOT derivable from `pg_locks`.
- Lock released ⟺ the leader's PG session died (session-scoped) — a real
  liveness signal: fresh heartbeat + no lock on any node = mismatch
  (transient ≤ 5 s after an acquire); stale heartbeat + no lock =
  `no_leader` (fail-closed: no scheduled work) until a candidate re-acquires.

## F14 — Candidate count needs the K8s API (and is nullable in dev)

Every chart pod is a candidate (`KUBEDASH_ROLE=leader`,
`KUBEDASH_REPLICA_ID` = pod name via Downward API; the chart sets this on
all replicas). The expected candidate count is the KubeDash
Deployment's `spec.replicas` — readable via the existing admin client
shape (`build_admin_client`, ADR-0021) but `K8sClient` has no
deployment read yet (small `get_pod`/`get_deployment` additions,
owner-refs chain pod → ReplicaSet → Deployment from
`settings.kubedash_replica_id` + the in-cluster namespace file). The dev
host backend's target cluster (kind) normally has no KubeDash
Deployment ⇒ the field is `candidates: int | null`, best-effort, null on
any failure (it must never fail the report).

## F15 — A node is a HALF VIEW; the catalog is the only part readable from one DSN

Prototype 001 (2026-11-11, both nodes probed live): every node shows
exactly ONE replication direction — one `spock.lag_tracker` row (the
direction INTO itself), one local subscription (`sub_n1n2` on n1 /
`sub_n2n1` on n2), one apply worker, one channel's totals. `spock.node`
+ `spock.node_interface` (the member list + per-node DSNs) are
replicated and identical on every node. ⇒ read the catalog (members,
DSNs, `spock_version`, `leader_lease`, tasks) **once from the app's own
DSN**, then fan out `probe_node` per member for everything
directional + the lock check. The member DSNs are
`host=<service> dbname=kubedash user=pgedge port=5432` — spock's
internal `pgedge` user and compose service hostnames, so the
credential substitution (blueprint line 109) and the F8 host/port
override map are required for host-run dev, not an optimization.

## F16 — The advisory-lock match is exact: `objsubid = 1`, raw key as `oid`

The real `pg_locks` row for the leader (pid 7899):
`classid = 4294967295, objid = 2565736957, objsubid = 1, granted`.
Single-bigint advisory locks record **objsubid = 1** (objsubid = 0 is
the two-integer form) and `objid` is the raw key cast to oid —
`hashtext('local')::oid = 2565736957` (no second hash:
`hashtext(hashtext('local'))::oid = 3176555083`). A cross-check with
`objsubid = 0` silently matches nothing (first prototype run derived a
false `lock_lease_mismatch` this way). Also: psycopg folds
`ConnectionRefusedError` into its message ("…: Connection refused") —
the exception chain ends at `psycopg.OperationalError`, so probe-error
classification must match message text (connection refused / timed out /
password / server closed), not exception types. A probe against a
stopped node returns in **2-4 ms** (0 statements, engine
create+dispose clean) — the 3 s `connect_timeout` bounds only the
unreachable-host (no RST) path.

## F17 — `replication_lag` (interval) is remote-write freshness, NOT apply delay

Observed: while n2 was down, n1's direction row grew to a **72.5 s
interval at 0 bytes**; with n2 up and no app writes, 90 s passed with
the interval SHRINKING (2.4 s → 0.6 s; LSN advanced — spock's own
traffic keeps live directions fresh). The interval measures the age of
the last remote write; it grows unbounded on any starved/idle direction
while `replication_lag_bytes` (the real apply backlog) stays 0. ⇒
`lag_exceeded:<node>` fires only when **`replication_lag_bytes > 0` AND
interval > threshold** — the interval alone false-alarms on idle or
starved-but-already-classified directions.

## Prototype: 001-spock-probe-visibility

- **Verdict:** VALIDATED ✓ (2026-11-11; record:
  `.skillgrid/meta/.prototype/001-spock-probe-visibility/prototype.md`)
- **What we learned:** per-node fan-out is REQUIRED (F15); the lock
  cross-check works with the exact F16 match and the R4 lock rules hold
  live (lock seen only on the leader's node; no false `no_leader` while
  the peer is down and the heartbeat is fresh); a down node yields a
  classified error in ≤4 ms, never a hang; lag thresholding needs the
  F17 bytes condition.
- **What's liftable:** `modules/ha_derive.py` (pure R4 matrix:
  `derive_status(nodes, lease, *, lag_exceeded_s, heartbeat_stale_s) ->
  StatusDerivation(status, reasons, leader, database, election)` —
  composed from `derive_database_status` (pgEdge node/replication
  reasons) and `derive_election_status` (lease + lock cross-check
  reasons); overall = worst section, flat contract unchanged; + the
  `NodeProbeData` / `LeaseState` shapes the real `probe_node` must fill).
  The UI renders the two failure domains under separate headers —
  stopping a node takes the database section DOWN while the election
  section stays HEALTHY.
- **Constraints for the build:** F16 exact match (`objsubid = 1`); F17
  bytes-AND-interval lag rule; message-based error classification;
  catalog from one DSN, fan-out only for directional metrics + lock;
  member DSNs need credential substitution + host/port override (F8);
  UI wording: channel conflicts are cumulative counters, worker health
  is `worker_status='running'` (not `streaming`).
