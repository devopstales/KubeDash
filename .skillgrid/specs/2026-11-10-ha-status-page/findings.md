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
