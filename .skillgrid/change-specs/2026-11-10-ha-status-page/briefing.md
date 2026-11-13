# Briefing — HA Status page (settings/ha-status)

**Status:** PROPOSED
**Tier:** T2 (new read-only admin API + new page; no schema change, no auth-flow change; the risk surface is the semi-internal spock catalog API + per-node probing)
**Build shape:** Tracer thread (one endpoint, one node's data rendered end-to-end → per-node probes → status derivation + frontend thickening)
**Spec:** this change. **Decisions:** extends ADR-0031 (active-active) with an observability surface; no new ADR required (read-only, no dependency, no one-way door).

## Context

The app now runs on a two-node pgEdge active-active cluster (ADR-0029/0030/0031; the dev stack switched over 2026-11-10). Nothing in the UI shows the health of that cluster: whether both replication directions are up, how far behind a node is, whether the leader lease is live, or whether the task queue is backing up. The nav already carries an admin-gated "HA Status" entry — a stub with no backend endpoint behind it (findings F11).

## Requirements (falsifiable)

1. **`GET /api/v1/admin/ha-status` (admin-only)** returns one JSON document: `spock_version`; every cluster member from `spock.node`; per node — reachability, its subscription status (`spock.sub_show_status`), its receive lag (`spock.lag_tracker`), apply-worker state, conflict count, and **whether the leader's advisory lock is held on THAT node** (`pg_locks` × `pg_stat_activity`, keyed `hashtext(leader replica_id)` — F12/F13); the **leader election** state — the `leader_lease` row (leader `replica_id`, token, tenure via `acquired_at`, heartbeat_at + freshness, `fence` = election count), the aggregated lock verdict (held / on which node / holder pid + session state), and the candidate count (`candidates: int | null` — the KubeDash Deployment's `spec.replicas` via the admin client, owner-refs chain; null in the host-run dev backend, F14); the `tasks` queue state (counts by status + oldest pending); and a derived overall `status` (`healthy` | `degraded` | `down`) with a list of human-readable reasons.
2. **Per-node probing.** The service reads `spock.node_interface` for the per-node DSNs (F7), substitutes the app's own DB credentials, and opens a short-lived read-only connection to each node (connect timeout ≤ 3 s). An unreachable node is reported `reachable: false` — the endpoint still returns 200 (a diagnostic page degrades, it never 500s on a sick cluster).
3. **Optional DSN override (ADR-0028).** A new optional INI section `[ha]` with `node_dsn_overrides` (`name=url;name=url`) takes precedence over the `spock.node_interface` DSNs — the dev host backend needs it because compose service names don't resolve on the host (F8: `n2=postgresql://kubedash:kubedash@localhost:16433/kubedash`). Empty default → use `spock.node_interface`. No credential identity is introduced (the app's existing DB user/password is reused).
4. **Status derivation.** `down` if any node is unreachable or any subscription status is not `replicating`; `degraded` if any receive lag exceeds 60 s, or `spock.exception_status` has rows, or the leader heartbeat is stale (> 10 s), or the lease row is missing, or the **lock cross-check fails** — heartbeat fresh but no granted lock on any reachable node (`lock_lease_mismatch`, transient ≤ 5 s right after an acquire), or a granted lock exists but the heartbeat is stale (`lock_without_heartbeat` — session alive, process wedged), or no lock and a stale heartbeat beyond the stale window (`no_leader` — fail-closed: the cluster still replicates, but no scheduled work runs until a candidate re-acquires within ~10 s); otherwise `healthy`. Every non-healthy verdict carries reasons (e.g. `node_unreachable:n2`, `lag_exceeded:n1`, `lock_lease_mismatch`, `no_leader`).
5. **Frontend.** A real view at `/settings/cluster-status` replaces the stub: overall status banner (with reasons), one card per node (status chip, lag, apply worker, conflicts, "holds leader lock" marker), a **leader election** section (leader replica_id, tenure, fence = election count, heartbeat age, lock verdict — held / on which node / holder pid+state — and candidate count when known, e.g. "1 leader of 3 candidates"), and a queue section (counts, oldest pending). TanStack Query polling ~5 s. Admin-gated as the stub already is.
6. **No new runtime egress, no new third-party dependency, no schema change** — `psycopg` is already the Postgres driver; the page is read-only (the app never writes to `spock.*` — under `autoddl` an app write would replicate, so reads only).

## Intent / non-goals

- **In:** the read-only endpoint + probe layer, the INI override, the page (route `/settings/cluster-status`), replacing the stub.
- **Out:** HA *control* operations (add/drop node, enable/disable subscription, resolve exceptions) — v1 is read-only; SSE push (v1 polls at 5 s); per-table channel-stats UI (the API aggregates totals; the per-table breakdown exists in the API for debugging); K8s-cluster HA (this "HA" is the Postgres/Spock cluster + the KubeDash control plane, not the target clusters).
- Route: `/settings/cluster-status` (user decision 2026-11-11 — the page ships at the pre-rename path; the earlier rename to `/settings/ha-status` is superseded). Replacing the stub is part of this change and lands with the spec.

## Deviations & gate clarifications (recorded at the 2026-11-13 QA gate — for review ratification)

1. **Probe credentials (R2, constraint F7):** the initial implementation probed with the interface DSN's own user (`pgedge`, password-less) instead of substituting the app's credentials; the review's live probe showed that fails on host connections (`fe_sendauth: no password supplied` — trust auth covers only local socket, so the first gate's local-psql check had not represented the in-cluster TCP probe). The review-fix gate implemented R2's app-credential substitution on the keyword path (host/port/dbname stay the interface DSN's) — unit-pinned (`test_probe_engine_keyword_dsn_substitutes_app_credentials`). Residual: in-cluster auth of the APP user against the spock catalog is real-SQL-only (W043).
2. **`candidates` contract (R1, F14):** `leader.candidates` falls back to the configured `[deployment] kubedash_replica_count` (minimum 1) whenever the in-cluster Deployment read is unavailable (no K8s client, RBAC, host-run dev) — i.e. it is effectively `int`, not `int | null`, and is 1 in the dev backend. The acceptance feature text was updated to match in the same gate.

## Constraints (from `findings.md`)

- Per-node local state (subscription status, lag, apply worker, **the leader's lock presence**) must be queried **on** the node that has it (F2/F3/F4/F13) — under active-active the leader's lock session lives on one specific node; probing only the connected node yields a half view.
- The advisory lock key is **per-replica** (`hashtext(<own replica_id>)`) and session-local — NOT a cross-node mutex (F13); the fence upsert is the cross-node LWW. The cross-check matches `pg_locks.objid = hashtext(leader replica_id)::oid` with `classid = 4294967295` (F12); followers hold no lock in steady state, so the candidate count cannot come from `pg_locks` (F13/F14).
- `spock.node_interface` DSNs carry the `pgedge` internal-admin user without a password (F7) — the app must substitute its own credentials when probing.
- Compose service names don't resolve from the dev host (F8) — hence the optional override (R3).
- The spock SQL is not expressible on sqlite (F10) — unit tests seam the probe layer; real SQL is covered by the kind-gated integration test / dev-stack e2e.
- Backend layering: the probe/assembly service is Flask-free (`app/services/`), engine + overrides passed in.
- Air-gap (ADR-0020): probing reaches only the cluster's own nodes — no new egress.

## Threats (drives the threat matrix in the blueprint)

- **Hang:** a dead node's probe blocks the request → per-node connect timeout + a total wall-clock budget.
- **Semi-internal API drift:** spock catalog objects could change across pgedge releases → the SQL is isolated in one module; the integration test fails loudly on drift.
- **Half view misread:** reporting only the connected node's state would show one replication direction → the response carries the probed node name per entry, and the unit tests assert both directions are present.
- **Socket leak:** probes against unreachable nodes → every per-node engine is disposed in a `finally`.
- **Lock cross-check false negative:** the leader's lock session is node-local (F13) → the check aggregates over all reachable nodes; a node that's down can't witness the lock, so the verdict is "not observed on any REACHABLE node" — combined with the heartbeat freshness it stays correct (a dead leader's session releases its lock anyway, session-scoped).
- **K8s read for candidates hangs the report:** best-effort with a short timeout, `candidates: null` on any failure (F14).

## Fast-Track classification

**standard** — new admin endpoint + new view + optional config key; no schema, no auth hot path, no concurrency change. Full pipeline, no waiver.
