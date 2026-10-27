# Active-active Postgres via pgEdge/Spock + strict fencing token on `leader_lease`

---
status: "accepted"
date: 2026-10-27
supersedes: ADR-0008
---

**Decision-makers.** KubeDash platform team
**Consulted.** —
**Informed.** —

#### Context and Problem Statement

ADR-0008 (leader election) gives KubeDash a single leader among N replicas: a
Postgres **advisory lock** is the mutex, and a single-row `leader_lease` table
(`replica_id`, `acquired_at`, `heartbeat_at`, `token`) is the observable state.
The leader heartbeats every 5 s; a follower takes over when the row is absent
or `heartbeat_at` is stale (> 10 s). Only the leader enqueues the leader-gated
tasks (ADR-0029's queue, previously RQ).

ADR-0008's election **assumes a single-writable Postgres**: exactly one node
accepts writes to the `leader_lease` row, so the advisory lock + the row's
`replica_id` together guarantee one leader. The current deployment (the Helm
chart's single Postgres, or a single node in dev) satisfies that.

The platform team wants the **database itself** to be highly available beyond
"one primary + failover": both database nodes writable, so there is no
read-only gap during a node loss. That is **active-active (multi-primary)**
Postgres. Making both nodes writable breaks ADR-0008's assumption in a
specific way: two nodes can both upsert the `leader_lease` row, and a
last-write-wins conflict resolution silently picks a winner — the *losing*
leader does not know it lost until its next heartbeat/fence check, and in the
window it may still write task state. This ADR decides **how to run Postgres
active-active and how to keep the leader election correct under it.**

Five constraints, fixed with the platform team, shape the option set:

1. **Active-active** (both nodes writable) — not active-passive failover.
2. **No Bitnami images** — a standing rule (Bitnami's free images moved to a
   legacy, no-update repo Aug 2026).
3. **No operator** — no CNPG / Patroni-operator / similar controller in the
   Helm install; a run-once init `Job` is acceptable, a long-lived controller
   is not.
4. **Docker-compose for development** — the active-active topology must be
   stand-up-able in `dev/` without a cluster.
5. **No build-your-own image** — the Postgres image must ship with the
   active-active capability pre-installed.

Note on the supersession trail: ADR-0008 exists in the `## LOCKED` index but
**has no body file on disk** (index-only, never committed). This ADR is the
first file to carry the leader-election / deployment-shape decision; it
supersedes ADR-0008's *single-writable assumption* and adds the fencing
mechanism, while preserving its advisory-lock + lease-row core.

#### Decision Drivers

- **Both nodes writable, no read-only gap.** The database loses a node without
  a promotion window in which writes are rejected.
- **Exactly one logical leader, always.** The active-active write concurrency
  must not produce two leaders writing task state simultaneously; the election
  must stay correct under last-write-wins conflict resolution.
- **Schema (Alembic) applied once, replicated.** Migrations are the source of
  truth; they must not be run against two writable nodes and risk a DDL
  conflict.
- **Meets all five constraints** (active-active, no Bitnami, no operator,
  docker-compose dev, no custom image build).
- **Row-level locks stay cluster-wide.** ADR-0029's `FOR UPDATE SKIP LOCKED`
  queue claim depends on row locks being shared across the writable nodes.
- **Advisory-lock behavior is documented, not assumed.** Advisory locks are
  session-local; their behavior across active-active nodes must be stated as an
  assumption the election tolerates.

#### Considered Options

- **pgEdge / Spock (chosen).** A Postgres distribution (fork) whose
  `ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal` image ships the Spock
  multi-master extension pre-installed (constraint 5), has a first-party
  docker-compose two-node example (constraint 4), and can be wrapped in a thin
  operator-less Helm chart with a run-once init `Job` (constraint 3). Spock
  provides bi-directional (active-active) replication, `autoddl` (DDL
  replicated, so Alembic runs once), and per-table conflict policies.

- **pgactive (AWS extension).** A Postgres *extension* (BDR-based, open-
  sourced 2025) with last-write-wins conflict resolution. Meets the active-
  active + no-operator + no-Bitnami constraints, but **requires building the
  image** (compile the C extension into a Postgres base) — it fails constraint
  5 — and DDL must be applied per node (no `autoddl`), so Alembic would run
  against two nodes.

- **Citus + Patroni.** A Postgres extension for *sharded* distributed tables
  with Patroni HA. Has an image and a compose, but it is **sharding, not
  multi-primary on a single row**: the `leader_lease` row would be a Citus
  reference table (replicated but single-writable on the coordinator), which
  defeats the active-active purpose for the election and the ADR-0029 queue.
  Wrong model for this decision.

- **Stock Postgres + Patroni (active-passive).** Meets no-Bitnami / no-operator-
  in-the-queue / compose / no-build, and is the simplest HA, but it is
  **active-passive** (one writer, failover promotes) — it fails constraint 1
  (no simultaneous two-writer). Rejected on the active-active requirement.

#### Decision Outcome

**Chosen option: pgEdge / Spock, wrapped in a thin operator-less Helm chart,
with a strict fencing token on `leader_lease`.**

**Image.** `ghcr.io/pgedge/pgedge-postgres:17-spock5-minimal` (Spock + lolor +
snowflake pre-baked; no build). If a migration or app path needs an extension
not in the `minimal` flavor, step up to the `standard` flavor — still a
pre-built image, no custom build.

**Helm (no operator).** A thin chart section in `charts/kubedash/` (or a
sibling chart) that deploys, with **no controller**:

- a `StatefulSet` (`replicas: 2`) on the pgEdge image, with
  `volumeClaimTemplates` for the data dir (`PGDATA` subpath);
- a **headless** `Service` (for the StatefulSet's stable per-node DNS) plus a
  regular `Service` (the app's connection target);
- a **run-once `Job`** (the only "operator-ish" piece — a plain `Job`, not a
  controller) that, after both nodes are up, runs the Spock wiring SQL
  (`spock.node_add` / the bi-directional subscriptions) once. After it runs,
  the two nodes replicate on their own; the `Job` does not persist.

This satisfies "no operator": there is no long-lived reconcile loop, only the
StatefulSet + Services + a one-shot `Job`.

**Dev (docker-compose).** `dev/` gains a two-node pgEdge compose from
`pgEdge/pgedge-docker`: a `db.json` declaring nodes `n1` + `n2` with
`autoddl:enabled`, and the first-party `bootstrap.sh` that wires Spock on first
boot. `docker compose up` → two nodes; `SELECT * FROM spock.node` shows both.
The backend's `KUBEDASH_DATABASE_URL` points at `n1` (dev does not need write
load-balancing).

**`autoddl` for migrations.** With `autoddl:enabled`, DDL executed on one node
replicates to the other. Alembic therefore runs **against one node only** and
the schema change appears on both — migrations stay the single source of truth
without a two-node DDL race. (This is a decisive fit: the codebase's rule is
"migrations are the source of truth; never hand-edit the schema.")

**Strict fencing token on `leader_lease`.** The mechanism that keeps the
election correct under active-active last-write-wins:

- Add a monotonic `fence` column to `leader_lease` (integer, starts 0).
- **On acquire**, the winner does
  `UPDATE leader_lease SET replica_id=:rid, token=:tok, fence=fence+1, ...
   WHERE id=1 RETURNING fence` and stores the returned `fence` in memory.
- **Strict check on every write.** *Every* leader-gated task DB-write (and the
  heartbeat) carries the leader's in-memory `fence` and is conditioned on it:
  `... WHERE id=1 AND fence = :my_fence`. If the leader lost the lease row to
  another node (an LWW conflict picked the other's upsert), its `fence` no
  longer matches → its write affects 0 rows → it observes the mismatch, sets
  `_is_leader = False`, and stops writing. The stale leader is fenced out of
  *all* writes, not just the heartbeat.

  This is the **strict** scope (chosen over a heartbeat-only fence): a stale
  leader is rejected on every task write, closing the split-brain write window
  rather than relying on the 10 s staleness window to catch it.

**Advisory-lock assumption (documented).** `pg_try_advisory_lock(hashtext(:rid))`
(ADR-0008's mutex) is **session-local** and is *not guaranteed to replicate*
across Spock nodes. The election tolerates this: the `leader_lease` row (which
*is* replicated) + the 10 s `heartbeat_at` staleness check + the strict fence
above are the source of truth; the advisory lock only prevents two *concurrent*
acquisitions on the same node/engine from double-acquiring. On a node loss the
advisory lock dies with its session, and a follower takes a fresh lock after
the staleness window — unchanged from ADR-0008. The ADR records this so the
advisory lock is not mistaken for a cross-node guarantee.

##### Consequences

- Good, because Postgres becomes **active-active** — a node loss does not
  open a read-only promotion gap; both nodes keep serving reads and writes.
- Good, because **pgEdge is the only option meeting all five constraints**
  (active-active + no Bitnami + no operator + docker-compose dev + no custom
  image build); the pre-baked image and first-party compose make the dev loop
  trivial.
- Good, because **`autoddl`** means Alembic runs once and the schema
  replicates — migrations stay the single source of truth under two writable
  nodes.
- Good, because the **strict fence** makes the leader election correct under
  last-write-wins: a stale leader's writes are rejected row-by-row, so there is
  never a window where two leaders both commit task state.
- Good, because ADR-0029's `FOR UPDATE SKIP LOCKED` queue claim stays correct
  — row-level locks are cluster-wide under Spock, so exactly-once claim holds
  across both writable nodes.
- Bad, because pgEdge is a **fork**: the Postgres version cadence is pgEdge's
  (they ship 16/17/18), not the upstream release train. Acceptable for a
  dashboard, but it is a pinned-cadence dependency.
- Bad, because the **init `Job`** is a one-shot that must be idempotent and
  must handle the "node B came up after the Job ran" case (re-run on scale);
  it is the one piece of active-active wiring that is not automatic.
- Bad, because the **strict fence** adds a `fence` condition to every task
  write and a `RETURNING fence` to acquire — more SQL and one more invariant to
  test than ADR-0008's bare lease row.
- Bad, because the advisory lock is now an *assumption-tolerated* mechanism
  rather than a cross-node guarantee; a future reader must not "fix" the
  election to rely on the advisory lock across nodes.

##### Confirmation

- **Dev compose:** `docker compose up` in `dev/` brings two pgEdge nodes;
  `SELECT * FROM spock.node` lists both; a row written on `n1` is readable on
  `n2` (and vice versa) within the replication window.
- **Fencing (the load-bearing test):** with two nodes writable, force an LWW
  conflict on the `leader_lease` row (two nodes acquire near-simultaneously);
  the loser's subsequent heartbeat *and* task write affect 0 rows (fence
  mismatch), it demotes, and only one leader commits task state. No double-
  committed task row.
- **`autoddl`:** run an Alembic migration against `n1` only; the new table /
  column appears on `n2` without running Alembic there.
- **Advisory lock:** confirm (and record the result) whether
  `pg_try_advisory_lock` is visible across the two Spock nodes in the deployed
  version; the election is correct either way, but the ADR's assumption is
  stated against the measured behavior.
- **Helm (no operator):** `helm template` of the chart renders a StatefulSet +
  Services + one `Job` and **no** Deployment/CRD for a DB operator; the `Job`
  runs once and completes.
- The ADR-0008 advisory-lock + lease-row core is unchanged except for the added
  `fence` column and the strict write-condition.

#### Pros and Cons of the Options

##### pgEdge / Spock (chosen)

- Good, because it is the only option meeting all five constraints: pre-baked
  active-active image (no build), first-party docker-compose, wrappable in a
  thin operator-less chart, `autoddl` for one-shot migrations, cluster-wide
  row locks for the ADR-0029 queue.
- Neutral, because it is a Postgres fork (a known, shipped cadence: 16/17/18).
- Bad, because the fork pins the Postgres version cadence to pgEdge's, and the
  init `Job` is manual one-shot wiring that must be idempotent.

##### pgactive (AWS extension)

- Good, because it is an extension on stock Postgres (no fork cadence) with
  LWW conflict resolution + a conflict-history table.
- Neutral, because it meets active-active / no-operator / no-Bitnami.
- Bad, because it requires **building the image** (fails the no-build
  constraint) and has no `autoddl` (DDL per node → Alembic against two nodes).

##### Citus + Patroni

- Good, because it is production-proven, has an image + compose, and scales
  *data* across nodes.
- Neutral, because it is a Postgres extension (no fork).
- Bad, because it is **sharding, not multi-primary on a single row** — the
  `leader_lease` row becomes a single-writable reference table, defeating the
  active-active purpose for the election and the queue.

##### Stock Postgres + Patroni (active-passive)

- Good, because it is the simplest, most proven HA, and meets no-Bitnami /
  compose / no-build.
- Neutral, because the app-level leader election already survives the failover
  window (ADR-0008).
- Bad, because it is **active-passive** — one writer, a read-only promotion gap
  on node loss — so it fails the active-active requirement (constraint 1).

#### More Information

- Supersedes ADR-0008 (leader election via PG advisory lock + lease table).
  ADR-0008 had no body file (index-only); this is the first file to carry the
  election / deployment-shape decision. The advisory-lock + lease-row core is
  preserved; the single-writable assumption is replaced by active-active + a
  strict fencing token.
- Pairs with ADR-0029 (queue on Postgres) and ADR-0030 (revocation on Postgres):
  this ADR makes the Postgres that hosts both active-active. Together the three
  remove Redis and make Postgres the sole, HA stateful dependency.
- The strict fence is the active-active-specific addition; on a single-writable
  Postgres it is inert (the fence always matches) and costs only the extra
  column + write-condition.
- Revisit triggers: (a) if pgEdge's fork cadence blocks a needed Postgres
  version, re-evaluate pgactive with a maintained pre-built image; (b) if the
  task set grows high-throughput fan-out, re-evaluate whether the active-active
  write concurrency is worth its fencing cost versus active-passive + fast
  failover.
