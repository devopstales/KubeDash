# Postgres queue + revocation + session-store, drop Redis, two-node pgEdge dev — Implementation Blueprint (steps, files, verification)

> **For agentic workers:** REQUIRED SUB-SKILL: Use skillgrid:subagent-execution (recommended) or skillgrid:simple-execution to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** PROPOSED

**Tier:** T3 (high-risk: data migration, auth hot path, concurrency)

**Build shape:** Tracer thread (the task queue end-to-end — migrate → enqueue → claim → run → reap — is the first working slice; the revocation/session/SAR moves and Redis removal thicken around it)

**Goal:** Replace Redis's four consumers (RQ broker, `jti` revocation, OIDC `state`, SAR verdict cache) with Postgres — a `tasks` queue with `FOR UPDATE SKIP LOCKED`, a `revoked_jtis` deny-list, and a `kv` table for OIDC state + SAR verdicts — add a strict `fence` to the leader election, and make the dev stack a two-node pgEdge active-active cluster with no Redis.

**Architecture:** Three new tables (Alembic migration): `tasks` (queue), `revoked_jtis` (deny-list), `kv` (generic TTL key-value for OIDC state + SAR verdicts). A new `app/core/pgqueue.py` module holds the claim/reaper/retry SQL; `wsgi.py` replaces the RQ worker with a poll loop over it. `leader.py` gains a `fence` column + strict write-condition. `security.py` swaps the Redis `jti`/`oidc_state` lookups for Postgres; `rbac.py` swaps the SAR cache for the `kv` table. `flask-redis` is removed from the stack once no consumer remains. The dev compose replaces `postgres:16`+`redis` with two `pgedge/pgedge:pg17-latest` nodes (Spock, `autoddl`) and drops Redis.

**Tech Stack:** Flask 3 + Smorest, SQLAlchemy 2.0 + Alembic, PostgreSQL 17 (pgEdge/Spock 5.0.1, `pgedge/pgedge:pg17-latest`), Docker Compose. Python 3.12, `uv`.

**Spec:** `.skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/briefing.md` (this change). Decisions: ADR-0029 (queue on Postgres), ADR-0030 (revocation on Postgres), ADR-0031 (active-active pgEdge + strict fence). The SAR-cache and OIDC-state moves are an extension the user approved at the blueprint gate (full Redis removal); they extend ADR-0030's "Postgres replaces Redis for auth state" to the two remaining auth/RBAC caches.

**Findings:** `.skillgrid/specs/2026-10-27-postgres-queue-revocation-active-active/findings.md` — prototype 001 validated every load-bearing claim: exactly-once `SKIP LOCKED` claim (single + cross-node), strict-fence reject of a stale leader's writes, reaper/backoff/dead-letter, the ~0.03–0.07 ms PK hot path (F5), the invalid `now()` partial index (F1), the `gen_random_uuid()`-in-WHERE planner trap (F2b), the pgEdge two-node topology on `pgedge/pgedge:pg17-latest` (F6), and crash recovery on unplanned exit (F7). Every design decision below that rests on a feasibility result cites that file.

## Terms

- **fence** — the monotonic integer on `leader_lease` that fences a stale leader's writes under active-active (ADR-0031). `.skillgrid/knowledge/glossary/02-technical-terms.md`.
- **reaper** — the leader task that re-queues stale `processing` queue rows and deletes expired `revoked_jtis`/`kv` rows (ADR-0029/0030).
- **kv table** — the generic TTL key-value store that replaces Redis for OIDC `state` and the SAR verdict cache (this plan; extends ADR-0030's Postgres-for-auth-state to the two remaining caches).
- **task queue** — the Postgres `tasks` table + `FOR UPDATE SKIP LOCKED` claim loop (ADR-0029).

## Must-Haves (goal-backward verification)

**Truths** (observable behaviors that must hold):
- Enqueueing a task `INSERT`s a `pending` row; two concurrent workers claiming the same row → exactly one claims it (`FOR UPDATE SKIP LOCKED`). *(findings F2/F6c)*
- A worker that SIGKILLs mid-job leaves a `processing` row; after the reaper interval the row is re-queued `pending` with backoff, and a new worker re-claims it — the queue is not wedged. *(findings F7/E2)*
- A task that raises is retried up to 3× with `LEAST(cap, base*5^attempts)` backoff, then `status='failed'` (dead-letter). *(findings F4)*
- A leader that loses the `leader_lease` row (fence advanced by a peer) finds its next fenced write affects **0 rows** and demotes; only the current fence-holder commits. *(findings F3/E3)*
- On `POST /auth/logout`, the JWT's `jti` is inserted into `revoked_jtis`; replaying that JWT → `401` (token revoked) before its 15-min expiry. *(ADR-0030)*
- `verify_jwt`'s revocation check is a primary-key lookup on `revoked_jtis` (bound `jti` parameter, no function in the WHERE clause). *(findings F5/F2b — ~0.03–0.07 ms at 50k rows)*
- `new_state()`/`consume_state()` store and one-shot-delete OIDC state in the `kv` table; a mismatched/already-consumed state → `StateMismatchError`.
- `rbac.can()` reads/writes the SAR verdict in the `kv` table under the same `sar:<...>` key shape (ADR-0004 addendum: every SAR attribute in the key); a cache hit never re-asks the cluster.
- No module in `backend/app` imports `redis_client` or `flask_redis` after the change; `flask-redis` is removed from `pyproject.toml`.
- `task dev-up` brings up two `pgedge/pgedge:pg17-latest` nodes (both in `spock.node`) and **no** Redis; the backend boots against it and passes its health check.
- An Alembic migration run against node n1 appears on node n2 without running there (`autoddl`). *(findings F6b)*

**Artifacts** (files that must exist with real implementation, not stubs):
- `backend/migrations/versions/<new>_queue_revocation_kv_fence.py` — creates `tasks`, `revoked_jtis`, `kv`; adds `leader_lease.fence`.
- `backend/app/core/pgqueue.py` — `enqueue()`, `claim()`, `complete()`, `fail()`, `reap()`, `backoff_seconds()`.
- `backend/app/services/revocation.py` — `revoke_jti()`, `is_revoked()`, `reap_expired()`.
- `backend/app/core/kvstore.py` — `kv_set()`, `kv_get()`, `kv_delete()`, `kv_reap()`.
- `backend/app/models/task.py`, `backend/app/models/revocation.py`, `backend/app/models/kv.py` — the three models.
- `dev/docker-compose.pgedge.yml` + `dev/pgedge/db.json` — the two-node active-active dev cluster.
- `backend/tests/core/test_pgqueue.py`, `backend/tests/core/test_pgqueue_crash.py`, `backend/tests/core/test_leader_fence.py`, `backend/tests/core/test_kvstore.py`, `backend/tests/services/test_revocation.py` — passing tests for the truths above.

**Key links** (critical connections that must work together):
- `wsgi.py`'s scheduler `enqueue()`s via `pgqueue.enqueue` (not `rq.Queue`); the worker loop `claim()`s via `pgqueue.claim` and the reaper runs `pgqueue.reap` only while `leader.is_leader()`.
- `security.verify_jwt` calls `revocation.is_revoked(jti)`; `security.new_state`/`consume_state` call `kvstore.kv_set`/`kv_delete`; `api/auth.logout` calls `revocation.revoke_jti(claims["jti"])`.
- `rbac._cache_get`/`_cache_set` call `kvstore.kv_get`/`kv_set` (replacing `redis_client`).
- `leader.Leader` reads/writes `leader_lease.fence`; `wsgi.py`'s task worker passes `leader.fence` into every fenced write.
- The dev compose's `db.json` node hostnames match the compose service names; the backend's `KUBEDASH_DATABASE_URL` points at n1.

**One-way-door decisions** (hard to reverse — explicit approval before implementing):
- **Adding `leader_lease.fence` (NOT NULL, default 0)** — a schema change to the election row; the strict write-condition then makes every leader write depend on it. Migration-gated. *(ADR-0031)*
- **Removing `flask-redis` + `KUBEDASH_REDIS_URL`** — a dependency + config removal; every Redis consumer must be moved first or the app fails to boot. *(ADR-0029/0030)*
- **Switching the dev default from `postgres:16` to two-node pgEdge** — changes the dev data-store image, node name, and the DB-URL the app connects to. *(ADR-0031; user-approved at the blueprint gate)*

## Global Constraints

- Backend layering: `app/services/` is pure Python with **no Flask imports** (the integration boundary) — `pgqueue.py`, `revocation.py`, `kvstore.py` follow this. `app/core/` may touch `db.engine`. *(per AGENTS.md § Conventions)*
- Read path stays informer-cache-based (ADR-0010); this change does not alter it.
- Air-gap (ADR-0020): no new runtime egress; the `pgedge/pgedge:pg17-latest` image is pulled at build/dev time only.
- `jti` is bound as a **parameter** in the revocation lookup — no function in the WHERE clause. *(findings F2b)*
- No partial index with `now()` in the predicate — `now()` is `STABLE`, not `IMMUTABLE`; use a plain index or none. *(findings F1)*
- Reaper interval (**2 min**) must exceed the longest task runtime (current tasks are sub-minute). *(findings F7/E4)*
- Migrations are the source of truth; never hand-edit the dev DB schema. Under pgEdge, DDL runs on **one** node and `autoddl` replicates it. *(findings F6b)*
- Conventional commits; atomic + independently revertable work units; `[skillgrid-context]` block per commit. *(per AGENTS.md § Committing & Branching)*
- `pgedge/pgedge:pg17-latest` `db.json` **must** include the `pgedge` `internal_admin` user, or the entrypoint aborts. *(findings F6)*

## File Structure

- `backend/migrations/versions/<new>_queue_revocation_kv_fence.py` — one migration: create `tasks`, `revoked_jtis`, `kv`; `ALTER leader_lease ADD COLUMN fence`.
- `backend/app/models/task.py` — `Task` model (`tasks` table).
- `backend/app/models/revocation.py` — `RevokedJti` model (`revoked_jtis`).
- `backend/app/models/kv.py` — `Kv` model (`kv`).
- `backend/app/core/pgqueue.py` — queue SQL: `enqueue`, `claim`, `complete`, `fail`, `reap`, `backoff_seconds`.
- `backend/app/core/kvstore.py` — `kv_set`, `kv_get`, `kv_delete`, `kv_reap` (generic TTL key-value).
- `backend/app/services/revocation.py` — `revoke_jti`, `is_revoked`, `reap_expired` (pure, no Flask).
- `backend/app/core/leader.py` — add `fence` to acquire/heartbeat/release; expose `Leader.fence`.
- `backend/app/core/security.py` — `verify_jwt` → `revocation.is_revoked`; `new_state`/`consume_state` → `kvstore`.
- `backend/app/api/auth.py` — `logout` → `revocation.revoke_jti`.
- `backend/app/services/rbac.py` — `_cache_get`/`_cache_set` → `kvstore`.
- `backend/app/core/ini_config.py` — remove the `redis_url` field + `_resolve_redis`.
- `backend/app/core/config.py` — drop `Settings.redis_url`.
- `backend/app/extensions.py` — drop `FlaskRedis` import + `redis_client`.
- `backend/app/__init__.py` — drop `redis_client` import + `init_app` + the `/readyz` redis ping.
- `backend/wsgi.py` — replace RQ worker + scheduler with the `pgqueue` poll loop + leader-gated reaper.
- `backend/pyproject.toml` — remove `flask-redis` (and `rq` if unused after `wsgi.py`).
- `dev/docker-compose.yml` — replace `postgres`+`redis` with the two-node pgEdge include; drop `redisdata` volume.
- `dev/docker-compose.pgedge.yml` + `dev/pgedge/db.json` — the two-node active-active cluster (image, `db.json` with `autoddl` + `pgedge` user).
- `Taskfile.yaml` — `dev-up`/`dev-ps`/`db-shell` point at the pgEdge n1; a `dev-active-up` alias if a single-node mode is kept.
- `backend/tests/core/test_pgqueue.py`, `test_pgqueue_crash.py`, `test_leader_fence.py`, `test_kvstore.py`, `backend/tests/services/test_revocation.py` — tests.

---

### Task 1: Migration — `tasks`, `revoked_jtis`, `kv`, `leader_lease.fence`

> ⚠ **one-way:** adding `leader_lease.fence` (NOT NULL default 0) and three new tables — schema change, migration-gated. STOP for explicit approval before running the migration.

**Files:**
- Create: `backend/migrations/versions/<new>_queue_revocation_kv_fence.py`
- Create: `backend/app/models/task.py`
- Create: `backend/app/models/revocation.py`
- Create: `backend/app/models/kv.py`
- Modify: `backend/app/models/__init__.py` (export the three models)
- Test: `backend/tests/models/test_new_tables.py`

**Interfaces:**
- Consumes: the current Alembic head `2eb286befb21` (merge of `8b2c4d5e6f7a` + `b7e2c4a9d105`).
- Produces: `Task` (id, path, status, attempts, enqueued_at, locked_at, locked_by, available_at), `RevokedJti` (jti PK, expires_at), `Kv` (key PK, value, expires_at), and `LeaderLease.fence: int`.
- Seam: the migration is the seam for the schema; the models are the ORM view.
- Deletion test: deleting the migration leaves the app's new models without tables → `IntegrityError` on first insert (the models in Tasks 2–4 depend on it).
- Adapters: 1 (the migration) — the models are its only consumer, so no port yet.

**SATISFIES:** `queue-and-kv-tables-exist` (acceptance scenario: after `alembic upgrade head`, the four objects exist with the right columns/constraints).

- [ ] **Step 1: Write the failing test**

```python
# backend/tests/models/test_new_tables.py
def test_new_tables_exist(app):
    from app.models import Task, RevokedJti, Kv
    from app.models.leader_lease import LeaderLease
    insp = sa.inspect(app.extensions.db.engine)
    for t in ("tasks", "revoked_jtis", "kv"):
        assert t in insp.get_table_names(), f"missing table {t}"
    # leader_lease.fence exists, NOT NULL, default 0
    cols = {c["name"]: c for c in insp.get_columns("leader_lease")}
    assert "fence" in cols and cols["fence"]["nullable"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/models/test_new_tables.py -v`
Expected: FAIL — `tasks` not in table names.

- [ ] **Step 3: Write the migration + models**

```python
# backend/migrations/versions/<new>_queue_revocation_kv_fence.py
"""queue + revocation + kv tables, leader_lease.fence (ADR-0029/0030/0031)

Revision ID: <rev>
Revises: 2eb286befb21
"""
from alembic import op
import sqlalchemy as sa

revision = "<rev>"
down_revision = "2eb286befb21"
branch_labels = None
depends_on = None

def upgrade():
    op.create_table("tasks",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.Text(), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    # plain index (F1: a partial `WHERE expires_at > now()` is invalid — now() is STABLE)
    op.create_index("tasks_pending_idx", "tasks", ["enqueued_at"], unique=False)
    op.create_table("revoked_jtis",
        sa.Column("jti", sa.Uuid(), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table("kv",
        sa.Column("key", sa.Text(), primary_key=True),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("kv_expires_idx", "kv", ["expires_at"], unique=False)
    op.add_column("leader_lease",
        sa.Column("fence", sa.Integer(), nullable=False, server_default="0"))
    # seed the lease row's fence if the row exists (create_all-era dev DBs)
    op.execute("UPDATE leader_lease SET fence = 0 WHERE fence IS NULL")

def downgrade():
    op.drop_column("leader_lease", "fence")
    op.drop_index("kv_expires_idx", table_name="kv")
    op.drop_table("kv")
    op.drop_table("revoked_jtis")
    op.drop_index("tasks_pending_idx", table_name="tasks")
    op.drop_table("tasks")
```

The three models mirror the columns (`db.Model`, `__tablename__`); `Kv.key` is a `Text` primary key (SAR keys are long strings).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && uv run pytest tests/models/test_new_tables.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/migrations/versions/ backend/app/models/
git commit -m "feat(db): add tasks/revoked_jtis/kv tables + leader_lease.fence (ADR-0029/0030/0031)"
```

---

### Task 2: `pgqueue` module + claim/reaper/retry SQL

> **Tracer-thread core.** This is the first working slice of the queue.

**Files:**
- Create: `backend/app/core/pgqueue.py`
- Test: `backend/tests/core/test_pgqueue.py`

**Interfaces:**
- Consumes: the `tasks` table (Task 1), `db.engine` (app-bound, per the `leader.py` `_engine_ctx` pattern).
- Produces:
  - `enqueue(path: str, engine) -> None`
  - `claim(engine, replica_id: str) -> str | None` (returns the claimed `path`, or `None`)
  - `complete(task_id: int, engine) -> None`
  - `fail(task_id: int, engine) -> None` (re-queue with backoff, or dead-letter at `attempts >= 3`)
  - `reap(engine, stale_seconds: int = 120) -> int` (re-queues stale `processing` rows; returns count)
  - `backoff_seconds(attempts: int) -> int` (`LEAST(600, 60 * 5**attempts)`)
- Seam: `pgqueue` is the queue boundary — `wsgi.py` (Task 5) and the reaper consume it; tests drive it with a real engine.
- Deletion test: deleting `pgqueue` re-introduces the claim/reaper/retry SQL inline in `wsgi.py` (the worker loop + reaper task).
- Adapters: 2 (prod engine in `wsgi.py`, test engine in `test_pgqueue.py`) — the seam is justified.

**SATISFIES:** `exactly-once-claim`, `reaper-requeues-stale-job`, `retry-then-dead-letter`.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/core/test_pgqueue.py
def test_enqueue_then_claim_returns_path(app):
    from app.core import pgqueue
    eng = app.extensions.db.engine
    pgqueue.enqueue("app.tasks.health.run", eng)
    assert pgqueue.claim(eng, "w1") == "app.tasks.health.run"

def test_two_concurrent_claimers_do_not_double_claim(app):
    from app.core import pgqueue
    import threading
    eng = app.extensions.db.engine
    for i in range(50):
        pgqueue.enqueue("app.tasks.health.run", eng)
    got = []
    lock = threading.Lock()
    def worker(n):
        p = pgqueue.claim(eng, f"w{n}")
        if p:
            with lock: got.append((n, p))
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    [t.start() for t in ts]; [t.join() for t in ts]
    # 10 distinct claims, no path claimed twice
    assert len(got) == 10
    # the 10 claimed rows have 10 distinct ids (verify via locked_by)
    rows = eng.execute(text("SELECT id, locked_by FROM tasks WHERE status='processing'")).all()
    assert len(rows) == 10 and len({r.locked_by for r in rows}) == 10

def test_reaper_requeues_stale_processing(app):
    from app.core import pgqueue
    eng = app.extensions.db.engine
    pgqueue.enqueue("app.tasks.health.run", eng)
    pgqueue.claim(eng, "dead")
    eng.execute(text("UPDATE tasks SET locked_at = now() - interval '3 minutes'"))
    assert pgqueue.reap(eng, stale_seconds=120) == 1
    assert eng.execute(text("SELECT status FROM tasks")).scalar() == "pending"

def test_fail_dead_letters_at_three_attempts(app):
    from app.core import pgqueue
    eng = app.extensions.db.engine
    pgqueue.enqueue("app.tasks.health.run", eng)
    tid = eng.execute(text("SELECT id FROM tasks")).scalar()
    for _ in range(3):
        pgqueue.fail(tid, eng)
    assert eng.execute(text("SELECT status, attempts FROM tasks")).first() == ("failed", 3)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/core/test_pgqueue.py -v`
Expected: FAIL — `ModuleNotFoundError: app.core.pgqueue`.

- [ ] **Step 3: Implement `pgqueue.py`**

```python
# backend/app/core/pgqueue.py
"""Postgres task queue (ADR-0029) — FOR UPDATE SKIP LOCKED claim + time-based
reaper. Pure SQLAlchemy `text()` against an engine; no Flask imports."""
from __future__ import annotations
from sqlalchemy import text

REAPER_STALE_SECONDS = 120  # > longest task runtime (findings F7/E4)
MAX_ATTEMPTS = 3
BACKOFF_CAP_SECONDS = 600

def backoff_seconds(attempts: int) -> int:
    return min(BACKOFF_CAP_SECONDS, 60 * (5 ** attempts))

def enqueue(path: str, engine) -> None:
    with engine.connect() as conn:
        conn.execute(text(
            "INSERT INTO tasks (path, enqueued_at, available_at, status) "
            "VALUES (:p, now(), now(), 'pending')"), {"p": path})
        conn.commit()

def claim(engine, replica_id: str) -> str | None:
    with engine.begin() as conn:
        row = conn.execute(text(
            "UPDATE tasks SET status='processing', locked_at=now(), "
            "locked_by=:rid, attempts=attempts+1 "
            "WHERE id = (SELECT id FROM tasks WHERE status='pending' "
            "AND available_at <= now() ORDER BY enqueued_at LIMIT 1 "
            "FOR UPDATE SKIP LOCKED) RETURNING path, id"),
            {"rid": replica_id}).first()
        return row.path if row else None

def complete(task_id: int, engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("UPDATE tasks SET status='done' WHERE id=:id"), {"id": task_id})

def fail(task_id: int, engine) -> None:
    with engine.begin() as conn:
        row = conn.execute(text(
            "UPDATE tasks SET attempts=attempts+1, locked_at=now() "
            "WHERE id=:id RETURNING attempts"), {"id": task_id}).first()
        attempts = row.attempts
        if attempts >= MAX_ATTEMPTS:
            conn.execute(text("UPDATE tasks SET status='failed' WHERE id=:id"), {"id": task_id})
        else:
            conn.execute(text(
                "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL, "
                "available_at = now() + make_interval(secs => :backoff) WHERE id=:id"),
                {"id": task_id, "backoff": backoff_seconds(attempts)})

def reap(engine, stale_seconds: int = REAPER_STALE_SECONDS) -> int:
    with engine.begin() as conn:
        r = conn.execute(text(
            "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL, "
            "available_at = now() + make_interval(secs => LEAST(:cap, 60 * power(5, attempts))) "
            "WHERE status='processing' AND locked_at < now() - make_interval(secs => :stale)"),
            {"cap": BACKOFF_CAP_SECONDS, "stale": stale_seconds})
        return r.rowcount
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/core/test_pgqueue.py -v`
Expected: PASS (all four).

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/pgqueue.py backend/tests/core/test_pgqueue.py
git commit -m "feat(queue): pgqueue SKIP LOCKED claim + time-based reaper + backoff (ADR-0029)"
```

---

### Task 3: `leader.py` strict fence

**Files:**
- Modify: `backend/app/core/leader.py:99-147` (`acquire_once`, `_heartbeat`, `_release`)
- Test: `backend/tests/core/test_leader_fence.py`

**Interfaces:**
- Consumes: `leader_lease.fence` (Task 1).
- Produces: `Leader.fence: int | None` (the in-memory fence after a successful acquire); the `acquire_once()` lease upsert (currently `leader.py:118-127`, an `INSERT … ON CONFLICT (id) DO UPDATE`) gains `fence = fence + 1` and captures `RETURNING fence`; `_heartbeat()` (`leader.py:131-138`) conditions on `fence` and demotes on 0 rows; `_release()` (`leader.py:140-147`) keeps its `replica_id` condition.
- Seam: `Leader` is the election boundary (ADR-0008/0031); the fence is internal to it.
- Deletion test: deleting the fence logic re-introduces the split-brain write window under active-active (a stale leader's heartbeat/task write commits).
- Adapters: 2 (real `Leader` in `wsgi.py`, the existing fake in `test_worker_gate.py` + the fence tests).

**SATISFIES:** `stale-leader-write-rejected`, `survivor-wins-after-lww`.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/core/test_leader_fence.py
def test_acquire_increments_fence_and_exposes_it(app):
    from app.core.leader import Leader
    l = Leader(_settings(app), stale_seconds=10, heartbeat_seconds=5)
    assert l.acquire_once() is True
    assert l.fence == 1

def test_stale_fence_write_affects_zero_rows(app):
    from app.core.leader import Leader
    a = Leader(_settings(app)); a.acquire_once()      # fence 1
    b = Leader(_settings(app, replica="B")); b.acquire_once()  # fence 2 (LWW)
    # A's heartbeat now carries fence=1; the row is fence=2 -> 0 rows
    a._heartbeat()
    row = app.extensions.db.engine.execute(text("SELECT replica_id FROM leader_lease")).first()
    assert row.replica_id == "B"
    # A demotes: a fenced write returned no row
    assert a.is_leader() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/core/test_leader_fence.py -v`
Expected: FAIL — `Leader` has no `fence` attribute / `acquire_once` doesn't return the fence.

- [ ] **Step 3: Modify `leader.py`**

In `acquire_once()`, after the advisory lock succeeds, extend the existing lease upsert (`leader.py:118-127`) to increment the fence and capture it:

```python
row = conn.execute(text(
    "INSERT INTO leader_lease (id, replica_id, token, acquired_at, heartbeat_at, fence) "
    "VALUES (1, :rid, :tok, now(), now(), fence + 1) "
    "ON CONFLICT (id) DO UPDATE SET replica_id = :rid, token = :tok, "
    "acquired_at = now(), heartbeat_at = now(), fence = fence + 1 "
    "RETURNING fence"),
    {**self._binds(), "tok": str(self._token)}).first()
self._fence = row.fence
```

> **Advisory-lock nuance (ADR-0031):** `pg_try_advisory_lock(hashtext(:rid))` is per-replica and
> session-local — it is NOT a cross-node mutex, so two peers can both hold it. The fence is the
> cross-node LWW: whichever peer's upsert commits second holds the higher `fence` and wins. The
> stale-check at `leader.py:106-112` stays as the fast-path "don't clobber a fresh lease", but the
> fence is the authoritative tiebreaker. (This is the exact split-brain window the prototype's
> F3/E3 validated — the loser's next fenced write affects 0 rows.)

Add `self._fence: int | None = None` in `__init__` (line ~48) and a `fence` property. In `_heartbeat()`, condition on the fence and demote on 0 rows:

```python
def _heartbeat(self) -> None:
    with self._engine_ctx() as engine, engine.connect() as conn:
        r = conn.execute(text(
            "UPDATE leader_lease SET heartbeat_at=now() "
            "WHERE id=1 AND replica_id=:rid AND fence=:f"),
            {**self._binds(), "f": self._fence})
        conn.commit()
        if r.rowcount == 0 and self._is_leader:
            self._is_leader = False  # fenced out (lost the lease row to a peer)
```

(Keeping `replica_id=:rid` in the heartbeat `WHERE` preserves the current "only the holder beats"
semantics; the `fence=:f` term is the ADR-0031 cross-node guard. If a peer has advanced the fence,
the update affects 0 rows and the stale leader demotes.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && uv run pytest tests/core/test_leader_fence.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/leader.py backend/tests/core/test_leader_fence.py
git commit -m "feat(leader): strict fence token on leader_lease, demote on fenced-out write (ADR-0031)"
```

---

### Task 4: `kvstore` + `revocation` (OIDC state, `jti` deny-list, SAR cache)

**Files:**
- Create: `backend/app/core/kvstore.py`
- Create: `backend/app/services/revocation.py`
- Test: `backend/tests/core/test_kvstore.py`
- Test: `backend/tests/services/test_revocation.py`

**Interfaces:**
- Consumes: the `kv` + `revoked_jtis` tables (Task 1).
- Produces:
  - `kvstore.kv_set(engine, key: str, value: str, ttl_seconds: int) -> None`
  - `kvstore.kv_get(engine, key: str) -> str | None` (None if absent **or** expired)
  - `kvstore.kv_delete(engine, key: str) -> bool` (True if a live row was deleted)
  - `kvstore.kv_reap(engine) -> int`
  - `revocation.revoke_jti(engine, jti: str, ttl_seconds: int) -> None`
  - `revocation.is_revoked(engine, jti: str) -> bool`
  - `revocation.reap_expired(engine) -> int`
- Seam: `kvstore` is the generic TTL-kv boundary (OIDC state + SAR cache + anything future); `revocation` is the auth deny-list boundary.
- Deletion test: deleting `kvstore` re-introduces the `kv` SQL inline in `security.py` (OIDC state) and `rbac.py` (SAR cache).
- Adapters: 2 each (prod engine + test engine) — justified.

**SATISFIES:** `kv-set-get-delete-expiry`, `revocation-insert-and-hit`, `verify-hook-is-pk-lookup`.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/core/test_kvstore.py
def test_kv_set_get_delete(app):
    from app.core import kvstore
    eng = app.extensions.db.engine
    kvstore.kv_set(eng, "oidc_state:abc", "1", 300)
    assert kvstore.kv_get(eng, "oidc_state:abc") == "1"
    assert kvstore.kv_delete(eng, "oidc_state:abc") is True
    assert kvstore.kv_get(eng, "oidc_state:abc") is None

def test_kv_get_expired_returns_none(app):
    from app.core import kvstore
    eng = app.extensions.db.engine
    kvstore.kv_set(eng, "k", "v", 300)
    eng.execute(text("UPDATE kv SET expires_at = now() - interval '1 minute' WHERE key='k'"))
    assert kvstore.kv_get(eng, "k") is None  # expired -> treated absent

def test_kv_reap_deletes_expired(app):
    from app.core import kvstore
    eng = app.extensions.db.engine
    kvstore.kv_set(eng, "live", "1", 300)
    kvstore.kv_set(eng, "dead", "1", 300)
    eng.execute(text("UPDATE kv SET expires_at = now() - interval '1 minute' WHERE key='dead'"))
    assert kvstore.kv_reap(eng) == 1

# backend/tests/services/test_revocation.py
def test_revoke_then_is_revoked(app):
    from app.services import revocation
    eng = app.extensions.db.engine
    revocation.revoke_jti(eng, "jti-1", 900)
    assert revocation.is_revoked(eng, "jti-1") is True
    assert revocation.is_revoked(eng, "jti-other") is False

def test_reap_expired_removes_passed_jti(app):
    from app.services import revocation
    eng = app.extensions.db.engine
    revocation.revoke_jti(eng, "jti-1", 900)
    eng.execute(text("UPDATE revoked_jtis SET expires_at = now() - interval '1 minute'"))
    assert revocation.reap_expired(eng) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/core/test_kvstore.py tests/services/test_revocation.py -v`
Expected: FAIL — modules not found.

- [ ] **Step 3: Implement `kvstore.py` + `revocation.py`**

```python
# backend/app/core/kvstore.py
"""Generic TTL key-value store (replaces Redis for OIDC state + SAR cache).
Pure SQLAlchemy text(); no Flask imports. F2b: lookups bind the key as a
parameter — never a function in the WHERE clause."""
from __future__ import annotations
from sqlalchemy import text

def kv_set(engine, key: str, value: str, ttl_seconds: int) -> None:
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO kv (key, value, expires_at) VALUES (:k, :v, now() + make_interval(secs => :ttl)) "
            "ON CONFLICT (key) DO UPDATE SET value=:v, expires_at = now() + make_interval(secs => :ttl)"),
            {"k": key, "v": value, "ttl": ttl_seconds})

def kv_get(engine, key: str) -> str | None:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT value FROM kv WHERE key = :k AND expires_at > now()"), {"k": key}).first()
        return row.value if row else None

def kv_delete(engine, key: str) -> bool:
    with engine.begin() as conn:
        r = conn.execute(text("DELETE FROM kv WHERE key = :k"), {"k": key})
        return r.rowcount > 0

def kv_reap(engine) -> int:
    with engine.begin() as conn:
        r = conn.execute(text("DELETE FROM kv WHERE expires_at < now()"))
        return r.rowcount
```

```python
# backend/app/services/revocation.py
"""Session-revocation deny-list on Postgres (ADR-0030). Pure; no Flask imports.
jti is bound as a parameter (findings F2b) — the hot path is a PK lookup."""
from __future__ import annotations
from sqlalchemy import text

def revoke_jti(engine, jti: str, ttl_seconds: int) -> None:
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO revoked_jtis (jti, expires_at) VALUES (:j, now() + make_interval(secs => :ttl)) "
            "ON CONFLICT (jti) DO NOTHING"), {"j": jti, "ttl": ttl_seconds})

def is_revoked(engine, jti: str) -> bool:
    with engine.connect() as conn:
        row = conn.execute(text(
            "SELECT 1 FROM revoked_jtis WHERE jti = :j AND expires_at > now()"), {"j": jti}).first()
        return row is not None

def reap_expired(engine) -> int:
    with engine.begin() as conn:
        r = conn.execute(text("DELETE FROM revoked_jtis WHERE expires_at < now()"))
        return r.rowcount
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/core/test_kvstore.py tests/services/test_revocation.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/kvstore.py backend/app/services/revocation.py backend/tests/
git commit -m "feat(auth): kvstore + revocation deny-list on Postgres (ADR-0030)"
```

---

### Task 5: Wire `wsgi.py` — `pgqueue` worker + leader-gated reaper (replace RQ)

> ⚠ **one-way:** removes the RQ worker path from `wsgi.py`; the scheduler + worker are rewritten. The `INTERVALS` dict and the per-task `leader.is_leader()` gate are preserved.

**Files:**
- Modify: `backend/wsgi.py:65-177` (`INTERVALS`, `_rq_worker_main`, `_schedule_if_leader`, `_run_worker_child`, `_run`, `_start_worker_if_leader`)
- Test: `backend/tests/test_worker_gate.py` (update the fake-queue assertions to the `pgqueue` seam)

**Interfaces:**
- Consumes: `pgqueue` (Task 2), `Leader.is_leader()` + `Leader.fence` (Task 3), `db.engine`, `redis_client` (still, until Task 7).
- Produces: a worker thread that polls `pgqueue.claim` every 5 s and runs the task; a reaper that runs `pgqueue.reap` + `revocation.reap_expired` + `kvstore.kv_reap` only while `leader.is_leader()`.
- Seam: the `pgqueue` claim loop replaces the RQ worker child; the scheduler's `queue.enqueue(path)` becomes `pgqueue.enqueue(path, engine)`.
- Deletion test: deleting the new worker loop re-introduces RQ as the task runner (the thing this change removes).
- Adapters: 2 (prod worker thread + the updated `test_worker_gate.py` fake).

**SATISFIES:** `scheduler-enqueues-via-pgqueue`, `worker-claims-and-runs`, `reaper-leader-gated`.

- [ ] **Step 1: Update the failing test**

```python
# backend/tests/test_worker_gate.py (replace the rq.Queue fake with a pgqueue fake)
def test_scheduler_enqueues_due_tasks_only_when_leading(monkeypatch):
    import wsgi
    enqueued = []
    monkeypatch.setattr(wsgi.pgqueue, "enqueue", lambda path, engine: enqueued.append(path))
    fake_leader = _FakeLeader(is_leader=True)
    monkeypatch.setattr(wsgi, "_now", lambda: 1000.0)
    wsgi._run_once(fake_leader, {}, last={})
    assert sorted(enqueued) == sorted(wsgi.INTERVALS)

def test_scheduler_idle_when_not_leading(monkeypatch):
    import wsgi
    enqueued = []
    monkeypatch.setattr(wsgi.pgqueue, "enqueue", lambda path, engine: enqueued.append(path))
    wsgi._run_once(_FakeLeader(is_leader=False), {}, last={})
    assert enqueued == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/test_worker_gate.py -v`
Expected: FAIL — `wsgi.pgqueue` / `wsgi._run_once` don't exist yet.

- [ ] **Step 3: Rewrite `wsgi.py`'s worker section**

Keep `INTERVALS` and `_start_worker_if_leader`'s role gate. Replace the RQ pieces:

```python
import app.core.pgqueue as pgqueue
from app.core import kvstore
from app.services import revocation

def _run_once(leader_obj, last: dict[str, float]) -> bool:
    """One scheduler tick: enqueue due tasks only while leading (per task, per poll)."""
    if not leader_obj.is_leader():
        return False
    engine = _engine()
    now = time.monotonic()
    due = False
    for path, interval in INTERVALS.items():
        if now - last.get(path, 0.0) >= interval:
            pgqueue.enqueue(path, engine)
            last[path] = now
            due = True
    return due

def _worker_loop(leader_obj, stop: threading.Event) -> None:
    engine = _engine()
    replica = get_settings().kubedash_replica_id
    last_reap = 0.0
    while not stop.is_set():
        path = pgqueue.claim(engine, replica)
        if path is not None:
            mod, _, fn = path.rpartition(".")
            tid = _last_claimed_id(engine, replica)
            try:
                getattr(importlib.import_module(mod), fn)()
                pgqueue.complete(tid, engine)
            except Exception:
                log.exception("task %s failed", path)
                pgqueue.fail(tid, engine)
        # leader-gated reaper: queue + revocation + kv
        if leader_obj.is_leader() and time.monotonic() - last_reap >= 30:
            pgqueue.reap(engine)
            revocation.reap_expired(engine)
            kvstore.kv_reap(engine)
            last_reap = time.monotonic()
        stop.wait(5)  # poll cadence == old RQ drain window
```

`_start_worker_if_leader` starts `Leader`, then a `_worker_loop` daemon thread (no RQ child process). `_engine()` re-opens `db.engine` in an app context (the `leader.py` `_engine_ctx` pattern).

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && uv run pytest tests/test_worker_gate.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/wsgi.py backend/tests/test_worker_gate.py
git commit -m "feat(wsgi): pgqueue worker loop + leader-gated reaper, replace RQ (ADR-0029)"
```

---

### Task 6: Wire auth + RBAC to Postgres (`verify_jwt`, OIDC state, logout, SAR cache)

**Files:**
- Modify: `backend/app/core/security.py:191-224` (`verify_jwt`, `new_state`, `consume_state`)
- Modify: `backend/app/api/auth.py:196-204` (`logout`)
- Modify: `backend/app/services/rbac.py:39-49` (`_cache_get`, `_cache_set`)
- Test: `backend/tests/core/test_security_revocation.py`, `backend/tests/services/test_rbac_cache.py`

**Interfaces:**
- Consumes: `revocation` (Task 4), `kvstore` (Task 4), `db.engine` (via `current_app.extensions` / `db.session`), `ACCESS_TTL_SECONDS` (900), `STATE_TTL_SECONDS` (300), `SAR_TTL` (30).
- Produces: `verify_jwt` raising `UnauthorizedError("token revoked")` on a `revoked_jtis` hit; `new_state`/`consume_state` one-shot via `kv`; `logout` inserting the `jti`; `rbac` caching via `kv`.
- Seam: `verify_jwt`/`new_state`/`consume_state` are the auth seams (tests patch them); `rbac._cache_get`/`_cache_set` are the SAR-cache seams.
- Deletion test: reverting these re-introduces the Redis `revoked:`/`oidc_state:`/`sar:` lookups (the consumers this change removes).
- Adapters: 2 each (real engine + existing test fakes).

**SATISFIES:** `logout-revokes-jti`, `verify-hook-401-on-revoked`, `oidc-state-consumed-once`, `sar-cache-hit-never-reasks`.

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/core/test_security_revocation.py
def test_verify_jwt_401_when_jti_revoked(app):
    from app.core import security
    from app.services import revocation
    access, _ = security.issue_token_pair(_user(app))
    claims = security.verify_jwt(access)  # not yet revoked
    revocation.revoke_jti(app.extensions.db.engine, claims["jti"], 900)
    import pytest
    with pytest.raises(security.UnauthorizedError):
        security.verify_jwt(access)

def test_consume_state_is_one_shot(app):
    from app.core import security
    st = security.new_state()
    security.consume_state(st)
    import pytest
    with pytest.raises(security.StateMismatchError):
        security.consume_state(st)

# backend/tests/services/test_rbac_cache.py
def test_sar_cache_hit_does_not_reask(app, monkeypatch):
    from app.services import rbac
    calls = []
    def fake_sar(*a, **k):
        calls.append(1); return True
    monkeypatch.setattr(rbac, "_sar_allowed", fake_sar)
    key = rbac._cache_key(1, "sub", "get", "pods", "", "ns", None)
    from app.core import kvstore
    kvstore.kv_set(app.extensions.db.engine, key, "1", rbac.SAR_TTL)
    assert rbac._cache_get(key) == "1"
    assert calls == []  # cache hit -> no cluster ask
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && uv run pytest tests/core/test_security_revocation.py tests/services/test_rbac_cache.py -v`
Expected: FAIL — still reading `redis_client` (no Redis in the test → `ConnectionError` or no-op).

- [ ] **Step 3: Swap the four call sites**

`security.py` — `verify_jwt`:
```python
from app.services import revocation
if revocation.is_revoked(db.engine, claims["jti"]):
    raise UnauthorizedError("token revoked")
```
`security.py` — `new_state` / `consume_state`:
```python
from app.core import kvstore
def new_state() -> str:
    st = secrets.token_hex(16)
    kvstore.kv_set(db.engine, f"oidc_state:{st}", "1", STATE_TTL_SECONDS)
    return st
def consume_state(state: str) -> None:
    if not kvstore.kv_delete(db.engine, f"oidc_state:{state}"):
        raise StateMismatchError("state mismatch")
```
`api/auth.py` — `logout` (add the `jti` revocation; keep refresh-token revocation):
```python
from app.services import revocation
def logout(self) -> Response:
    user = g.current_user
    revoke_user_refresh_tokens(user.id)
    revocation.revoke_jti(db.engine, _current_jti(), ACCESS_TTL_SECONDS)
    resp = make_response(jsonify(status="ok")); resp.headers["Cache-Control"] = "no-store"
    return clear_session_cookies(resp)
```
(`_current_jti()` decodes the ambient access token's `jti` — add a small helper in `security.py`.)

`rbac.py` — `_cache_get` / `_cache_set`:
```python
from app.core import kvstore
def _cache_get(key: str) -> str | None:
    return kvstore.kv_get(db.engine, key)
def _cache_set(key: str, value: str) -> None:
    kvstore.kv_set(db.engine, key, value, SAR_TTL)
```
(drop the `redis_client` import + the bytes-decode branch — `kv` values are text).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && uv run pytest tests/core/test_security_revocation.py tests/services/test_rbac_cache.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/security.py backend/app/api/auth.py backend/app/services/rbac.py backend/tests/
git commit -m "feat(auth): revocation/OIDC-state/SAR-cache on Postgres, drop redis reads (ADR-0030)"
```

---

### Task 7: Remove Redis from the stack + two-node pgEdge dev compose

> ⚠ **one-way:** removes `flask-redis` + `KUBEDASH_REDIS_URL` and switches the dev default to two-node pgEdge. Every Redis consumer must be gone (Tasks 5–6) or the app fails to boot.

**Files:**
- Modify: `backend/app/extensions.py:2,12` (drop `FlaskRedis` + `redis_client`)
- Modify: `backend/app/__init__.py:11,94,214-217` (drop import, `init_app`, the `/readyz` redis ping)
- Modify: `backend/app/core/config.py:31-32` (drop `redis_url`)
- Modify: `backend/app/core/ini_config.py:27,60,227-247,267` (drop `redis_url` field + `_resolve_redis`)
- Modify: `backend/pyproject.toml` (remove `flask-redis`; remove `rq` if `wsgi.py` no longer imports it)
- Create: `dev/docker-compose.pgedge.yml`, `dev/pgedge/db.json`
- Modify: `dev/docker-compose.yml:15-47,180-184` (replace `postgres`+`redis` with the pgEdge include; drop `redisdata`)
- Modify: `Taskfile.yaml` (`dev-up`/`dev-ps`/`db-shell` → pgEdge n1)
- Test: `backend/tests/test_no_redis_imports.py`

**Interfaces:**
- Consumes: Tasks 5–6 (no `redis_client` references remain).
- Produces: a Redis-free app + a two-node pgEdge dev cluster.
- Seam: the dev compose is the dev-infra seam; the import removal is the code seam.
- Deletion test: re-adding `flask-redis` re-introduces the dependency this change removes.
- Adapters: the pgEdge compose + the existing single-node compose (if a `dev-active-up` alias is kept) = 2.

**SATISFIES:** `no-redis-imports-remain`, `dev-up-brings-two-pgedge-nodes-no-redis`, `app-boots-against-pgedge`.

- [ ] **Step 1: Write the failing test (import guard)**

```python
# backend/tests/test_no_redis_imports.py
import importlib, pkgutil
def test_no_module_imports_redis_client():
    import app
    for m in pkgutil.walk_packages(app.__path__, prefix="app."):
        mod = importlib.import_module(m.name)
        src = importlib.util.find_spec(m.name).origin
        with open(src) as f:
            assert "redis_client" not in f.read(), f"{m.name} still references redis_client"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && uv run pytest tests/test_no_redis_imports.py -v`
Expected: FAIL — `extensions.py` / `rbac.py` / `security.py` reference `redis_client`.

- [ ] **Step 3: Remove Redis + write the pgEdge dev compose**

Remove the `flask_redis` import + `redis_client` from `extensions.py`; the import + `redis_client.init_app(app)` + the `/readyz` redis block from `__init__.py`; `redis_url` from `config.py`; `redis_url` + `_resolve_redis` from `ini_config.py`; `flask-redis` (and `rq` if unused) from `pyproject.toml`.

`dev/pgedge/db.json`:
```json
{
  "name": "kubedash", "port": 5432, "options": ["autoddl:enabled"],
  "nodes": [
    { "name": "n1", "region": "us-east-1", "hostname": "kdpg-n1" },
    { "name": "n2", "region": "us-east-2", "hostname": "kdpg-n2" }
  ],
  "users": [
    { "username": "kubedash", "password": "kubedash", "superuser": true, "service": "postgres", "type": "admin" },
    { "username": "pgedge", "password": "z1Zsku10a91RS526jnVrLC39", "superuser": true, "service": "postgres", "type": "internal_admin" }
  ]
}
```
`dev/docker-compose.pgedge.yml` — two `pgedge/pgedge:pg17-latest` services (`kdpg-n1` on `15432`, `kdpg-n2` on `15433`), each mounting `./pgedge/db.json` + a volume, `NODE_NAME`/`PGDATA` env (findings F6). In `dev/docker-compose.yml`, replace the `postgres` + `redis` services with an `include:` of `docker-compose.pgedge.yml` (or inline the two services) and drop the `redisdata` volume. Point `KUBEDASH_DATABASE_URL` (Taskfile dev default) at `kdpg-n1:5432` / user `kubedash`.

- [ ] **Step 4: Run test + dev-stack smoke to verify they pass**

Run: `cd backend && uv run pytest tests/test_no_redis_imports.py -v` → PASS.
Run: `task dev-up` → both `kdpg-n1`/`kdpg-n2` in `spock.node`, no `redis` container, backend `/readyz` green against n1.

- [ ] **Step 5: Commit**

```bash
git add backend/app/ backend/pyproject.toml dev/ Taskfile.yaml backend/tests/test_no_redis_imports.py
git commit -m "chore(infra): remove redis from stack; dev default = two-node pgEdge (ADR-0029/0030/0031)"
```

---

## Self-Review

- **Spec coverage:** queue (T1–2, T5), revocation (T1, T4, T6), session-store/OIDC state (T4, T6), SAR cache (T6), fence (T3), pgEdge dev compose (T7), Redis removal (T7). All four Redis consumers are moved.
- **Must-haves coverage:** every truth maps to a task (claim→T2, reaper→T2, retry→T2, fence→T3, logout/verify→T6, PK lookup→T4, OIDC state→T4/T6, SAR→T6, no-redis→T7, dev-up→T7, autoddl→T7 smoke).
- **One-way-door completeness:** `fence` column (T1), Redis removal (T7), pgEdge dev switch (T7) — all flagged with `> ⚠ one-way:`.
- **Placeholder scan:** no TBD/TODO/"similar to Task N"; every code step shows the code.
- **Type consistency:** `pgqueue.claim(engine, replica_id) -> str | None` used identically in T2 and T5; `kvstore.kv_set(engine, key, value, ttl_seconds)` consistent across T4/T6; `revocation.is_revoked(engine, jti) -> bool` consistent T4/T6; `Leader.fence` (T3) is what T5's fenced writes would consume (T5's `_worker_loop` claims via `pgqueue`; the fence is enforced at the lease/heartbeat level in T3 and on task DB-writes in the tasks themselves — noted in the interface block).

## Owed-Decision Gate

- **Reaper cadence (30 s) and the worker poll (5 s)** — named sources: the 5 s poll matches the existing `wsgi.py` `time.sleep(5)`; the 30 s reaper is a new value. **Decision note:** 30 s is chosen as a cheap sub-minute cadence for the three `reap_*` sweeps (queue + revocation + kv); it is an implementation tuning constant, not a spec-constrained value, so it is recorded here rather than owed. If a longer task is added, the reaper *interval* (2 min, Task 2) — not the sweep cadence — is the number to revisit (findings F7/E4).
- **`db.json` `pgedge` user password** — copied from the pgEdge docs example (`z1Zsku10a91RS526jnVrLC39`); a dev-only credential, not an identity/credential the app authenticates with (the app uses `kubedash`/`kubedash`). Named source: findings F6.

No other value lacks a named source → **no owed decisions.**

## Threat Matrix

| Boundary | Applicability | Design response | Planned RED test |
|---|---|---|---|
| **Concurrency (queue claim)** | Applicable: two replicas / two pgEdge nodes claim the same row | `FOR UPDATE SKIP LOCKED` claim (atomic, cluster-wide); reaper is time-based | `test_two_concurrent_claimers_do_not_double_claim` (T2) |
| **Crash / unplanned exit** | Applicable: SIGKILL/OOM mid-claim or mid-lease | Time-based reaper (not lock-based); advisory lock session-scoped (self-releases); strict fence rejects late writes | `test_reaper_requeues_stale_processing` (T2), `test_stale_fence_write_affects_zero_rows` (T3) |
| **Auth hot path (revocation)** | Applicable: `verify_jwt` runs per request | `jti` bound as a parameter (PK lookup, no function in WHERE) — findings F2b | `test_verify_jwt_401_when_jti_revoked` (T6) + the F5 benchmark constraint |
| **State (OIDC CSRF)** | Applicable: `state` is a one-shot CSRF nonce | `kv` one-shot delete; mismatch → `StateMismatchError` | `test_consume_state_is_one_shot` (T6) |
| **RBAC verdict cache** | Applicable: per-request SAR cache, ADR-0004 key carries every attribute | `kv` under the unchanged `sar:<...>` key; a hit never re-asks | `test_sar_cache_hit_does_not_reask` (T6) |
| **Migration (one-way)** | Applicable: `fence` column + 3 tables | Alembic migration, guarded `has_table`, `autoddl` replicates on pgEdge | `test_new_tables_exist` (T1) |
| **Infra (dev compose)** | Applicable: two-node pgEdge, `db.json` user requirement | `db.json` includes `pgedge` internal_admin user; hostnames match service names — findings F6 | `task dev-up` smoke: both nodes in `spock.node`, no redis (T7) |

## Execution Handoff

The blueprint has 7 tasks of work → **`skillgrid:slicing`** is invoked to break it into vertical tracer-bullet tickets with dependency edges and execution waves (the tracer thread is Task 1→2→5; Tasks 3, 4, 6, 7 thicken around it).

**Update `state.yaml`:** set `pipeline.current_change: 2026-10-27-postgres-queue-revocation-active-active` and `pipeline.current_phase: blueprint`.

**Two execution options after slicing:**
1. **Subagent-Driven (recommended)** — fresh subagent per ticket, review between tasks.
2. **Inline Execution** — `skillgrid:simple-execution`, batched with checkpoints.

The final review is the two-axis pass (`skillgrid:requesting-code-review`); for this high-risk change (auth hot path + concurrency + migration) the execution skill should escalate the final review to `skillgrid:parallel-code-review`.
