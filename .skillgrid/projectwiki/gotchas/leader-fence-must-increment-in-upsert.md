---
type: Reference
title: "A counter fenced by SELECT-then-INSERT hands two peers the same fence"
description: "The leader fence is a per-acquire counter, so it must be incremented inside the upsert (`fence = leader_lease.fence + 1` + `RETURNING fence`). Reading it and binding the next value in Python lets two peers acquiring in the same window both hold the same fence — the exact tie ADR-0031 exists to break. Found and fixed in da790985 (2026-11-10, review of the Postgres-queue change)."
tags: [gotcha, postgres, leader-election, fencing, concurrency, pgqueue, adr-0031]
status: stable
generated: { by: skillgrid/reflect, at: 2026-11-10 }
verification:
  engine: ripgrep
  anchors:
    - path: backend/app/core/leader.py
      all_of: ["fence = leader_lease.fence + 1", "RETURNING fence", "WHERE id = 1 AND replica_id = :rid AND fence = :f"]
---

# A counter fenced by SELECT-then-INSERT hands two peers the same fence

**The gotcha.** `leader_lease.fence` is not a version of the row — it is a
**counter incremented on every acquire**, and it is the only cross-node
tiebreaker a leader has. `pg_try_advisory_lock` cannot serve that role: the
lock is *session-local*, so two pgEdge nodes each happily take their own
session's lock. So the fence must be produced by the same statement that
claims the lease. Write it as a read-then-bind (a `SELECT fence`, then an
`INSERT ... VALUES (fence + 1)` computed in Python) and two peers that acquire
inside that window both bind the same value: both hold an equal fence, both
believe they lead, and the ADR-0031 fencing is silently void.

**The fix** (`da790985`, review finding "Important #1" on the
2026-10-27-postgres-queue-revocation-active-active change):

```sql
INSERT INTO leader_lease (id, replica_id, token, acquired_at, heartbeat_at, fence)
VALUES (1, :rid, :tok, now(), now(), 1)
ON CONFLICT (id) DO UPDATE SET replica_id = :rid, token = :tok,
  acquired_at = now(), heartbeat_at = now(),
  fence = leader_lease.fence + 1
RETURNING fence
```

Two details trip people on this statement, both now spelled out in
`backend/app/core/leader.py`:

- On the `DO UPDATE` side the column must be **qualified** —
  `leader_lease.fence`. Bare `fence` is ambiguous, and `excluded.fence` is
  the row we *tried* to insert (always `1`), not the live value.
- The `INSERT` side **cannot** reference the target column at all, so its
  initial value has to be the literal `1`. Do not "fix" that asymmetry.

Every subsequent leader write then carries `WHERE fence = :f` (the heartbeat
does: `WHERE id = 1 AND replica_id = :rid AND fence = :f`), so a stale leader
updates zero rows and demotes itself. Never drop that predicate to "keep the
beat alive".

**Why it is subtle.** Fence-as-counter looks like a version column, and
version columns are usually computed from a read. Sequential unit tests pass
either way — the failure needs two connections interleaving between the read
and the write. This is the class of bug a green suite cannot see; it was
caught at review, not by QA.

**Rule for the agent.** Any monotonic counter that grants authority
(leader fence, generation, epoch, lease number) must be produced by the write
that grants it — a single atomic `UPDATE ... SET c = c + 1 RETURNING c` /
`ON CONFLICT DO UPDATE`. If you catch yourself computing the next value in
application code, the token is not fencing anything.

**Related.** `workflows/leader-task-execution.md` (where the fence is used on
the enqueue path) and `invariants/leader-only-rq-worker.md` (leader election
contract; its title predates ADR-0029 removing RQ). Open debt: `tasks` has no
retention for `done` rows (recorded as W035 — needs an ADR-0029 amendment, so
it is deliberately **not** documented here as settled behavior).
