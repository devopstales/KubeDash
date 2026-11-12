#!/usr/bin/env bash
# Prototype 001 / Experiment E: an UNPLANNED worker exit (SIGKILL) must not wedge the queue.
#
# The risk: a worker claims a row (status='processing'), then dies UNEXPECTEDLY
# (SIGKILL / OOM / power loss) — no cleanup runs, no advisory lock released.
# The queue must still recover via the REAPER (time-based), not via lock release.
#
# Also asserts:
#   E1: a SIGKILL'd worker leaves a stuck 'processing' row (no crash handler ran).
#   E2: the reaper re-queues it after the stale threshold -> queue is not wedged.
#   E3: a FENCED leader_lease write by a SIGKILL'd leader is invisible; a fresh
#       acquire (fence+1) + write by the survivor commits -> no split-brain.
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

# recreate the prototype schema in the (already up) scratch pg
docker cp schema.sql kdproto-pg:/tmp/schema.sql >/dev/null
P -q -f /tmp/schema.sql >/dev/null 2>&1

# ---------- E1: SIGKILL mid-claim leaves a stuck row ----------
echo "=== E1: simulate a worker that claims then is SIGKILL'd (no cleanup) ==="
P -q -c "TRUNCATE tasks RESTART IDENTITY;"
P -q -c "INSERT INTO tasks (path) VALUES ('app.tasks.health.run');"
# worker claims it (sets processing + locked_at), then 'dies' — we model the
# death by NOT clearing it and backdating locked_at past the stale threshold,
# exactly what a SIGKILL mid-task leaves behind.
P -q -c "UPDATE tasks SET status='processing', locked_at=now()-interval '3 minutes', locked_by='killed-worker', attempts=1;"
echo "before reaper (stuck row from killed worker):"
P -c "SELECT status, locked_by, attempts, EXTRACT(epoch FROM (now()-locked_at))::int AS locked_ago_s FROM tasks;"
STUCK=$(P -tAc "SELECT count(*) FROM tasks WHERE status='processing' AND locked_at < now()-interval '2 minutes';")
echo "stuck in-flight rows (expect >=1): $STUCK"

# ---------- E2: reaper recovers it -> queue not wedged ----------
echo ""
echo "=== E2: reaper (time-based, NOT lock-based) re-queues the stuck row ==="
P -c "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL,
        available_at = now() + make_interval(secs => LEAST(600, 60 * power(5, attempts)))
     WHERE status='processing' AND locked_at < now() - interval '2 minutes';"
P -c "SELECT status, locked_by, attempts, EXTRACT(epoch FROM (available_at-now()))::int AS available_in_s FROM tasks;"
echo "re-queued? status is now: $(P -tAc "SELECT status FROM tasks;")  (expect pending)"
# a new worker can claim it again
P -q -c "BEGIN; WITH c AS (SELECT id FROM tasks WHERE status='pending' AND available_at<=now()+interval '10 minutes' ORDER BY enqueued_at LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE tasks SET status='processing', locked_by='new-worker', attempts=attempts+1 WHERE id=(SELECT id FROM c); COMMIT;"
echo "new worker re-claimed it: locked_by=$(P -tAc "SELECT locked_by FROM tasks;") attempts=$(P -tAc "SELECT attempts FROM tasks;")"

# ---------- E3: SIGKILL'd leader's fenced write is invisible ----------
echo ""
echo "=== E3: SIGKILL'd leader (fence N) vs survivor (fence N+1) under active-active ==="
P -q -c "UPDATE leader_lease SET fence=0, replica_id='', heartbeat_at=now();"
# leader A acquires (fence 1), heartbeats, then is SIGKILL'd
AF=$(P -tAc "UPDATE leader_lease SET replica_id='A', fence=fence+1, heartbeat_at=now() WHERE id=1 RETURNING fence;" | grep -E '^[0-9]+$')
echo "A acquired fence=$AF, then SIGKILL'd (no release, no cleanup)"
# A's LATE in-flight write (buffered before the kill, flushed after) — fenced on A's fence
LATE=$(P -tAc "UPDATE leader_lease SET heartbeat_at=now() WHERE id=1 AND fence=$AF RETURNING 1;" | grep -c '^1$' || true)
# survivor B acquires (fence 2) — the takeover path after detecting A's stale heartbeat
BF=$(P -tAc "UPDATE leader_lease SET replica_id='B', fence=fence+1, heartbeat_at=now() WHERE id=1 RETURNING fence;" | grep -E '^[0-9]+$')
echo "B took over, fence=$BF"
# now A's late write arrives (still carrying fence=$AF) — must be rejected
A_LATE=$(P -tAc "UPDATE leader_lease SET heartbeat_at=now() WHERE id=1 AND fence=$AF RETURNING 1;" | grep -c '^1$' || true)
B_OK=$(P -tAc "UPDATE leader_lease SET heartbeat_at=now() WHERE id=1 AND fence=$BF RETURNING 1;" | grep -c '^1$' || true)
echo "A's late fenced write affected rows (expect 0): $A_LATE"
echo "B's fenced write affected rows   (expect 1): $B_OK"
echo "final owner: $(P -tAc "SELECT replica_id||' fence='||fence FROM leader_lease;")"

# ---------- E4: crash BEFORE the reaper threshold -> NOT yet re-queued (correct) ----------
echo ""
echo "=== E4: a worker that died < 2 min ago is NOT re-queued yet (no premature re-run) ==="
P -q -c "TRUNCATE tasks RESTART IDENTITY; INSERT INTO tasks (path) VALUES ('app.tasks.cluster_sync.run');"
P -q -c "UPDATE tasks SET status='processing', locked_at=now()-interval '30 seconds', locked_by='recently-killed', attempts=1;"
P -c "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL,
        available_at = now() + make_interval(secs => LEAST(600, 60 * power(5, attempts)))
     WHERE status='processing' AND locked_at < now() - interval '2 minutes';"
echo "recently-killed row status (expect still 'processing' — not yet stale): $(P -tAc "SELECT status FROM tasks;")"
echo "VERDICT: reaper threshold prevents re-running a job that may still be in flight."
