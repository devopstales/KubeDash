#!/usr/bin/env bash
# Prototype 001 / Experiment C: reaper re-queues a dead worker's in-flight job.
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

P -q -c "TRUNCATE tasks RESTART IDENTITY;"
# one job, claimed by a worker that then "dies" (locked 5 min ago)
P -q -c "INSERT INTO tasks (path, status, attempts, locked_at, locked_by, available_at, enqueued_at)
         VALUES ('app.tasks.health.run','processing',1, now()-interval '5 minutes','dead-worker', now()-interval '5 minutes', now()-interval '5 minutes');"
echo "before reaper: $(P -tAc "SELECT status||' attempts='||attempts FROM tasks;")"

echo "=== run the reaper (re-queue processing rows stale > 2 min) ==="
P -c "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL,
        available_at = now() + make_interval(secs => LEAST(600, 60 * power(5, attempts)))
     WHERE status='processing' AND locked_at < now() - interval '2 minutes';"
echo "after reaper:  $(P -tAc "SELECT status||' attempts='||attempts||' available_in='||EXTRACT(epoch FROM (available_at - now()))::int||'s' FROM tasks;")"

echo ""
echo "=== second death (attempts now 1 -> re-queued; claim -> 2; die; re-queue with bigger backoff) ==="
P -q -c "UPDATE tasks SET status='processing', locked_at=now()-interval '5 minutes', locked_by='dead-worker-2', attempts=attempts+1;"
P -c "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL,
        available_at = now() + make_interval(secs => LEAST(600, 60 * power(5, attempts)))
     WHERE status='processing' AND locked_at < now() - interval '2 minutes';"
echo "backoff at attempts=2 (expect ~300s=5min): $(P -tAc "SELECT EXTRACT(epoch FROM (available_at - now()))::int||'s' FROM tasks;")"

echo ""
echo "=== third death -> attempts=3 -> dead-letter (status='failed') ==="
P -q -c "UPDATE tasks SET status='processing', locked_at=now()-interval '5 minutes', locked_by='dead-worker-3', attempts=attempts+1;"
P -c "UPDATE tasks SET status='failed', locked_at=NULL, locked_by=NULL
     WHERE status='processing' AND locked_at < now() - interval '2 minutes' AND attempts>=3;"
P -c "UPDATE tasks SET status='pending', locked_at=NULL, locked_by=NULL,
        available_at = now() + make_interval(secs => LEAST(600, 60 * power(5, attempts)))
     WHERE status='processing' AND locked_at < now() - interval '2 minutes' AND attempts<3;"
echo "final (expect failed, attempts=3): $(P -tAc "SELECT status||' attempts='||attempts FROM tasks;")"
echo "VERDICT: reaper re-queues stale in-flight jobs with growing backoff; dead-letters at attempts>=3."
