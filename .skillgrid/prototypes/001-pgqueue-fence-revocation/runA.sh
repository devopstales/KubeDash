#!/usr/bin/env bash
# Prototype 001 / Experiment A: exactly-once claim under 10-way concurrency.
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

P -q -c "TRUNCATE tasks RESTART IDENTITY;"
P -q -c "INSERT INTO tasks (path, enqueued_at, available_at, status) SELECT 'app.tasks.health.run', now() - (g||' s')::interval, now() - (g||' s')::interval, 'pending' FROM generate_series(1,50) g;"
echo "enqueued pending: $(P -tAc 'SELECT count(*) FROM tasks WHERE status='\''pending'\'';')"

# 10 parallel claimers, each claiming exactly 1 row via SKIP LOCKED
for w in $(seq 1 10); do
  docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 -q -c \
    "BEGIN; WITH c AS (SELECT id FROM tasks WHERE status='pending' AND available_at<=now() ORDER BY enqueued_at LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE tasks SET status='processing', locked_at=now(), locked_by='worker-$w', attempts=attempts+1 WHERE id=(SELECT id FROM c); COMMIT;" &
done
wait

echo "=== status after 10 parallel claims ==="
P -c "SELECT status, count(*) FROM tasks GROUP BY status ORDER BY status;"
echo "rows claimed by >1 worker (expect 0): $(P -tAc "SELECT count(*) FROM (SELECT id FROM tasks WHERE status='processing' GROUP BY id HAVING count(*)>1) x;")"
echo "distinct workers that claimed (expect 10): $(P -tAc "SELECT count(DISTINCT locked_by) FROM tasks WHERE status='processing';")"
echo "total claimed (expect 10): $(P -tAc "SELECT count(*) FROM tasks WHERE status='processing';")"
