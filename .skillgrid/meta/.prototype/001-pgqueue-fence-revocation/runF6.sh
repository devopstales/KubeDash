#!/usr/bin/env bash
# Prototype 001 / F6: pgEdge two-node topology — replication, autoddl, cross-node claim.
set -u
N1() { docker exec kdpg-n1 psql -U admin -d kubedash -v ON_ERROR_STOP=1 "$@"; }
N2() { docker exec kdpg-n2 psql -U admin -d kubedash -v ON_ERROR_STOP=1 "$@"; }

echo "=== F6a: cross-node DML replication (write on n1, read on n2) ==="
N1 -q -c "DROP TABLE IF EXISTS kd_repl; CREATE TABLE kd_repl (id int primary key, v text);"
N1 -q -c "INSERT INTO kd_repl VALUES (1,'written-on-n1');"
# wait for replication to propagate
for i in $(seq 1 12); do
  V=$(N2 -tAc "SELECT v FROM kd_repl WHERE id=1;" 2>/dev/null)
  [ "$V" = "written-on-n1" ] && break; sleep 2
done
echo "n2 sees row 1 v = '$V'  (expect written-on-n1)"
echo "n1 sees count: $(N1 -tAc 'SELECT count(*) FROM kd_repl;') | n2 sees count: $(N2 -tAc 'SELECT count(*) FROM kd_repl;')"

echo ""
echo "=== F6b: autoddl (DDL on n1 propagates to n2 without running it there) ==="
N1 -q -c "ALTER TABLE kd_repl ADD COLUMN added_on_n1 text;"
for i in $(seq 1 12); do
  C=$(N2 -tAc "SELECT count(*) FROM information_schema.columns WHERE table_name='kd_repl' AND column_name='added_on_n1';" 2>/dev/null)
  [ "$C" = "1" ] && break; sleep 2
done
echo "n2 has column added_on_n1: $(N2 -tAc "SELECT count(*) FROM information_schema.columns WHERE table_name='kd_repl' AND column_name='added_on_n1';")  (expect 1 — autoddl replicated the DDL)"

echo ""
echo "=== F6c: cross-node FOR UPDATE SKIP LOCKED claim (two nodes claim concurrently) ==="
N1 -q -c "DROP TABLE IF EXISTS kd_q; CREATE TABLE kd_q (id serial primary key, status text default 'pending', locked_by text);"
for i in $(seq 1 12); do N2 -tAc "SELECT count(*) FROM kd_q;" 2>/dev/null | grep -q 0 && break; sleep 2; done
N1 -q -c "INSERT INTO kd_q (status) SELECT 'pending' FROM generate_series(1,20);"
for i in $(seq 1 12); do N2 -tAc "SELECT count(*) FROM kd_q;" 2>/dev/null | grep -q 20 && break; sleep 2; done
echo "seeded 20 rows (n2 count: $(N2 -tAc 'SELECT count(*) FROM kd_q;'))"
# 6 claimers on n1 + 6 on n2, each claiming 1
for w in 1 2 3 4 5 6; do
  N1 -q -c "BEGIN; WITH c AS (SELECT id FROM kd_q WHERE status='pending' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE kd_q SET status='processing', locked_by='n1-$w' WHERE id=(SELECT id FROM c); COMMIT;" &
  N2 -q -c "BEGIN; WITH c AS (SELECT id FROM kd_q WHERE status='pending' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED) UPDATE kd_q SET status='processing', locked_by='n2-$w' WHERE id=(SELECT id FROM c); COMMIT;" &
done
wait
# let the processing rows replicate, then assert no double-claim
for i in $(seq 1 15); do
  DUP=$(N1 -tAc "SELECT count(*) FROM (SELECT id FROM kd_q WHERE status='processing' GROUP BY id HAVING count(*)>1) x;" 2>/dev/null)
  CLAIMED=$(N1 -tAc "SELECT count(*) FROM kd_q WHERE status='processing';" 2>/dev/null)
  [ "$CLAIMED" = "12" ] && break; sleep 2
done
echo "total claimed (expect 12): $CLAIMED"
echo "rows double-claimed (expect 0): $DUP"
echo "distinct claimers (expect 12): $(N1 -tAc "SELECT count(DISTINCT locked_by) FROM kd_q WHERE status='processing';")"
echo "claimers by node: $(N1 -tAc "SELECT string_agg(DISTINCT split_part(locked_by,'-',1), ',' ) FROM kd_q WHERE status='processing';")"
echo ""
echo "=== F6d: spock.node membership (both nodes see both) ==="
N1 -c "SELECT node_name, region FROM spock.node ORDER BY node_name;"
