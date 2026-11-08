#!/usr/bin/env bash
# Prototype 001 / Experiment B: strict fence rejects a stale leader's writes.
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

P -q -c "UPDATE leader_lease SET fence=0, replica_id='', heartbeat_at=now();"
P -q -c "TRUNCATE tasks RESTART IDENTITY;"

# acquire(): UPDATE ... fence=fence+1 ... RETURNING fence
acquire() { # $1 = replica id ; strip the "UPDATE 1" tag, keep the fence value
  P -tAc "UPDATE leader_lease SET replica_id='$1', token=gen_random_uuid(), acquired_at=now(), heartbeat_at=now(), fence=fence+1 WHERE id=1 RETURNING fence;" | grep -E '^[0-9]+$'
}
# fenced write: only affects the row if the stored fence still equals $1
fenced_heartbeat() { # $1 = fence value ; count data rows (strip the "UPDATE N" tag)
  P -tAc "UPDATE leader_lease SET heartbeat_at=now() WHERE id=1 AND fence=$1 RETURNING 1;" | grep -c '^1$'
}

echo "=== A acquires ==="
A_FENCE=$(acquire A)
echo "A's fence = $A_FENCE"
P -c "SELECT replica_id, fence FROM leader_lease;"

echo "A's fresh heartbeat rowcount (expect 1): $(fenced_heartbeat $A_FENCE)"

echo "=== B wins the lease (active-active LWW conflict) ==="
B_FENCE=$(acquire B)
echo "B's fence = $B_FENCE"
P -c "SELECT replica_id, fence FROM leader_lease;"

echo "A's STALE heartbeat rowcount (expect 0, fence mismatch): $(fenced_heartbeat $A_FENCE)"
echo "B's fresh heartbeat rowcount  (expect 1): $(fenced_heartbeat $B_FENCE)"

echo "=== final state ==="
P -c "SELECT replica_id AS owner, fence FROM leader_lease;"
echo "VERDICT: row owner is B (fence $B_FENCE); A (fence $A_FENCE) is fenced out of every write."
