#!/usr/bin/env bash
# Prototype 001 / Experiment D (revised): verify-hook hot-path latency.
# D1 found the planner is UNRELIABLE: `WHERE jti=:jti AND expires_at>now()`
# sometimes takes a 263 ms bitmap scan (via the expires_at index) instead of the
# PK scan. This tests the two fixes + a real p50/p99.
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

P -q -c "TRUNCATE revoked_jtis;"
P -q -c "INSERT INTO revoked_jtis (jti, expires_at) SELECT gen_random_uuid(), now() + interval '15 minutes' FROM generate_series(1, 50000);"
echo "size: $(P -tAc 'SELECT count(*) FROM revoked_jtis;')"
LIVE=$(P -tAc "SELECT jti FROM revoked_jtis LIMIT 1;")

echo ""
echo "=== D2: query WITHOUT expires_at predicate (pure PK probe) ==="
echo "-- absent jti (the path that was 263 ms):"
P -c "EXPLAIN (ANALYZE) SELECT 1 FROM revoked_jtis WHERE jti=gen_random_uuid();" | grep -E "Index Scan|Bitmap|Execution Time|Heap Blocks|Rows Removed"
echo "-- live jti:"
P -c "EXPLAIN (ANALYZE) SELECT 1 FROM revoked_jtis WHERE jti='$LIVE';" | grep -E "Index Scan|Bitmap|Execution Time"

echo ""
echo "=== D3: explicit Index Only Scan hint via SET enable_bitmapscan=off (absent jti) ==="
P -c "SET enable_bitmapscan=off; EXPLAIN (ANALYZE) SELECT 1 FROM revoked_jtis WHERE jti=gen_random_uuid() AND expires_at>now();" | grep -E "Index Only Scan|Index Scan|Bitmap|Execution Time|Heap Blocks|Rows Removed"

echo ""
echo "=== real p50/p99: 3000 sequential lookups (1500 hit + 1500 miss), D2 shape ==="
docker exec kdproto-pg psql -U proto -d kubedash -tA -q <<SQL
DO \$\$
DECLARE
  n int := 3000; i int; t timestamptz; live uuid; ms double precision;
  sum double precision := 0; arr double precision[] := '{}';
BEGIN
  SELECT jti INTO live FROM revoked_jtis LIMIT 1;
  FOR i IN 1..n LOOP
    t := clock_timestamp();
    IF i % 2 = 0 THEN PERFORM 1 FROM revoked_jtis WHERE jti = live;
    ELSE              PERFORM 1 FROM revoked_jtis WHERE jti = gen_random_uuid(); END IF;
    ms := EXTRACT(epoch FROM (clock_timestamp() - t)) * 1000.0;
    sum := sum + ms; arr := arr || ms;
  END LOOP;
  RAISE NOTICE 'n=% mean=%.4f ms', n, sum/n;
  RAISE NOTICE 'p50=%.4f ms', arr[FLOOR(n*0.50)+1];
  RAISE NOTICE 'p99=%.4f ms', arr[FLOOR(n*0.99)+1];
  RAISE NOTICE 'max=%.4f ms', (SELECT max(x) FROM unnest(arr) x);
END \$\$;
SQL
echo "VERDICT: compare D2 (no predicate) and D3 (bitmapscan off) against D1's 263 ms miss."
