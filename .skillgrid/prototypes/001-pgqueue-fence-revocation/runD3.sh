#!/usr/bin/env bash
# Prototype 001 / Experiment D3: drop the expires_at index -> PK-only hot path.
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

P -q -c "DROP INDEX IF EXISTS revoked_jtis_expires_idx;"
echo "indexes now:"; P -c "\di revoked_jtis_pkey"
LIVE=$(P -tAc "SELECT jti FROM revoked_jtis LIMIT 1;")

echo ""
echo "=== absent jti (PK-only) ==="
P -c "EXPLAIN (ANALYZE) SELECT 1 FROM revoked_jtis WHERE jti=gen_random_uuid();" | grep -E "Index Scan|Index Only|Bitmap|Execution Time|Heap Blocks|Rows Removed"
echo "=== live jti (PK-only) ==="
P -c "EXPLAIN (ANALYZE) SELECT 1 FROM revoked_jtis WHERE jti='$LIVE' AND expires_at>now();" | grep -E "Index Scan|Index Only|Bitmap|Execution Time"

echo ""
echo "=== benchmark via file (clean \$\$) ==="
cat > /tmp/bench.sql <<'SQL'
DO $$
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
END $$;
SQL
docker cp /tmp/bench.sql kdproto-pg:/tmp/bench.sql
docker exec kdproto-pg psql -U proto -d kubedash -q -f /tmp/bench.sql 2>&1 | grep -E "NOTICE"
echo "VERDICT: with the expires_at index dropped, is the absent-jti path a fast PK miss?"
