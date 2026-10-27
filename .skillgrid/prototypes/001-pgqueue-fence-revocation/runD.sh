#!/usr/bin/env bash
# Prototype 001 / Experiment D: verify-hook hot-path latency (the ADR-0030 risk).
# Question: is the per-request `SELECT 1 FROM revoked_jtis WHERE jti=:jti AND
# expires_at>now()` (a PK lookup) fast enough to replace Redis SISMEMBER?
set -u
cd "$(dirname "$0")"
P() { docker exec kdproto-pg psql -U proto -d kubedash -v ON_ERROR_STOP=1 "$@"; }

# steady-state size: ~a day of logouts (bounded by the reaper). 50k rows.
P -q -c "TRUNCATE revoked_jtis;"
P -q -c "INSERT INTO revoked_jtis (jti, expires_at)
         SELECT gen_random_uuid(), now() + interval '15 minutes'
         FROM generate_series(1, 50000);"
echo "revoked_jtis size: $(P -tAc 'SELECT count(*) FROM revoked_jtis;')"

# EXPLAIN the hot-path query (one live jti, one absent jti)
LIVE=$(P -tAc "SELECT jti FROM revoked_jtis LIMIT 1;")
echo ""
echo "=== EXPLAIN (live jti) ==="
P -c "EXPLAIN (ANALYZE, BUFFERS) SELECT 1 FROM revoked_jtis WHERE jti='$LIVE' AND expires_at > now();"
echo ""
echo "=== EXPLAIN (absent jti) ==="
P -c "EXPLAIN (ANALYZE, BUFFERS) SELECT 1 FROM revoked_jtis WHERE jti=gen_random_uuid() AND expires_at > now();"

# 2000 sequential lookups (mixed hit/miss) -> mean + p50/p99
echo ""
echo "=== 2000 sequential lookups (1000 hit + 1000 miss) ==="
docker exec kdproto-pg bash -lc '
  PGPASSWORD= psql -U proto -d kubedash -tA -q <<SQL > /tmp/lat.txt
DO $$
DECLARE
  n int := 2000; i int; t timestamptz; live uuid;
  ms double precision; sum double precision := 0;
  arr double precision[];
BEGIN
  SELECT jti INTO live FROM revoked_jtis LIMIT 1;
  FOR i IN 1..n LOOP
    t := clock_timestamp();
    IF i % 2 = 0 THEN
      PERFORM 1 FROM revoked_jtis WHERE jti = live AND expires_at > now();
    ELSE
      PERFORM 1 FROM revoked_jtis WHERE jti = gen_random_uuid() AND expires_at > now();
    END IF;
    ms := EXTRACT(epoch FROM (clock_timestamp() - t)) * 1000.0;
    sum := sum + ms;
    arr := arr || ms;
  END LOOP;
  RAISE NOTICE "n=% mean=%.4f ms", n, sum/n;
  RAISE NOTICE "p50=%.4f ms", arr[CEIL(n*0.50)];
  RAISE NOTICE "p99=%.4f ms", arr[CEIL(n*0.99)];
  RAISE NOTICE "max=%.4f ms", (SELECT max(x) FROM unnest(arr) x);
END $$;
SQL
' 2>&1 | grep -E "NOTICE|n=|p50|p99|max"
echo "VERDICT: see the p50/p99 above; compare against a Redis SISMEMBER (~0.1-0.5 ms) and the API's existing per-request DB budget."
