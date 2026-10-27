DO $$
DECLARE
  n int := 5000; i int; t timestamptz; live uuid; miss uuid; ms double precision;
  sum double precision := 0; arr double precision[] := '{}';
BEGIN
  SELECT jti INTO live FROM revoked_jtis LIMIT 1;
  miss := gen_random_uuid();           -- one absent uuid, reused (bound-param shape)
  FOR i IN 1..n LOOP
    t := clock_timestamp();
    IF i % 2 = 0 THEN PERFORM 1 FROM revoked_jtis WHERE jti = live;
    ELSE              PERFORM 1 FROM revoked_jtis WHERE jti = miss; END IF;
    ms := EXTRACT(epoch FROM (clock_timestamp() - t)) * 1000.0;
    sum := sum + ms; arr := arr || ms;
  END LOOP;
  RAISE NOTICE 'n=% mean=%.4f ms', n, sum/n;
  RAISE NOTICE 'p50=%.4f ms', arr[FLOOR(n*0.50)+1];
  RAISE NOTICE 'p90=%.4f ms', arr[FLOOR(n*0.90)+1];
  RAISE NOTICE 'p99=%.4f ms', arr[FLOOR(n*0.99)+1];
  RAISE NOTICE 'max=%.4f ms', (SELECT max(x) FROM unnest(arr) x);
END $$;
