# Database Connection Pool Tuning for Multi-Replica KubeDash

## Connection Pool Basics

### Why Connection Pooling Matters

A connection pool reduces database overhead by reusing connections:

```
Without pooling (connection per request):
├─ Request 1: Open connection → execute → close (overhead: high)
├─ Request 2: Open connection → execute → close (overhead: high)
└─ Request 3: Open connection → execute → close (overhead: high)

With pooling (connection reuse):
├─ Pool maintains 5 warm connections
├─ Request 1: Use pooled connection 1
├─ Request 2: Use pooled connection 2
└─ Request 3: Return pool connection 1 (warm, ready)
```

**Performance Impact:**
- Without pooling: PostgreSQL connection overhead = ~100-300ms per connection
- With pooling: Connection retrieval << 1ms

### Multi-Replica Challenge

In cluster mode, each pod creates its own pool:

```
3 KubeDash pods, pool_size=10, max_overflow=10:
├─ Pod 1: 10 + 10 overflow = 20 connections max
├─ Pod 2: 10 + 10 overflow = 20 connections max
├─ Pod 3: 10 + 10 overflow = 20 connections max
└─ Total: ~60 concurrent connections to PostgreSQL
```

This can overwhelm the database. Solution: **Tune pools based on replica count**.

---

## Configuration Location

### 1. SQLAlchemy Configuration

File: `src/kubedash/lib/config.py`

```python
import os

class Config:
    """Base configuration"""
    
    # Determine replica count
    REPLICA_COUNT = int(os.environ.get('REPLICA_COUNT', '1'))
    REPLICA_MODE = os.environ.get('REPLICA_MODE', 'single')
    
    # Calculate pool size based on replica mode
    if REPLICA_MODE == 'cluster':
        # Multi-replica: reduce per-pod pool
        if REPLICA_COUNT >= 5:
            POOL_SIZE = 3
            MAX_OVERFLOW = 5
        elif REPLICA_COUNT >= 3:
            POOL_SIZE = 5
            MAX_OVERFLOW = 10
        else:
            POOL_SIZE = 7
            MAX_OVERFLOW = 14
    else:
        # Single-replica: can use larger pool
        if 'sqlite://' in os.environ.get('SQLALCHEMY_DATABASE_URI', ''):
            POOL_SIZE = 5
            MAX_OVERFLOW = 10
        else:
            POOL_SIZE = 10
            MAX_OVERFLOW = 20
    
    # Connection pool configuration
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': POOL_SIZE,
        'max_overflow': MAX_OVERFLOW,
        'pool_recycle': 3600,           # Recycle after 1 hour
        'pool_pre_ping': True,          # Test connection before use
        'echo': False,                  # SQL logging (set True to debug)
        'connect_args': {
            'connect_timeout': 10,
            'options': '-c statement_timeout=30s',  # Statement timeout
        }
    }
```

### 2. Environment Variables

Override at runtime:

```bash
# Per-pod pool
export SQLALCHEMY_POOL_SIZE=5
export SQLALCHEMY_MAX_OVERFLOW=10
export SQLALCHEMY_POOL_RECYCLE=3600

# Or via Kubernetes ConfigMap/Secret
kubectl set env deployment/kubedash \
  SQLALCHEMY_POOL_SIZE=5 \
  SQLALCHEMY_MAX_OVERFLOW=10
```

### 3. Helm Chart Configuration

File: `deploy/kubedash/values.yaml`

```yaml
database:
  # Connection pool configuration
  poolSize: 5
  maxOverflow: 10
  poolRecycle: 3600
  
  # Auto-calculate based on replicas
  autoTunePooling: true  # If true, ignores poolSize/maxOverflow
  
  # Connection timeout
  connectTimeout: 10
  statementTimeout: 30s

# Pod configuration
replicaCount: 3

# Auto-apply pool settings
configTemplate:
  SQLALCHEMY_POOL_SIZE: "{{ .Values.database.poolSize }}"
  SQLALCHEMY_MAX_OVERFLOW: "{{ .Values.database.maxOverflow }}"
```

Generate ConfigMap in Helm template:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubedash-db-config
data:
  SQLALCHEMY_POOL_SIZE: |
    {{- if .Values.database.autoTunePooling }}
      {{- if ge (int .Values.replicaCount) 5 }}
        3
      {{- else if ge (int .Values.replicaCount) 3 }}
        5
      {{- else }}
        7
      {{- end }}
    {{- else }}
      {{ .Values.database.poolSize }}
    {{- end }}
  SQLALCHEMY_MAX_OVERFLOW: |
    {{- if .Values.database.autoTunePooling }}
      {{- if ge (int .Values.replicaCount) 5 }}
        5
      {{- else if ge (int .Values.replicaCount) 3 }}
        10
      {{- else }}
        14
      {{- end }}
    {{- else }}
      {{ .Values.database.maxOverflow }}
    {{- end }}
```

---

## Recommended Pool Sizes

### By Deployment Type

| Deployment | Database | Pool Size | Max Overflow | Total | Scenario |
|-----------|----------|-----------|--------------|-------|----------|
| Single-replica | SQLite | 5 | 10 | 15 | Development/small |
| Single-replica | PostgreSQL | 10 | 20 | 30 | Production single |
| 2-replica cluster | PostgreSQL | 7 | 14 | 21 | Per-pod total = 42 |
| 3-replica cluster | PostgreSQL | 5 | 10 | 15 | Per-pod total = 45 |
| 5-replica cluster | PostgreSQL | 3 | 5 | 8 | Per-pod total = 40 |
| High load (3 pods) | PostgreSQL | 10 | 20 | 30 | Minimal resource limit |
| Low resource (3 pods) | PostgreSQL | 3 | 5 | 8 | Memory-constrained |

### Calculation Formula

```
Recommended pool_size = (database_max_connections - buffer) / replica_count

Example: PostgreSQL default max_connections = 100
├─ 3-replica cluster: (100 - 20) / 3 ≈ 26 per pod
│  But with overflow, keep smaller to prevent exhaustion
│  Recommended: pool_size=5, max_overflow=10 = 15 per pod
└─ 5-replica cluster: (100 - 20) / 5 = 16 per pod
   Recommended: pool_size=3, max_overflow=5 = 8 per pod
```

---

## Monitoring Pool Utilization

### 1. Application Metrics Endpoint

Track pool usage via metrics:

```python
# src/kubedash/lib/metrics.py

from prometheus_client import Gauge, Counter

# Pool metrics
pool_size = Gauge('kubedash_db_pool_size', 'Current pool size')
pool_checked_out = Gauge('kubedash_db_pool_checked_out', 'Connections checked out')
pool_exhausted = Counter('kubedash_db_pool_exhausted_total', 'Pool exhaustion events')

def update_pool_metrics(db):
    """Update connection pool metrics"""
    pool = db.engine.pool
    
    try:
        pool_size.set(pool.size())
        checked_out = len([c for c in pool._all_conns if hasattr(c, '_in_use') and c._in_use])
        pool_checked_out.set(checked_out)
    except Exception as e:
        logger.error(f"Failed to update pool metrics: {e}")
```

Register in Flask app:

```python
@app.before_request
def update_metrics():
    update_pool_metrics(db)
```

### 2. Prometheus Monitoring

Query pool utilization:

```promql
# Pool utilization percentage
kubedash_db_pool_checked_out / kubedash_db_pool_size * 100

# Alert if approaching exhaustion
ALERT DBPoolNearExhaustion
  IF kubedash_db_pool_checked_out / kubedash_db_pool_size > 0.85
  FOR 2m
  ANNOTATIONS {
    summary: "Database connection pool {{ $value }}% utilized"
  }
```

### 3. Direct Database Query

Check connection count from PostgreSQL:

```sql
-- View current connections
SELECT count(*) as current_connections
FROM pg_stat_activity;

-- View connections by state
SELECT state, count(*)
FROM pg_stat_activity
GROUP BY state;

-- View connections by database
SELECT datname, count(*)
FROM pg_stat_activity
WHERE datname = 'kubedash'
GROUP BY datname;

-- View connections by user
SELECT usename, count(*)
FROM pg_stat_activity
GROUP BY usename;
```

Run from Kubernetes:

```bash
kubectl exec -it postgres-0 -- \
  psql -U postgres -c "SELECT datname, count(*) FROM pg_stat_activity GROUP BY datname;"
```

---

## Pool Recycling and Connection Health

### Problem: Stale Connections

Over time, connections can become stale:
- Idle connections get closed by firewall
- Network interruptions
- Database restarts

### Solution: Connection Recycling

```python
# In config.py
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_recycle': 3600,  # Recycle connections after 1 hour
    'pool_pre_ping': True, # Test connection before using
}
```

**pool_recycle:**
- Closes and recreates connections older than specified seconds
- Default: -1 (no recycling, can cause stale connections)
- Recommended: 3600 (1 hour) for production

**pool_pre_ping:**
- Tests connection with SELECT 1 before each use
- Catches dead connections early
- Small performance overhead (negligible)

### Health Check Query

```python
# src/kubedash/lib/database.py

def health_check_connection():
    """Health check database connection"""
    try:
        result = db.session.execute(db.text("SELECT 1"))
        return {'status': 'healthy', 'latency_ms': 1}
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {'status': 'unhealthy', 'error': str(e)}
```

API endpoint:

```python
@app.route('/api/health/database')
def database_health():
    result = health_check_connection()
    if result['status'] == 'healthy':
        return {'status': 'ok'}, 200
    else:
        return {'status': 'error', 'error': result['error']}, 503
```

---

## Handling Pool Exhaustion

### What Happens

```
Error: QueuePool limit exceeded with overflow
  Exceeded pool_size=5 and max_overflow=10, both exhausted
```

### Prevention (Best)

1. Monitor pool utilization (alert at 80%)
2. Increase pool size before exhaustion
3. Optimize slow queries (reduce connection hold time)

### Emergency Response

If pool becomes exhausted:

```bash
# 1. Check active connections
psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname='kubedash';"

# 2. Kill idle connections
psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity 
         WHERE datname='kubedash' AND state='idle' AND state_change < now() - interval '5 minutes';"

# 3. Increase pool size temporarily
kubectl set env deployment/kubedash SQLALCHEMY_POOL_SIZE=10 SQLALCHEMY_MAX_OVERFLOW=20

# 4. Investigate root cause
# - Are there slow queries holding connections?
# - Are connections not being returned to pool?
# - Is HPA scaling up too many pods?
```

### Finding Connection Leaks

```python
# Connections should be returned to pool after request
# If not, pool gets exhausted

# Common mistake:
@app.route('/api/data')
def get_data():
    session = db.session  # Opens connection
    result = session.query(User).all()
    return jsonify(result)
    # Session not closed! Connection leaked

# Correct:
@app.route('/api/data')
def get_data():
    result = db.session.query(User).all()
    db.session.close()  # Explicit close
    return jsonify(result)

# Or use context manager:
@app.route('/api/data')
def get_data():
    with db.session() as session:
        result = session.query(User).all()
    # Auto-closed
    return jsonify(result)
```

Detect leaks with:

```python
@app.after_request
def check_session_closed(response):
    """Alert if session not properly closed"""
    if db.session.is_active:
        logger.warning("⚠️  SQLAlchemy session still active after request")
    return response
```

---

## Load Testing Pool Configuration

### k6 Load Test

Test pool behavior under load:

```javascript
// load-test-pool.js
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  vus: 10,           // 10 concurrent users
  duration: '1m',    // 1 minute test
  ramp: true,
};

export default function() {
  // Simulate API call that uses database
  let response = http.get('http://kubedash:8000/api/v1/cluster/mode');
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 200ms': (r) => r.timings.duration < 200,
  });
}
```

Run test:

```bash
# Before: Monitor pool metrics
kubectl exec kubedash-0 -- python3 -c "
from app import create_app
app = create_app()
with app.app_context():
    print(f'Pool: {db.engine.pool}')
"

# Run k6 load test
k6 run load-test-pool.js

# Monitor during test
kubectl logs -f deployment/kubedash | grep "db_pool"
curl http://kubedash:8000/metrics | grep db_pool
```

### Interpret Results

Look for:

```
✅ Good:
- Pool size stays constant
- Checked out connections stay < 80% of max
- No "pool exhausted" errors
- Response times stable

❌ Bad:
- Pool exhaustion errors
- Checked out connections = pool + overflow
- Response times increasing
- Timeouts
```

---

## Tuning Process

### Step 1: Establish Baseline

Get current pool stats:

```bash
# During normal load
curl http://kubedash:8000/metrics | grep db_pool
# kubedash_db_pool_size 5
# kubedash_db_pool_checked_out 3
# Utilization: 3/5 = 60% (good)
```

### Step 2: Load Test

Run k6 with expected load:

```bash
k6 run --vus 20 load-test.js
```

### Step 3: Identify Bottleneck

If pool exhaustion occurs:

```bash
# Check if it's the pool or the database itself
# 1. Increase pool size
kubectl set env deployment/kubedash SQLALCHEMY_POOL_SIZE=10

# 2. Re-run test
k6 run --vus 20 load-test.js

# If still failing: database bottleneck (scale database)
# If passes: pool was too small
```

### Step 4: Adjust Configuration

Update values based on findings:

```yaml
# values.yaml
database:
  poolSize: 10      # Increased from 5
  maxOverflow: 20   # Increased from 10
```

Deploy:

```bash
helm upgrade kubedash ./deploy/kubedash -f values.yaml
```

### Step 5: Monitor in Production

Watch for pool exhaustion:

```bash
# Alert on Prometheus
ALERT DBPoolApproachingLimit
  IF kubedash_db_pool_checked_out / (kubedash_db_pool_size + kubedash_db_pool_max_overflow) > 0.9
  FOR 2m
```

---

## Best Practices Summary

✅ **DO:**
- Tune pool based on replica count
- Enable pool_pre_ping
- Set pool_recycle
- Monitor pool utilization
- Alert on high utilization (> 80%)
- Load test before production
- Test with realistic concurrent load

❌ **DON'T:**
- Use default SQLAlchemy pool settings in production
- Ignore pool exhaustion errors
- Leave pool_pre_ping disabled
- Set pool_recycle to -1 (no recycling)
- Deploy to production without monitoring

## Quick Reference

```bash
# Check pool configuration
kubectl exec kubedash-0 -- python3 -c \
  "from app import create_app; app = create_app(); print(app.config['SQLALCHEMY_ENGINE_OPTIONS'])"

# Monitor pool in real-time
kubectl exec kubedash-0 -- python3 << 'EOF'
import time
from app import create_app
app = create_app()
with app.app_context():
    while True:
        pool = db.engine.pool
        print(f"Pool: {pool.size()} / {pool.size() + pool._overflow}")
        time.sleep(1)
EOF

# Get pool statistics
kubectl exec postgres-0 -- psql -U postgres -c \
  "SELECT datname, usename, state, COUNT(*) FROM pg_stat_activity GROUP BY datname, usename, state;"
```
