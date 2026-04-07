# Database Health Checks for Multi-Replica KubeDash

## Overview

Database health checks ensure KubeDash can safely operate. This guide covers implementing, monitoring, and responding to database health issues.

## Health Check Types

### 1. Connection Availability

**Purpose:** Verify database is reachable and accepting connections

**Implementation:**

```python
# src/kubedash/lib/health.py

from datetime import datetime
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)

def check_database_connection():
    """Check if database is reachable"""
    try:
        with db.engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            result.scalar()
        
        return {
            'status': 'healthy',
            'type': 'database_connection',
            'timestamp': datetime.utcnow().isoformat(),
            'latency_ms': 1
        }
    except Exception as e:
        logger.error(f"Database connection check failed: {e}")
        return {
            'status': 'unhealthy',
            'type': 'database_connection',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
```

**API Endpoint:**

```python
@app.route('/api/health/database')
def health_database():
    """Database health check"""
    result = check_database_connection()
    status_code = 200 if result['status'] == 'healthy' else 503
    return jsonify(result), status_code
```

**Kubernetes Liveness Probe:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubedash
spec:
  template:
    spec:
      containers:
      - name: kubedash
        image: kubedash:latest
        livenessProbe:
          httpGet:
            path: /api/health/database
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
          timeoutSeconds: 5
```

### 2. Connection Pool Health

**Purpose:** Verify connection pool is not exhausted

**Implementation:**

```python
def check_connection_pool():
    """Check connection pool health"""
    try:
        pool = db.engine.pool
        pool_size = pool.size()
        checked_out = len([c for c in pool._all_conns 
                          if hasattr(c, '_in_use') and c._in_use])
        
        utilization = checked_out / pool_size if pool_size > 0 else 0
        
        return {
            'status': 'healthy' if utilization < 0.9 else 'degraded',
            'type': 'connection_pool',
            'pool_size': pool_size,
            'checked_out': checked_out,
            'max_overflow': pool._max_overflow,
            'utilization_percent': round(utilization * 100, 2),
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Connection pool check failed: {e}")
        return {
            'status': 'error',
            'type': 'connection_pool',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
```

### 3. Replication Lag (PostgreSQL HA)

**Purpose:** Monitor replication lag in high-availability setup

**Implementation:**

```python
def check_replication_lag():
    """Check PostgreSQL replication lag"""
    try:
        # Query replication status
        result = db.session.execute(text("""
            SELECT 
                usename,
                client_addr,
                state,
                sync_state,
                write_lsn,
                flush_lsn,
                replay_lsn,
                (pg_wal_lsn_diff(write_lsn, replay_lsn) / 1024 / 1024)::int as lag_mb
            FROM pg_stat_replication
        """))
        
        replicas = []
        max_lag_mb = 0
        
        for row in result:
            lag = row.lag_mb or 0
            max_lag_mb = max(max_lag_mb, lag)
            replicas.append({
                'user': row.usename,
                'address': str(row.client_addr),
                'state': row.state,
                'sync_state': row.sync_state,
                'lag_mb': lag
            })
        
        status = 'healthy'
        if max_lag_mb > 100:
            status = 'degraded'
        elif max_lag_mb > 500:
            status = 'unhealthy'
        
        return {
            'status': status,
            'type': 'replication_lag',
            'replicas': replicas,
            'max_lag_mb': max_lag_mb,
            'replica_count': len(replicas),
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.warning(f"Replication lag check failed (likely on replica): {e}")
        return {
            'status': 'unknown',
            'type': 'replication_lag',
            'error': 'Not a primary or replication not configured',
            'timestamp': datetime.utcnow().isoformat()
        }
```

### 4. Query Performance

**Purpose:** Detect slow queries affecting database

**Implementation:**

```python
def check_slow_queries():
    """Check for slow queries"""
    try:
        # Query pg_stat_statements for slow queries
        result = db.session.execute(text("""
            SELECT 
                query,
                calls,
                mean_exec_time,
                max_exec_time,
                total_exec_time
            FROM pg_stat_statements
            WHERE mean_exec_time > 100  -- Queries averaging > 100ms
            ORDER BY mean_exec_time DESC
            LIMIT 5
        """))
        
        slow_queries = []
        for row in result:
            slow_queries.append({
                'query': row.query[:100],  # First 100 chars
                'calls': row.calls,
                'mean_time_ms': round(row.mean_exec_time, 2),
                'max_time_ms': round(row.max_exec_time, 2)
            })
        
        status = 'healthy'
        if slow_queries:
            logger.warning(f"Found {len(slow_queries)} slow queries")
            status = 'degraded'
        
        return {
            'status': status,
            'type': 'slow_queries',
            'slow_query_count': len(slow_queries),
            'queries': slow_queries[:5],  # Return top 5
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        # pg_stat_statements not installed
        logger.debug(f"Slow query check not available: {e}")
        return {
            'status': 'unknown',
            'type': 'slow_queries',
            'error': 'pg_stat_statements not installed',
            'timestamp': datetime.utcnow().isoformat()
        }
```

### 5. Storage Space

**Purpose:** Ensure database has sufficient disk space

**Implementation:**

```python
def check_database_storage():
    """Check database storage usage"""
    try:
        result = db.session.execute(text("""
            SELECT 
                datname,
                pg_size_pretty(pg_database_size(datname)) as size_human,
                pg_database_size(datname) as size_bytes
            FROM pg_database
            WHERE datname = current_database()
        """))
        
        row = result.first()
        
        return {
            'status': 'healthy',
            'type': 'database_storage',
            'database': row.datname,
            'size_human': row.size_human,
            'size_bytes': row.size_bytes,
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Storage check failed: {e}")
        return {
            'status': 'unknown',
            'type': 'database_storage',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
```

### 6. Transactions and Locks

**Purpose:** Detect transaction/lock issues that could block operations

**Implementation:**

```python
def check_active_transactions():
    """Check for long-running transactions and locks"""
    try:
        result = db.session.execute(text("""
            SELECT 
                pid,
                usename,
                query,
                query_start,
                state,
                EXTRACT(EPOCH FROM (now() - query_start))::int as duration_sec
            FROM pg_stat_activity
            WHERE duration_sec > 60  -- Transactions > 1 minute
            AND state != 'idle'
            ORDER BY query_start
        """))
        
        long_transactions = []
        for row in result:
            long_transactions.append({
                'pid': row.pid,
                'user': row.usename,
                'state': row.state,
                'duration_sec': row.duration_sec,
                'query': row.query[:80]  # First 80 chars
            })
        
        status = 'healthy'
        if len(long_transactions) > 3:
            status = 'degraded'
        
        return {
            'status': status,
            'type': 'active_transactions',
            'long_transactions': long_transactions,
            'count': len(long_transactions),
            'timestamp': datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Transaction check failed: {e}")
        return {
            'status': 'unknown',
            'type': 'active_transactions',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }
```

---

## Composite Health Check Endpoint

Combine all checks into one endpoint:

```python
@app.route('/api/health/comprehensive')
def health_comprehensive():
    """Comprehensive health check combining all database checks"""
    
    checks = {
        'connection': check_database_connection(),
        'pool': check_connection_pool(),
        'replication_lag': check_replication_lag(),
        'slow_queries': check_slow_queries(),
        'storage': check_database_storage(),
        'transactions': check_active_transactions(),
    }
    
    # Determine overall status
    statuses = [c.get('status', 'unknown') for c in checks.values()]
    
    if 'unhealthy' in statuses:
        overall_status = 'unhealthy'
        http_status = 503
    elif 'degraded' in statuses:
        overall_status = 'degraded'
        http_status = 200  # Still ok, but warn
    else:
        overall_status = 'healthy'
        http_status = 200
    
    return jsonify({
        'status': overall_status,
        'timestamp': datetime.utcnow().isoformat(),
        'checks': checks
    }), http_status
```

Example response:

```json
{
  "status": "degraded",
  "timestamp": "2026-04-05T10:15:30Z",
  "checks": {
    "connection": {
      "status": "healthy",
      "type": "database_connection",
      "latency_ms": 2
    },
    "pool": {
      "status": "healthy",
      "pool_size": 5,
      "checked_out": 3,
      "utilization_percent": 60.0
    },
    "replication_lag": {
      "status": "healthy",
      "replicas": 2,
      "max_lag_mb": 5
    },
    "slow_queries": {
      "status": "degraded",
      "slow_query_count": 2,
      "queries": [
        {
          "query": "SELECT * FROM large_table WHERE...",
          "mean_time_ms": 250.5
        }
      ]
    },
    "storage": {
      "status": "healthy",
      "size_human": "2.5 GB"
    },
    "transactions": {
      "status": "healthy",
      "count": 0
    }
  }
}
```

---

## Kubernetes Configuration

### Readiness Probe

Pod is ready to serve requests:

```yaml
readinessProbe:
  httpGet:
    path: /api/health/database
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 5
  failureThreshold: 2
  timeoutSeconds: 3
```

### Startup Probe

Pod has successfully started:

```yaml
startupProbe:
  httpGet:
    path: /api/health/database
    port: 8000
  failureThreshold: 30
  periodSeconds: 10
  # Pod has up to 300 seconds to start
```

### Alert Rules

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: kubedash-database-alerts
spec:
  groups:
  - name: database
    rules:
    # Connection pool exhaustion
    - alert: DBPoolExhausted
      expr: |
        kubedash_db_pool_checked_out / 
        (kubedash_db_pool_size + kubedash_db_pool_max_overflow) > 0.95
      for: 2m
      labels:
        severity: warning
      annotations:
        summary: "Database connection pool {{ $value | humanizePercentage }} utilized"
    
    # Replication lag
    - alert: DBReplicationLag
      expr: kubedash_db_replication_lag_mb > 100
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "PostgreSQL replication lag {{ $value }} MB"
    
    # High transaction duration
    - alert: DBLongRunningTransaction
      expr: kubedash_db_transaction_duration_sec > 300
      for: 5m
      labels:
        severity: warning
      annotations:
        summary: "Transaction running for {{ $value }}s"
```

---

## Manual Health Check Commands

### Check Database Connection

```bash
# From pod
kubectl exec kubedash-0 -- curl localhost:8000/api/health/database

# From local (using port-forward)
kubectl port-forward svc/kubedash 8000 &
curl http://localhost:8000/api/health/database
```

### Check Connection Pool

```bash
# From pod
kubectl exec kubedash-0 -- python3 << 'EOF'
from app import create_app
app = create_app()
with app.app_context():
    pool = db.engine.pool
    print(f"Pool size: {pool.size()}")
    print(f"Max overflow: {pool._max_overflow}")
    print(f"Current connections: {len([c for c in pool._all_conns if c._in_use])}")
EOF
```

### Check Replication Status (PostgreSQL)

```bash
# From PostgreSQL pod
kubectl exec postgres-0 -- psql -U postgres -c \
  "SELECT usename, client_addr, state, sync_state FROM pg_stat_replication;"

# Expected output:
#  usename |  client_addr   | state  | sync_state
# ---------+----------------+--------+----------
#  repl    | 10.0.0.2       | stream | async
#  repl    | 10.0.0.3       | stream | async
```

### Check Slow Queries

```bash
kubectl exec postgres-0 -- psql -U postgres -c \
  "SELECT query, calls, mean_exec_time FROM pg_stat_statements 
   WHERE mean_exec_time > 100 ORDER BY mean_exec_time DESC LIMIT 5;"
```

### Check Storage Usage

```bash
kubectl exec postgres-0 -- psql -U postgres -c \
  "SELECT datname, pg_size_pretty(pg_database_size(datname)) 
   FROM pg_database WHERE datname = 'kubedash';"
```

---

## Responding to Health Check Failures

### Connection Unavailable

```
Error: connection refused
```

**Investigation:**
```bash
# 1. Check if PostgreSQL pod is running
kubectl get pods -l app=postgres

# 2. Check if service is accessible
kubectl get svc postgres
kubectl describe svc postgres

# 3. Test connectivity
kubectl exec kubedash-0 -- nc -zv postgres 5432

# 4. Check logs
kubectl logs postgres-0
```

**Fix:**
- Restart PostgreSQL pod: `kubectl delete pod postgres-0`
- Check PostgreSQL readiness probe
- Verify network policy allows connection

### Connection Pool Exhausted

```
Error: QueuePool limit exceeded
```

**Investigation:**
```bash
# Check pool utilization
curl http://kubedash:8000/api/health/comprehensive | jq '.checks.pool'

# Check active connections
kubectl exec postgres-0 -- psql -U postgres -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname='kubedash';"
```

**Fix:**
- Increase pool size: `kubectl set env deployment/kubedash SQLALCHEMY_POOL_SIZE=10`
- Kill idle connections in database
- Look for connection leaks in code
- Scale database resources

### High Replication Lag

```
Replication lag: 500+ MB
```

**Investigation:**
```bash
# Check replica status
kubectl logs postgres-replica-0 | tail -20

# Check network between primary and replica
kubectl exec postgres-0 -- ping postgres-replica-0

# Check write volume
psql -c "SELECT (pg_wal_lsn_diff('0/0', pg_current_wal_lsn()) / 1024 / 1024)::int as lsn_mb;"
```

**Fix:**
- Check network connectivity between primary and replicas
- Increase `wal_max_size` in PostgreSQL config
- Optimize slow queries
- Scale replica resources

### Slow Queries Detected

```
Mean query time: 500+ms
```

**Investigation:**
```bash
# Get slow query details
kubectl exec postgres-0 -- psql -U postgres << 'EOF'
SELECT query, calls, mean_exec_time, max_exec_time 
FROM pg_stat_statements 
WHERE mean_exec_time > 100 
ORDER BY mean_exec_time DESC 
LIMIT 5;
EOF

# Analyze execution plan
EXPLAIN ANALYZE SELECT ...;
```

**Fix:**
- Add database indexes
- Optimize query
- Update statistics: `ANALYZE;`
- Scale database resources

---

## Health Check in CI/CD

### Pre-Deployment Check

```bash
#!/bin/bash
# tests/check-db-health.sh

# Wait for pod to be ready
kubectl rollout status deployment/kubedash -w

# Check comprehensive health
HEALTH=$(kubectl exec kubedash-0 -- curl -s localhost:8000/api/health/comprehensive)
STATUS=$(echo $HEALTH | jq -r '.status')

if [ "$STATUS" != "healthy" ] && [ "$STATUS" != "degraded" ]; then
    echo "❌ Database health check failed"
    echo $HEALTH | jq '.'
    exit 1
fi

echo "✅ Database health check passed"
echo $HEALTH | jq '.'
exit 0
```

Run in pipeline:

```yaml
# .github/workflows/deploy.yml
- name: Check database health
  run: bash tests/check-db-health.sh
  after:
    - Deploy to staging
  before:
    - Promote to production
```

---

## Best Practices

✅ **DO:**
- Check database health before serving requests
- Monitor connection pool utilization
- Alert on replication lag
- Track slow queries
- Set realistic thresholds
- Document thresholds in runbook
- Test health checks in staging

❌ **DON'T:**
- Ignore degraded status
- Let connection pool exhaust
- Deploy without health checks
- Set thresholds too high
- Run health checks too frequently (impacts performance)

## Success Criteria

- [ ] Connection available within 5ms
- [ ] Connection pool utilization < 80%
- [ ] Replication lag < 100MB (healthy) or < 500MB (degraded)
- [ ] No slow queries (mean < 100ms)
- [ ] Sufficient disk space (> 20% free)
- [ ] No long-running transactions (> 5 min)
