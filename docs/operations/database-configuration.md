# Database Configuration for Multi-Replica KubeDash

## Overview

Database configuration is critical for multi-replica deployments. This guide covers database requirements, setup, and optimization.

## Database Requirements by Deployment Mode

### Single-Replica Mode ✅

**Supported Databases:**
- SQLite (file-based, simplest)
- PostgreSQL
- MySQL/MariaDB

**Characteristics:**
- No replication needed
- Simple setup (SQLite can be embedded)
- No distributed transactions
- Backup/restore straightforward

### Multi-Replica Mode (Cluster) ⚠️ POSTGRESQL REQUIRED

**Required Database:**
- **PostgreSQL only** (version 12+)
- SQLite explicitly NOT supported in cluster mode

**Why PostgreSQL Required:**
- Thread-safe connection pooling (SQLite has severe limitations)
- Proper transaction isolation for concurrent replicas
- WAL (Write-Ahead Logging) for durability
- Replication support for HA setup
- Query performance under concurrent load

**Why SQLite Cannot Work:**
```
SQLite Limitations in Multi-Replica:
├─ Single-threaded by default
├─ Limited concurrent write capacity (locks entire DB)
├─ Connection pooling problematic (WAL mode helps but insufficient)
├─ Network replication not supported (local file system only)
└─ No MVCC (Multi-Version Concurrency Control) like PostgreSQL
```

**Validation: KubeDash enforces this at startup:**

```python
# src/kubedash/lib/replica_mode.py
if replica_mode == 'cluster' and _is_sqlite_database(app):
    raise ValueError(
        "Cluster mode requires PostgreSQL database, but SQLite is configured. "
        "Please configure SQLALCHEMY_DATABASE_URI to point to a PostgreSQL instance."
    )
```

---

## PostgreSQL Configuration

### Connection String Format

```
postgresql://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]
```

**Examples:**

Local development:
```
postgresql://kubedash:password@localhost:5432/kubedash
```

Cloud (AWS RDS):
```
postgresql://kubedash:password@kubedash.abc123.us-east-1.rds.amazonaws.com:5432/kubedash
```

Cloud (Google Cloud SQL):
```
postgresql://kubedash:password@35.192.1.2:5432/kubedash
```

With SSL (production):
```
postgresql://kubedash:password@postgres.prod.svc:5432/kubedash?sslmode=require&sslcert=/path/to/cert
```

### Environment Variable Configuration

Set in pod or Helm values:

```bash
# Single-replica (can use SQLite or PostgreSQL)
export SQLALCHEMY_DATABASE_URI="sqlite:///kubedash.db"
# or
export SQLALCHEMY_DATABASE_URI="postgresql://example:pass@localhost/kubedash"

# Multi-replica (PostgreSQL only)
export SQLALCHEMY_DATABASE_URI="postgresql://example:pass@postgres.prod:5432/kubedash"
export REPLICA_MODE="cluster"
export REPLICA_COUNT="3"
```

### Kubernetes Configuration

In Helm values.yaml:

```yaml
# values.yaml
postgresql:
  enabled: false  # Using external PostgreSQL
  external:
    host: "postgres.db.svc.cluster.local"
    port: 5432
    database: "kubedash"
    username: "kubedash"
    # password stored in secret
    secretName: "kubedash-postgres"
    secretKey: "password"

# Or full connection string
externalDatabase:
  url: "postgresql://kubedash:password@postgres.db.svc:5432/kubedash"
```

In deployment manifest:

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
        env:
        - name: SQLALCHEMY_DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: kubedash-postgres
              key: connection-url
        - name: REPLICA_MODE
          value: "cluster"  # Multi-replica deployments
```

---

## Connection Pool Configuration

### Why Connection Pooling Matters

In multi-replica mode, multiple pods need efficient database connections:

```
Without pooling (bad):
├─ Pod 1: 10 connection threads → 10 connections
├─ Pod 2: 10 connection threads → 10 connections
├─ Pod 3: 10 connection threads → 10 connections
└─ Total: 30 concurrent connections (database overloaded)

With pooling (good):
├─ Pod 1: Pool of 5 reusable connections
├─ Pod 2: Pool of 5 reusable connections
├─ Pod 3: Pool of 5 reusable connections
└─ Total: ~15 connections (database healthy)
```

### SQLAlchemy Pool Configuration

In `lib/config.py`:

```python
# Connection pool settings
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_size': 10,              # Connections to keep in pool
    'max_overflow': 20,           # Extra connections allowed
    'pool_recycle': 3600,         # Recycle connections after 1 hour
    'pool_pre_ping': True,        # Test connections before using
    'echo': False,                # Log SQL (set True for debugging)
}

# For multi-replica, tune based on replica count
if REPLICA_MODE == 'cluster':
    # Reduce per-pod pool to avoid overload
    SQLALCHEMY_ENGINE_OPTIONS['pool_size'] = 5
    SQLALCHEMY_ENGINE_OPTIONS['max_overflow'] = 10
```

Environment variables for tuning:

```bash
# Per-pod connection pool
export SQLALCHEMY_POOL_SIZE=5
export SQLALCHEMY_MAX_OVERFLOW=10
export SQLALCHEMY_POOL_RECYCLE=3600
export SQLALCHEMY_POOL_PRE_PING=true
```

### Recommended Pool Sizes

```
Deployment Model          | Pool Size | Max Overflow | Rationale
--------------------------|-----------|--------------|----------------------------------
Single-Replica (SQLite)   | 5         | 10           | SQLite minimal overhead
Single-Replica (Postgres) | 10        | 20           | Full utilization, single pod
Multi-Replica (3 pods)    | 5         | 10           | Shared database, lower per-pod
Multi-Replica (5+ pods)   | 3         | 5            | Many pods, strict pooling
High Load                 | 10        | 30           | More concurrent queries needed
Low Resource Limits       | 3         | 5            | Limited memory per pod
```

### Health Check: Connection Pool

Monitor pool exhaustion:

```python
# In monitoring/metrics.py
from sqlalchemy import event

def get_pool_stats(db):
    pool = db.engine.pool
    return {
        'pool_size': pool.size(),
        'checked_in': pool.checkedout(),
        'checked_out': len(pool._all_conns) - pool.checkedout(),
        'overflow': pool.overflow(),
    }

# Alert if pool exhausted
def check_pool_health():
    stats = get_pool_stats(db)
    total = stats['pool_size'] + stats['max_overflow']
    used = stats['checked_out'] + stats['overflow']
    utilization = used / total
    
    if utilization > 0.9:
        logger.warning(f"Connection pool 90% utilized: {used}/{total}")
```

---

## Database Initialization & Migration

### First Run Setup

```bash
# Create database (as admin/superuser)
createdb kubedash

# Run migrations
cd src/kubedash
flask db upgrade

# Initialize schema
python -m flask shell
>>> from app import create_app; app = create_app()
>>> from lib.initializers.database import init_db
>>> init_db()
```

### Using Alembic for Migrations

To make changes to schema:

```bash
# Generate migration file
flask db migrate -m "Add user preferences table"

# Review generated file in migrations/versions/
# Edit if needed

# Apply migration
flask db upgrade

# Rollback if needed
flask db downgrade
```

### Production Deployment

Use init containers to auto-migrate:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubedash
spec:
  template:
    spec:
      initContainers:
      - name: migrate
        image: kubedash:latest
        command:
        - flask
        - db
        - upgrade
        env:
        - name: SQLALCHEMY_DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: kubedash-postgres
              key: connection-url
      containers:
      - name: kubedash
        image: kubedash:latest
        env:
        - name: SQLALCHEMY_DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: kubedash-postgres
              key: connection-url
```

---

## Performance Tuning

### PostgreSQL Server Configuration

For multi-replica KubeDash workload:

```sql
-- Connection settings
max_connections = 100
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 10MB
min_wal_size = 1GB
max_wal_size = 4GB

-- Replication settings
wal_level = replica
max_wal_senders = 3
wal_keep_segments = 64
hot_standby = on
```

### Connection Pool Tuning for Load

Monitor and adjust based on load testing:

```bash
# During load testing, monitor:
# 1. Connection pool utilization
# 2. Query execution time
# 3. Database CPU usage
# 4. Memory usage

# If pool exhausted:
export SQLALCHEMY_POOL_SIZE=10      # Increase pool
export SQLALCHEMY_MAX_OVERFLOW=30   # Increase overflow

# If queries slow:
# Option 1: Add database indexes
# Option 2: Optimize slow queries (use EXPLAIN)
# Option 3: Scale database resources

# If database CPU high:
# Option 1: Add query caching
# Option 2: Optimize N+1 queries
# Option 3: Scale database vertically
```

---

## Testing Database Configuration

### Connectivity Test

```bash
# Test connection from pod
kubectl exec -it kubedash-0 -- python3 << 'EOF'
import os
from sqlalchemy import create_engine, text

db_uri = os.environ['SQLALCHEMY_DATABASE_URI']
engine = create_engine(db_uri)

try:
    with engine.connect() as conn:
        result = conn.execute(text("SELECT 1"))
        print(f"✅ Connected to: {db_uri}")
        print(f"   Version: {result.scalar()}")
except Exception as e:
    print(f"❌ Connection failed: {e}")
finally:
    engine.dispose()
EOF
```

### Pool Utilization Test

```bash
# Run synthetic load
kubectl run load-gen --image=python:3.10 -- python3 << 'EOF'
import psycopg2
import concurrent.futures
import time

conn_str = "postgresql://user:pass@postgres:5432/kubedash"

def make_query(i):
    conn = psycopg2.connect(conn_str)
    cur = conn.cursor()
    cur.execute("SELECT 1")
    time.sleep(0.1)
    cur.close()
    conn.close()
    return i

# Concurrent queries
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(make_query, range(100)))

print(f"✅ Completed {len(results)} concurrent queries")
EOF
```

### Migration Test

```bash
# Test migration doesn't break schema
kubectl exec kubedash-0 -- python3 << 'EOF'
from app import create_app
from flask_sqlalchemy import SQLAlchemy

app = create_app()
with app.app_context():
    # Check schema integrity
    inspector = sqlalchemy.inspect(db.engine)
    tables = inspector.get_table_names()
    print(f"✅ Database has {len(tables)} tables")
    for table in tables:
        cols = inspector.get_columns(table)
        print(f"   - {table}: {len(cols)} columns")
EOF
```

---

## Troubleshooting

### Connection Refused

```bash
# 1. Check database pod is running
kubectl get pod -l app=postgres

# 2. Check service is accessible
kubectl get svc postgres

# 3. Test connectivity from pod
kubectl exec kubedash-0 -- nc -zv postgres 5432

# 4. Check credentials in secret
kubectl get secret kubedash-postgres -o jsonpath='{.data.connection-url}' | base64 -d
```

### Connection Pool Exhausted

```
Error: QueuePool limit exceeded
```

Solutions:
1. Increase pool size: `SQLALCHEMY_POOL_SIZE=10`
2. Reduce connection lifetime: `SQLALCHEMY_POOL_RECYCLE=600`
3. Identify connection leaks: Review code for missing `db.session.close()`
4. Scale database connections: Increase PostgreSQL `max_connections`

### Slow Queries

```bash
# Enable query logging
export SQLALCHEMY_ECHO=true

# Analyze slow query
EXPLAIN ANALYZE SELECT * FROM large_table WHERE id > 1000000;

# Add index if needed
CREATE INDEX idx_large_table_id ON large_table(id);
```

---

## Database Validation Checklist

- [ ] Database type is PostgreSQL (not SQLite) for cluster mode
- [ ] Connection string correct and accessible
- [ ] Database user has necessary permissions (CREATE, INSERT, UPDATE, DELETE)
- [ ] Connection pool size appropriate for replica count
- [ ] Migrations applied successfully
- [ ] Pool pre-ping enabled for health checks
- [ ] Connection recycling configured
- [ ] Database backups configured
- [ ] Replication (if HA) is running
- [ ] Monitoring alerts configured

## Quick Reference

| Task | Command |
|------|---------|
| Test connection | `psql postgresql://user:pass@host/db` |
| Check pool stats | `select count(*) from pg_stat_activity;` |
| List indexes | `\d+ table_name` |
| Analyze table | `ANALYZE table_name;` |
| Vacuum table | `VACUUM ANALYZE table_name;` |
| View slow queries | `SELECT * FROM pg_stat_statements;` |
| Reset counter | `SELECT pg_stat_statements_reset();` |
