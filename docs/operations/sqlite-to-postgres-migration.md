# SQLite to PostgreSQL Migration Guide

## Overview

This guide covers migrating KubeDash from SQLite (single-replica) to PostgreSQL (multi-replica).

## When to Migrate

**Migrate when:**
- Scaling from 1 to 2+ replicas
- High concurrent load (SQLite limited)
- Durability/HA requirements
- Disaster recovery needs

**Can stay with SQLite:**
- Single-replica deployments
- Development/testing
- Low traffic

## Migration Checklist

- [ ] Backup current SQLite database
- [ ] Create PostgreSQL instance
- [ ] Migrate schema
- [ ] Migrate data
- [ ] Test integrity
- [ ] Update configuration
- [ ] Test failover
- [ ] Monitor performance
- [ ] Commit to multi-replica mode

## Step 1: Backup SQLite Database

```bash
# Local development backup
cp kubedash.db kubedash-backup-$(date +%Y%m%d-%H%M%S).db

# Export as SQL dump (portable backup)
sqlite3 kubedash.db ".dump" > kubedash-backup.sql

# Verify backup
sqlite3 kubedash-backup.sql ".tables"
```

## Step 2: Create PostgreSQL Instance

### Option A: Managed PostgreSQL (Recommended)

**AWS RDS:**
```bash
aws rds create-db-instance \
  --db-instance-identifier kubedash-prod \
  --db-instance-class db.t3.small \
  --engine postgres \
  --engine-version 14.7 \
  --master-username postgres \
  --allocated-storage 100 \
  --multi-az  # HA replication
```

**Google Cloud SQL:**
```bash
gcloud sql instances create kubedash-prod \
  --database-version=POSTGRES_14 \
  --tier=db-custom-2-4096 \
  --region=us-central1 \
  --availability-type=REGIONAL  # HA
```

**Azure Database for PostgreSQL:**
```bash
az postgres server create \
  --resource-group kubedash \
  --name kubedash-prod \
  --location eastus \
  --sku-name GP_Gen5_2 \
  --storage-size 102400  # 100GB
```

### Option B: Self-Hosted Kubernetes

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  serviceName: postgres
  replicas: 1
  template:
    spec:
      containers:
      - name: postgres
        image: postgres:14-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: kubedash
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        volumeMounts:
        - name: data
          mountPath: /var/lib/postgresql/data
        livenessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - pg_isready -U postgres
          initialDelaySeconds: 30
        readinessProbe:
          exec:
            command:
            - /bin/sh
            - -c
            - pg_isready -U postgres
  volumeClaimTemplates:
  - metadata:
      name: data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      resources:
        requests:
          storage: 100Gi
```

## Step 3: Create Database and User

```bash
# Connect to PostgreSQL
psql -h postgres-host -U postgres

# Create database
CREATE DATABASE kubedash;

# Create user
CREATE USER kubedash WITH ENCRYPTED PASSWORD 'secure_password';

# Grant permissions
GRANT ALL PRIVILEGES ON DATABASE kubedash TO kubedash;

# Connect to new database
\c kubedash

# Grant default schemas
GRANT ALL ON SCHEMA public TO kubedash;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO kubedash;
```

## Step 4: Run Alembic Migrations

Initialize schema in PostgreSQL:

```bash
# Activate environment
source venv/bin/activate
cd src/kubedash

# Set PostgreSQL connection
export SQLALCHEMY_DATABASE_URI="postgresql://kubedash:password@postgres:5432/kubedash"

# Run migrations to build schema
flask db upgrade

# Verify schema created
psql -h postgres -U kubedash -d kubedash -c "\dt"
```

## Step 5: Migrate Data from SQLite

Two approaches depending on data size:

### Approach A: Direct SQL Export/Import (Small data < 1GB)

```bash
# 1. Export SQLite dump
sqlite3 kubedash.db ".dump" > kubedash-dump.sql

# 2. Adapt SQLite-specific syntax
# Remove SQLite-specific lines:
sed -i '/^PRAGMA/d' kubedash-dump.sql
sed -i '/^BEGIN TRANSACTION/d' kubedash-dump.sql
sed -i '/COMMIT/d' kubedash-dump.sql
sed -i '/AUTOINCREMENT/d' kubedash-dump.sql

# 3. Import to PostgreSQL
psql -h postgres -U kubedash -d kubedash < kubedash-dump.sql

# 4. Verify data migrated
psql -h postgres -U kubedash -d kubedash -c "SELECT COUNT(*) FROM users;"
```

### Approach B: Python Script (Recommended for large data)

```python
#!/usr/bin/env python3
"""Migrate SQLite to PostgreSQL"""

import sqlite3
import psycopg2
from tqdm import tqdm
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Connections
sqlite_conn = sqlite3.connect('kubedash.db')
sqlite_conn.row_factory = sqlite3.Row
sqlite_cursor = sqlite_conn.cursor()

pg_conn = psycopg2.connect(
    host='postgres',
    user='kubedash',
    password='password',
    database='kubedash'
)
pg_cursor = pg_conn.cursor()

# Tables to migrate (in dependency order)
TABLES = ['users', 'rbac_roles', 'audit_logs', 'settings']

def migrate_table(table_name):
    """Migrate table from SQLite to PostgreSQL"""
    logger.info(f"Migrating {table_name}...")
    
    # Get data from SQLite
    sqlite_cursor.execute(f"SELECT * FROM {table_name}")
    rows = sqlite_cursor.fetchall()
    
    if not rows:
        logger.info(f"  {table_name}: No data")
        return
    
    # Get column names
    columns = [description[0] for description in sqlite_cursor.description]
    col_str = ', '.join(columns)
    placeholders = ', '.join(['%s'] * len(columns))
    
    # Insert to PostgreSQL
    insert_query = f"INSERT INTO {table_name} ({col_str}) VALUES ({placeholders})"
    
    for row in tqdm(rows, desc=table_name):
        try:
            pg_cursor.execute(insert_query, tuple(row))
        except psycopg2.Error as e:
            logger.error(f"  Error inserting row: {e}")
            pg_conn.rollback()
            raise
    
    pg_conn.commit()
    logger.info(f"  {table_name}: {len(rows)} rows migrated")

# Disable foreign key checks during migration
pg_cursor.execute("SET session_replication_role = 'replica'")

try:
    # Migrate each table
    for table in TABLES:
        migrate_table(table)
    
    # Re-enable foreign key checks
    pg_cursor.execute("SET session_replication_role = 'origin'")
    
    logger.info("✅ Migration complete!")
    
except Exception as e:
    logger.error(f"❌ Migration failed: {e}")
    pg_conn.rollback()
    raise

finally:
    sqlite_cursor.close()
    sqlite_conn.close()
    pg_cursor.close()
    pg_conn.close()
```

Run the migration:
```bash
python3 migrate_sqlite_to_postgres.py
```

## Step 6: Verify Data Integrity

```bash
# 1. Count rows
sqlite3 kubedash.db "SELECT COUNT(*) FROM users;"
psql -h postgres -U kubedash -d kubedash -c "SELECT COUNT(*) FROM users;"
# Should match

# 2. Check for data corruption
psql -h postgres -U kubedash -d kubedash << 'EOF'
-- Verify user table
SELECT COUNT(*) as user_count FROM users;
SELECT COUNT(*) as admin_count FROM users WHERE role='admin';

-- Verify audit logs
SELECT COUNT(*) as log_count FROM audit_logs;
SELECT DATE_TRUNC('day', created_at) as day, COUNT(*) FROM audit_logs GROUP BY DATE_TRUNC('day', created_at);
EOF

# 3. Run application assertions
python3 << 'EOF'
from app import create_app
app = create_app()
with app.app_context():
    from models import User, AuditLog
    users = User.query.count()
    logs = AuditLog.query.count()
    print(f"✅ Users: {users}")
    print(f"✅ Audit Logs: {logs}")
EOF
```

## Step 7: Update Configuration

### Development Environment

```bash
# Update .env
SQLALCHEMY_DATABASE_URI="postgresql://kubedash:password@localhost:5432/kubedash"
REPLICA_MODE="single"  # Still single-replica in dev

# Test connection
python3 << 'EOF'
from app import create_app
app = create_app()
print("✅ Connected to PostgreSQL")
EOF
```

### Kubernetes Deployment

Update Helm values or deployment manifest:

```yaml
# values.yaml
externalDatabase:
  enabled: true
  type: postgresql
  host: "postgres.prod:5432"
  database: kubedash
  username: kubedash
  # password in secret
  secretName: kubedash-postgres
  secretKey: password

# Enable multi-replica mode
replicaMode: cluster
replicas: 3
```

Apply changes:
```bash
kubectl set env deployment/kubedash \
  SQLALCHEMY_DATABASE_URI="postgresql://kubedash:password@postgres.prod:5432/kubedash" \
  REPLICA_MODE="cluster" \
  REPLICA_COUNT="3"

kubectl rollout restart deployment/kubedash
```

## Step 8: Test on PostgreSQL

Before switching all traffic:

```bash
# 1. Run with PostgreSQL connection string
export SQLALCHEMY_DATABASE_URI="postgresql://kubedash:password@postgres:5432/kubedash"

# 2. Start application
cd src/kubedash && python3 app.py

# 3. Test key functions
curl http://localhost:8000/api/health/ready
curl http://localhost:8000/api/cluster/status

# 4. Monitor logs for errors
kubectl logs -f deployment/kubedash

# 5. Run integration tests
pytest tests/integration/ -v

# 6. Test failover behavior
kubectl delete pod kubedash-0
# Verify pod restarts and reconnects to PostgreSQL

# 7. Test data consistency
# Create new user in pod 1
# Verify user visible in pod 2 (via PostgreSQL shared DB)
```

## Step 9: Cutover

Minimal-downtime cutover:

```bash
# 1. Verify PostgreSQL is ready
psql -h postgres -U kubedash -d kubedash -c "SELECT 1;"

# 2. Scale down old SQLite-based deployment
kubectl scale deployment kubedash-sqlite --replicas=0

# 3. Scale up PostgreSQL-based multi-replica
kubectl scale deployment kubedash --replicas=3

# 4. Wait for all pods ready
kubectl rollout status deployment/kubedash -w

# 5. Verify cluster status
kubectl port-forward svc/kubedash 8000 &
curl http://localhost:8000/api/cluster/status

# 6. Monitor for errors
kubectl logs -l app=kubedash --tail=100 -f
```

## Step 10: Post-Migration

### Verify Everything Works

```bash
# 1. All pods running
kubectl get pods -l app=kubedash

# 2. Leader elected
kubectl logs kubedash-0 | grep "leadership"

# 3. Sessions shared
# Create session on pod 1, verify on pod 2

# 4. Backups working
kubectl exec kubedash-0 -- bash backup.sh

# 5. Monitoring active
# Check Grafana dashboard
```

### Cleanup

```bash
# 1. Delete local SQLite backups (keep vault copy)
rm kubedash.db kubedash-backup*.db

# 2. Remove old SQLite deployment
kubectl delete deployment kubedash-sqlite

# 3. Archive migration logs
tar czf migration-$(date +%Y%m%d).tar.gz logs/

# 4. Update documentation
# - Mark SQLite migration complete
# - Document PostgreSQL connection details
# - Add runbooks for PostgreSQL operations
```

## Troubleshooting

### "Permission Denied" on PostgreSQL User

```bash
# Verify permissions
psql -h postgres -U postgres -d kubedash -c "\du"

# Grant missing permissions
GRANT ALL PRIVILEGES ON DATABASE kubedash TO kubedash;
GRANT ALL ON SCHEMA public TO kubedash;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO kubedash;
```

### Data Mismatch After Migration

```bash
# 1. Check for failed inserts (migration logs)
grep ERROR migration.log

# 2. Rerun migration for failed tables
python3 migrate_sqlite_to_postgres.py --table=users --verbose

# 3. Compare row counts
sqlite3 kubedash.db "SELECT COUNT(*) FROM users;"
psql -h postgres -U kubedash -d kubedash -c "SELECT COUNT(*) FROM users;"
```

### Connection Pooling Errors

```
QueuePool limit exceeded
```

Increase pool:
```bash
export SQLALCHEMY_POOL_SIZE=10
export SQLALCHEMY_MAX_OVERFLOW=20
```

### Slow Performance After Migration

```bash
# Analyze tables for query optimization
psql -h postgres -U kubedash -d kubedash << 'EOF'
ANALYZE;
ANALYZE audit_logs;
EOF

# Check for missing indexes
SELECT indexname FROM pg_indexes WHERE tablename='users';

# Add indexes if needed
CREATE INDEX idx_users_email ON users(email);
```

## Rollback (If Needed)

If issues found after migration:

```bash
# 1. Keep backup database: kubedash-backup.sql
# 2. Revert to SQLite deployment
kubectl scale deployment kubedash --replicas=0
kubectl scale deployment kubedash-sqlite --replicas=1

# 3. Restore SQLite from backup
sqlite3 kubedash.db < kubedash-backup.sql

# 4. Restart application
kubectl scale deployment kubedash-sqlite --replicas=1

# 5. Post-mortem: Identify and fix issue
# 6. Plan for retry

# Note: Data created after migration will be lost in rollback
# Plan maintenance window and communicate downtime
```

## Performance Comparison

### Before (SQLite) vs After (PostgreSQL)

| Metric | SQLite | PostgreSQL | Improvement |
|--------|--------|------------|------------|
| Concurrent connections | 1-5 | 50+ | 10x |
| Query concurrency limit | Very low | High | 100x |
| Replication | No | Yes | N/A |
| Failover | Manual | Automatic (HA) | N/A |
| Scalability | Single node | Multi-node | N/A |

## Success Criteria

- [ ] All data migrated (row counts match)
- [ ] Application connects without errors
- [ ] Multi-replica cluster forms (3+ pods with leader)
- [ ] Session sharing works across pods
- [ ] Failover tested successfully
- [ ] Performance meets or exceeds SQLite
- [ ] Monitoring/alerting active
- [ ] Backup/recovery procedures verified
