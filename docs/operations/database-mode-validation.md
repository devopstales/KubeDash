# Database Mode Validation for Multi-Replica KubeDash

## Overview

KubeDash strictly validates database configuration to prevent misconfiguration in production. This document covers the validation rules and how they're enforced.

## Validation Rules

### Rule 1: Multi-Replica Requires PostgreSQL

**Rule:** Cluster mode (`REPLICA_MODE=cluster`) is **only** allowed with PostgreSQL.

**Enforcement Point:** Application startup

```python
# src/kubedash/lib/replica_mode.py

def validate_replica_config():
    """Validate replica configuration is valid for deployment mode"""
    
    replica_mode = get_replica_mode()
    
    if replica_mode == 'cluster':
        # Check database type
        db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
        
        if not _is_postgres_database(db_uri):
            raise ValueError(
                "❌ INVALID CONFIGURATION:\n"
                f"   REPLICA_MODE='cluster' requires PostgreSQL, but got: {_get_db_type(db_uri)}\n"
                f"   SQLite cannot support multi-replica cluster mode due to:\n"
                f"   - No connection pooling support\n"
                f"   - No network replication\n"
                f"   - Limited concurrent writes\n"
                f"\n"
                f"   To fix:\n"
                f"   1. Set SQLALCHEMY_DATABASE_URI to PostgreSQL (postgresql://...)\n"
                f"   2. Run migrations: flask db upgrade\n"
                f"   3. Restart application"
            )
```

**When Checked:**
- Application startup (if fails, app refuses to start)
- During Helm install/upgrade (if enabled via values)
- Kubernetes validation via ValidatingWebhook (if configured)

**Error Message Example:**

```
RuntimeError: Invalid replica configuration
  REPLICA_MODE=cluster detected
  
  ❌ Database is SQLite (sqlite:///kubedash.db)
  
  SQLite CANNOT be used with cluster mode!
  Required: PostgreSQL (postgresql://user:pass@host/db)
  
  To migrate:
  1. Set SQLALCHEMY_DATABASE_URI=postgresql://...
  2. Run: flask db upgrade
  3. Run migration script: python scripts/migrate_sqlite_to_postgres.py
  
  See: docs/operations/sqlite-to-postgres-migration.md
```

### Rule 2: Single-Replica Allows SQLite or PostgreSQL

**Rule:** Single-replica mode (`REPLICA_MODE=single`) supports both SQLite and PostgreSQL.

```python
if replica_mode == 'single':
    # Both SQLite and PostgreSQL are valid
    # No additional validation needed
    logger.info(f"Single-replica mode: Using {_get_db_type(db_uri)}")
```

**Recommendation:** Use PostgreSQL even in single-replica for:
- Easier future scaling
- Better performance
- HA migration path

### Rule 3: Default to Safe Mode

**Rule:** If REPLICA_MODE not set, default to `single` (safe, lowest barrier to entry).

```python
def get_replica_mode():
    """Get replica mode with safe defaults"""
    mode = os.environ.get('REPLICA_MODE', 'single').lower()
    
    valid_modes = ['single', 'cluster']
    if mode not in valid_modes:
        raise ValueError(f"REPLICA_MODE must be one of {valid_modes}, got: {mode}")
    
    return mode
```

### Rule 4: Replica Count Consistency

**Rule:** REPLICA_COUNT must match actual pod replicas.

```python
def validate_replica_count():
    """Validate replica count is consistent"""
    
    desired_count = int(os.environ.get('REPLICA_COUNT', '1'))
    
    # In Kubernetes, verify against actual pods
    if os.environ.get('KUBERNETES_SERVICE_HOST'):
        actual_replicas = _count_actual_pods()
        
        if actual_replicas < 2 and os.environ.get('REPLICA_MODE') == 'cluster':
            logger.warning(
                f"⚠️  REPLICA_MODE=cluster but only {actual_replicas} pod(s) running\n"
                f"   Increase replicas to >= 2 for cluster mode\n"
                f"   Current: {actual_replicas}, Desired: {desired_count}"
            )
```

**How to Check:**

```bash
# View reported replica count
curl http://localhost:8000/api/v1/cluster/mode

# Output:
# {
#   "mode": "cluster",
#   "replica_count": 3,
#   "actual_pods": 3,
#   "feature_flags": ["leader_election", "shared_sessions", "leader_tasks"]
# }
```

### Rule 5: PostgreSQL Version Check

**Rule:** PostgreSQL must be version 12+

```python
def validate_postgres_version():
    """Ensure PostgreSQL version supports required features"""
    
    if not _is_postgres_database():
        return  # Not PostgreSQL, skip check
    
    with db.engine.connect() as conn:
        version = conn.execute(text("SELECT version()")).scalar()
        major_version = int(version.split()[1].split('.')[0])
        
        if major_version < 12:
            raise ValueError(
                f"PostgreSQL version {major_version} not supported\n"
                f"Required: 12+\n"
                f"Reason: Replication features require 12+"
            )
```

## Validation Points

### 1. Application Startup

```python
# src/kubedash/app.py

def create_app(config_name='default'):
    app = Flask(__name__)
    
    # Step 1: Load configuration
    app.config.from_object(config)
    
    # Step 2: Validate replica mode (EARLY, before DB init)
    validate_replica_config()  # Fails here if invalid
    
    # Step 3: Initialize database
    db.init_app(app)
    
    # Step 4: Validate database compatibility
    validate_postgres_version()
    
    # Step 5: Run migrations
    with app.app_context():
        Migrate(app, db)
    
    return app
```

### 2. Kubernetes Deployment

Validation via initContainer:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubedash
spec:
  template:
    spec:
      initContainers:
      # Validate configuration before starting
      - name: validate-config
        image: kubedash:latest
        command:
        - python3
        - -c
        - |
          import sys
          from app import create_app
          try:
              app = create_app()
              print("✅ Configuration valid")
              sys.exit(0)
          except ValueError as e:
              print(f"❌ Configuration invalid: {e}")
              sys.exit(1)
        env:
        - name: SQLALCHEMY_DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: kubedash-db
              key: connection-url
        - name: REPLICA_MODE
          value: "cluster"
      
      # Run migrations
      - name: migrate
        image: kubedash:latest
        command: ["flask", "db", "upgrade"]
        env:
        - name: SQLALCHEMY_DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: kubedash-db
              key: connection-url
      
      containers:
      - name: kubedash
        image: kubedash:latest
        env:
        - name: SQLALCHEMY_DATABASE_URI
          valueFrom:
            secretKeyRef:
              name: kubedash-db
              key: connection-url
        - name: REPLICA_MODE
          value: "cluster"
```

### 3. Helm Chart Validation

```yaml
# deploy/kubedash/templates/deployment.yaml

{{- if and (eq .Values.replicaMode "cluster") (eq .Values.database.type "sqlite") }}
  {{- fail "Database type must be PostgreSQL for cluster mode" }}
{{- end }}

{{- if and (eq .Values.replicaMode "cluster") (lt (int .Values.replicas) 2) }}
  {{- fail "Cluster mode requires at least 2 replicas" }}
{{- end }}
```

## Validation Checklist

Create a validation script that developers and operators can run:

```python
#!/usr/bin/env python3
"""Validate KubeDash database configuration"""

import os
import sys
from sqlalchemy import create_engine, text, __version__ as sa_version

def check_database_type():
    """Check database is correct type for deployment mode"""
    db_uri = os.environ.get('SQLALCHEMY_DATABASE_URI')
    replica_mode = os.environ.get('REPLICA_MODE', 'single')
    
    is_postgres = db_uri and 'postgresql' in db_uri
    is_sqlite = db_uri and ('sqlite' in db_uri or db_uri.startswith('sqlite'))
    
    print("\n📋 Database Type Check")
    print(f"  REPLICA_MODE: {replica_mode}")
    print(f"  Database: {'PostgreSQL' if is_postgres else 'SQLite' if is_sqlite else 'Unknown'}")
    
    if replica_mode == 'cluster' and not is_postgres:
        print("  ❌ INVALID: Cluster mode requires PostgreSQL")
        return False
    
    print("  ✅ Database type valid for mode")
    return True

def check_database_connection():
    """Check database connectivity"""
    db_uri = os.environ.get('SQLALCHEMY_DATABASE_URI')
    
    if not db_uri:
        print("\n❌ SQLALCHEMY_DATABASE_URI not set")
        return False
    
    print("\n📋 Database Connection Check")
    
    try:
        engine = create_engine(db_uri, echo=False, pool_pre_ping=True)
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print(f"  ✅ Connected successfully")
            return True
    except Exception as e:
        print(f"  ❌ Connection failed: {e}")
        return False

def check_postgresql_version():
    """Check PostgreSQL version if applicable"""
    db_uri = os.environ.get('SQLALCHEMY_DATABASE_URI')
    
    if not db_uri or 'postgresql' not in db_uri:
        return True  # Not PostgreSQL
    
    print("\n📋 PostgreSQL Version Check")
    
    try:
        engine = create_engine(db_uri)
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version()")).scalar()
            major = int(version.split()[1].split('.')[0])
            
            print(f"  Version: {version.split(',')[0]}")
            
            if major >= 12:
                print(f"  ✅ PostgreSQL {major}+ supported")
                return True
            else:
                print(f"  ❌ PostgreSQL {major} not supported (require 12+)")
                return False
    except Exception as e:
        print(f"  ❌ Version check failed: {e}")
        return False

def check_migrations():
    """Check migrations are applied"""
    print("\n📋 Database Schema Check")
    
    try:
        from app import create_app
        app = create_app()
        with app.app_context():
            # Try to query a known table
            from flask_sqlalchemy import inspect
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            if tables:
                print(f"  ✅ Schema exists ({len(tables)} tables)")
                return True
            else:
                print(f"  ⚠️  No tables found (migrations may not be applied)")
                return False
    except Exception as e:
        print(f"  ⚠️  Could not verify schema: {e}")
        return False

def check_configuration():
    """Check environment configuration"""
    print("\n📋 Environment Configuration Check")
    
    checks = {
        'REPLICA_MODE': os.environ.get('REPLICA_MODE', 'single'),
        'REPLICA_COUNT': os.environ.get('REPLICA_COUNT', '1'),
        'POD_NAME': os.environ.get('POD_NAME', '(not set)'),
        'POD_NAMESPACE': os.environ.get('POD_NAMESPACE', '(not set)'),
        'SQLALCHEMY_DATABASE_URI': '(set)' if os.environ.get('SQLALCHEMY_DATABASE_URI') else '(not set)',
    }
    
    for key, value in checks.items():
        if key == 'SQLALCHEMY_DATABASE_URI':
            status = "✅" if value == '(set)' else "❌"
        else:
            status = "✅"
        print(f"  {status} {key}: {value}")
    
    return os.environ.get('SQLALCHEMY_DATABASE_URI') is not None

def main():
    """Run all validation checks"""
    print("🔍 KubeDash Database Configuration Validation\n")
    
    checks = [
        ("Database Type", check_database_type),
        ("Configuration", check_configuration),
        ("Connection", check_database_connection),
        ("PostgreSQL Version", check_postgresql_version),
        ("Schema", check_migrations),
    ]
    
    results = []
    for name, check_fn in checks:
        try:
            result = check_fn()
            results.append((name, result))
        except Exception as e:
            print(f"  ❌ Check failed: {e}")
            results.append((name, False))
    
    print("\n" + "="*50)
    print("Validation Summary:")
    print("="*50)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    all_pass = all(r for _, r in results)
    
    if all_pass:
        print("\n✅ All checks passed!")
        return 0
    else:
        print("\n❌ Some checks failed. Review above for details.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
```

Run the validation:

```bash
# Run validation script
cd src/kubedash
python3 scripts/validate-db-config.py

# Example output:
# 🔍 KubeDash Database Configuration Validation
#
# 📋 Database Type Check
#   REPLICA_MODE: cluster
#   Database: PostgreSQL
#   ✅ Database type valid for mode
#
# 📋 Environment Configuration Check
#   ✅ REPLICA_MODE: cluster
#   ✅ REPLICA_COUNT: 3
#   ✅ POD_NAME: kubedash-0
#   ✅ POD_NAMESPACE: default
#   ✅ SQLALCHEMY_DATABASE_URI: (set)
#
# 📋 Database Connection Check
#   ✅ Connected successfully
#
# 📋 PostgreSQL Version Check
#   Version: PostgreSQL 14.7 on x86_64-pc-linux-gnu
#   ✅ PostgreSQL 14+ supported
#
# 📋 Database Schema Check
#   ✅ Schema exists (15 tables)
#
# ==================================================
# Validation Summary:
# ==================================================
# ✅ PASS: Database Type
# ✅ PASS: Configuration
# ✅ PASS: Connection
# ✅ PASS: PostgreSQL Version
# ✅ PASS: Schema
#
# ✅ All checks passed!
```

## How It Works

### Detection Functions

```python
# src/kubedash/lib/database.py

def is_sqlite_database(db_uri: str) -> bool:
    """Check if database is SQLite"""
    return db_uri.startswith('sqlite://') or 'sqlite' in db_uri.lower()

def is_postgres_database(db_uri: str) -> bool:
    """Check if database is PostgreSQL"""
    return db_uri.startswith('postgresql://') or 'postgres' in db_uri.lower()

def get_database_type(db_uri: str) -> str:
    """Get human-readable database type"""
    if is_sqlite_database(db_uri):
        return "SQLite"
    elif is_postgres_database(db_uri):
        return "PostgreSQL"
    else:
        return "Unknown"
```

### Logging

When validation rules are enforced:

```
2026-04-05 10:15:30 INFO  Validating replica configuration...
2026-04-05 10:15:30 INFO  REPLICA_MODE: cluster
2026-04-05 10:15:30 INFO  Database type: PostgreSQL
2026-04-05 10:15:30 INFO  ✅ Configuration valid
2026-04-05 10:15:30 INFO  PostgreSQL version 14.7 (supports leader election)
2026-04-05 10:15:30 INFO  Leader election enabled
2026-04-05 10:15:30 INFO  Replica count: 3
```

## Troubleshooting Invalid Configurations

### Error: "Cluster mode requires PostgreSQL"

**Cause:** Running cluster mode with SQLite

**Fix:**
```bash
# Option 1: Switch to single-replica
export REPLICA_MODE=single

# Option 2: Migrate to PostgreSQL
export SQLALCHEMY_DATABASE_URI="postgresql://user:pass@postgres:5432/kubedash"
python3 scripts/migrate_sqlite_to_postgres.py
export REPLICA_MODE=cluster
export REPLICA_COUNT=3
```

### Error: "PostgreSQL version 11 not supported"

**Cause:** Using PostgreSQL 11 (too old)

**Fix:** Upgrade PostgreSQL to 12+

```bash
# Cloud provider upgrade (managed PostgreSQL)
# AWS RDS: Use AWS console or: aws rds modify-db-instance --engine-version 14.7

# Self-hosted: Backup, upgrade, restore
pg_dumpall > backup.sql
# Upgrade PostgreSQL package
psql < backup.sql
```

## Best Practices

1. **Always validate before starting:** Run validation script before deployment
2. **Use PostgreSQL even for single-replica:** Future-proofs your setup
3. **Test migration path:** Before going to production
4. **Monitor validation logs:** Alert if configuration becomes invalid
5. **Document your choice:** Why did you pick SQLite or PostgreSQL?

## Validation Status Endpoint

Check validation status via API:

```bash
curl http://localhost:8000/api/v1/health/ready

# Returns:
# {
#   "status": "ready",
#   "checks": {
#     "database": "connected",
#     "database_type": "PostgreSQL",
#     "replica_mode": "cluster",
#     "schema_version": "20260405_001",
#     "leader_elected": true
#   }
# }
```
