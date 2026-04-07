# PostgreSQL High Availability for Multi-Replica KubeDash

## Overview

For multi-replica KubeDash, PostgreSQL must be highly available. This guide covers HA configurations for PostgreSQL.

## Option 1: Managed PostgreSQL (Recommended)

Use a managed service for lowest operational burden:

### AWS RDS PostgreSQL

```bash
# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier kubedash-db \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username postgres \
  --master-user-password <secure-password> \
  --allocated-storage 20 \
  --backup-retention-period 30 \
  --multi-az  # Enable Multi-AZ for automatic failover
```

**Configuration:**
- Multi-AZ: Enabled (automatic failover)
- Backup retention: 30 days
- Automatic backups: Enabled
- Connection string: `postgresql://user:pass@kubedash-db.abc123.us-east-1.rds.amazonaws.com:5432/kubedash`

### Google Cloud SQL

```bash
# Create Cloud SQL instance
gcloud sql instances create kubedash-db \
  --database-version=POSTGRES_14 \
  --tier=db-g1-small \
  --region=us-central1 \
  --availability-type=REGIONAL  # Enables HA
```

**Configuration:**
- Availability type: Regional (automatic failover)
- Backups: Daily
- Connection: Via Cloud Proxy or public IP

### Azure Database for PostgreSQL

```bash
# Create Azure PostgreSQL instance
az postgres server create \
  --name kubedash-db \
  --resource-group kubedash \
  --location eastus \
  --admin-user postgres \
  --admin-password <secure-password> \
  --sku-name B_Gen5_2 \
  --geo-redundant-backup Enabled  # HA replication
```

**Configuration:**
- Geo-redundant backup: Enabled
- Auto-grow storage: Enabled
- Backup retention: 35 days

---

## Option 2: Self-Hosted with Patroni (High Complexity)

For on-premise or custom deployments using Patroni for automatic failover.

### Architecture

```
┌─────────────────────────────────────────────┐
│ Kubernetes Namespace                        │
├─────────────────────────────────────────────┤
│                                             │
│ Primary PostgreSQL (Leader)                 │
│ ├─ Patroni (Service: leader role)           │
│ └─ PVC (persistent storage)                 │
│                                             │
│ Secondary PostgreSQL (Replicas)             │
│ ├─ Pod 1: Patroni                           │
│ ├─ Pod 2: Patroni                           │
│ └─ PVCs (persistent storage)                │
│                                             │
│ etcd Cluster (Patroni coordination)         │
│ ├─ etcd-0, etcd-1, etcd-2                   │
│ └─ ConfigMaps for leader tracking           │
│                                             │
└─────────────────────────────────────────────┘
```

### Deployment

#### 1. Deploy etcd (Patroni needs a DCS)

```bash
# Using Bitnami chart
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install etcd bitnami/etcd \
  --set statefulset.replicaCount=3 \
  --set persistence.size=10Gi
```

#### 2. Deploy PostgreSQL with Patroni

Create `patroni-postgres-statefulset.yaml`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: patroni-config
data:
  patroni.yaml: |
    scope: kubedash-postgres
    name: ${HOSTNAME}
    namespace: default
    restapi:
      connect_address: 0.0.0.0:8008
    bootstrap:
      dcs:
        type: etcd3
        etcd:
          hosts:
          - etcd:2379
      initdb:
      - encoding: UTF8
        locale: en_US.UTF-8
        data-checksums: true
    postgresql:
      connect_address: 0.0.0.0:5432
      admin_username: postgres
      parameters:
        wal_level: replica
        max_wal_senders: 3
        wal_keep_segments: 64
        hot_standby: "on"
      pg_hba:
      - local all postgres trust
      - host replication replicator 127.0.0.1/32 trust
      - host replication replicator 10.0.0.0/8 trust
      - host all all 127.0.0.1/32 trust
      - host all all 10.0.0.0/8 md5
    watchdog:
      mode: off

---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: patroni-postgres
spec:
  serviceName: patroni-postgres
  replicas: 3
  selector:
    matchLabels:
      app: patroni-postgres
  template:
    metadata:
      labels:
        app: patroni-postgres
    spec:
      containers:
      - name: postgres
        image: patroni:latest
        ports:
        - containerPort: 5432
          name: postgres
        - containerPort: 8008
          name: restapi
        env:
        - name: HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: PGPASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-credentials
              key: password
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
        - name: patroni-config
          mountPath: /etc/patroni
        livenessProbe:
          httpGet:
            path: /primary
            port: 8008
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /primary
            port: 8008
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: patroni-config
        configMap:
          name: patroni-config
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: fast-ssd
      resources:
        requests:
          storage: 50Gi

---
apiVersion: v1
kind: Service
metadata:
  name: patroni-postgres
spec:
  clusterIP: None
  selector:
    app: patroni-postgres
  ports:
  - port: 5432
    name: postgres

---
apiVersion: v1
kind: Service
metadata:
  name: patroni-postgres-primary
spec:
  selector:
    app: patroni-postgres
    role: primary
  ports:
  - port: 5432
    targetPort: 5432
```

Deploy:

```bash
kubectl create secret generic postgres-credentials \
  --from-literal=password=<secure-password>

kubectl apply -f patroni-postgres-statefulset.yaml
```

#### 3. Connect KubeDash to Patroni Primary

```bash
# Update KubeDash deployment to use patroni-postgres-primary
kubectl set env deployment/kubedash \
  SQLALCHEMY_DATABASE_URI="postgresql://postgres:<password>@patroni-postgres-primary:5432/kubedash"
```

### Patroni Monitoring

```bash
# Check Patroni cluster status
kubectl exec -it patroni-postgres-0 -- patronictl -c /etc/patroni/patroni.yaml list

# Example output:
# + Cluster: kubedash-postgres (6856107544926027652) ----+
# | Member       | Host            | Role         | State | Lag in MB |
# +--------------+-----------------+--------------+-------+-----------+
# | patroni-postgres-0 | patroni-postgres-0 | Leader  | running |        |
# | patroni-postgres-1 | patroni-postgres-1 | Replica | running |       0 |
# | patroni-postgres-2 | patroni-postgres-2 | Replica | running |       0 |
# +--------------+-----------------+--------------+-------+-----------+
```

---

## Option 3: Streaming Replication (Medium Complexity)

For on-premise deployments with manual failover.

### Setup: 1 Primary + 2 Replicas

Primary PostgreSQL:
```sql
-- Enable WAL archiving
ALTER SYSTEM SET wal_level = replica;
ALTER SYSTEM SET max_wal_senders = 3;
ALTER SYSTEM SET hot_standby = on;
SELECT pg_reload_conf();
```

Replicas (via pg_basebackup):
```bash
pg_basebackup -h primary.db -D ./data -U replicator -v -P
```

**Limitations:**
- Manual failover required
- No automatic replica promotion
- Requires external tooling or manual procedures

---

## Connection Pooling (Required for Multi-Replica)

### PgBouncer Configuration

```ini
# pgbouncer.ini
[databases]
kubedash = host=patroni-postgres port=5432 user=postgres password=secret dbname=kubedash

[pgbouncer]
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
min_pool_size = 10
reserve_pool_size = 5
reserve_pool_timeout = 3
timeout = 600
```

Deploy in Kubernetes:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pgbouncer-config
data:
  pgbouncer.ini: |
    [databases]
    kubedash = host=patroni-postgres-primary port=5432 user=postgres dbname=kubedash
    [pgbouncer]
    pool_mode = transaction
    max_client_conn = 1000
    default_pool_size = 25

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pgbouncer
spec:
  replicas: 2
  selector:
    matchLabels:
      app: pgbouncer
  template:
    metadata:
      labels:
        app: pgbouncer
    spec:
      containers:
      - name: pgbouncer
        image: pgbouncer:latest
        ports:
        - containerPort: 6432
        volumeMounts:
        - name: config
          mountPath: /etc/pgbouncer
      volumes:
      - name: config
        configMap:
          name: pgbouncer-config

---
apiVersion: v1
kind: Service
metadata:
  name: pgbouncer
spec:
  selector:
    app: pgbouncer
  ports:
  - port: 6432
    targetPort: 6432
```

Connect KubeDash to PgBouncer:

```bash
kubectl set env deployment/kubedash \
  SQLALCHEMY_DATABASE_URI="postgresql://postgres:secret@pgbouncer:6432/kubedash"
```

---

## Database Health Checks

### Liveness Check

```bash
# Test connection
kubectl exec -it kubedash-0 -- psql \
  postgresql://postgres:secret@patroni-postgres-primary/kubedash \
  -c "SELECT 1"
```

### Replication Status

```bash
# Check replication lag
kubctl exec -it patroni-postgres-0 -- psql -U postgres -d postgres -c \
  "SELECT slot_name, restart_lsn, confirmed_flush_lsn FROM pg_replication_slots;"
```

---

## Backup and Recovery

### Automated Backups (Managed Services)

- AWS RDS: Automatic daily snapshots
- Google Cloud SQL: Cloud Backup
- Azure: Geo-redundant backups

### Manual Backups (Self-Hosted)

```bash
# Full backup
pg_dump postgresql://postgres:secret@primary/kubedash | gzip > kubedash-$(date +%Y%m%d).sql.gz

# Point-in-time recovery
pg_restlog -D ./data --recovery-target-timeline latest
```

---

## Disaster Recovery Procedures

### Complete Database Lost

1. Restore from automated backup (RDS, Cloud SQL, Azure)
2. Verify data integrity
3. Update KubeDash connection string if needed

### Replication Lag > 100MB

```bash
# Check lag on replica
SELECT slot_name, restart_lsn, confirmed_flush_lsn 
FROM pg_replication_slots;

# If lag is too high, consider:
# 1. Increasing wal_keep_segments
# 2. Reeinitializing replica from scratch
# 3. Checking network bandwidth
```

---

## Recommendation Summary

| Scenario | Option | Complexity | Failover Time |
|----------|--------|-----------|--------------|
| AWS cloud | RDS Multi-AZ | Low | < 2 min |
| GCP cloud | Cloud SQL HA | Low | < 2 min |
| Azure cloud | Database HA | Low | < 2 min |
| On-premise | Patroni + etcd | High | < 30 sec |
| On-premise minimal | Streaming replication | Medium | Manual |

**Recommendation:** Use managed PostgreSQL (RDS/Cloud SQL/Azure) for production KubeDash multi-replica deployments.
