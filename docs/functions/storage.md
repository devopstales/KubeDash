# Storage Resources

KubeDash provides comprehensive visibility into your cluster's storage configuration including Storage Classes, Persistent Volumes, Persistent Volume Claims, ConfigMaps, and Volume Snapshots.

## Storage Classes

Storage Classes define different types of storage available in your cluster.

### Viewing Storage Classes

Navigate to `Storage > Storage Classes` to see all storage classes:

![Storage Class List](../img/storage/storage-class-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Storage class name |
| Provisioner | Storage provisioner (e.g., kubernetes.io/aws-ebs) |
| Reclaim Policy | Delete or Retain |
| Volume Binding Mode | Immediate or WaitForFirstConsumer |
| Allow Volume Expansion | Whether volumes can be resized |
| Default | Whether this is the default storage class |

### Storage Class Details

Click on a storage class to view:

- **Provisioner**: The volume plugin used
- **Parameters**: Provider-specific parameters
- **Reclaim Policy**: What happens when PVC is deleted
- **Mount Options**: Default mount options

### Common Storage Provisioners

| Provisioner | Description |
|-------------|-------------|
| `kubernetes.io/aws-ebs` | AWS EBS volumes |
| `kubernetes.io/gce-pd` | Google Cloud Persistent Disk |
| `kubernetes.io/azure-disk` | Azure Disk |
| `kubernetes.io/cinder` | OpenStack Cinder |
| `rancher.io/local-path` | Local path provisioner |

## Persistent Volumes (PV)

Persistent Volumes are cluster-wide storage resources.

### Viewing Persistent Volumes

Navigate to `Storage > Persistent Volumes` to see all PVs:

![PV List](../img/storage/pv-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | PV name |
| Capacity | Storage capacity |
| Access Modes | RWO, ROX, RWX |
| Reclaim Policy | Delete, Retain, or Recycle |
| Status | Available, Bound, Released, or Failed |
| Claim | Bound PVC (if any) |
| Storage Class | Associated storage class |
| Age | Time since creation |

### PV Details

Click on a PV to view:

- **Spec**: Capacity, access modes, storage class
- **Source**: Volume source (AWS EBS, NFS, etc.)
- **Status**: Current phase and bound claim
- **Mount Options**: Configured mount options

### Access Modes

| Mode | Abbreviation | Description |
|------|--------------|-------------|
| ReadWriteOnce | RWO | Single node read-write |
| ReadOnlyMany | ROX | Multiple nodes read-only |
| ReadWriteMany | RWX | Multiple nodes read-write |
| ReadWriteOncePod | RWOP | Single pod read-write |

## Persistent Volume Claims (PVC)

PVCs are requests for storage by users.

### Viewing PVCs

Navigate to `Storage > PVCs` to see all PVCs in the selected namespace:

![PVC List](../img/storage/pvc-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | PVC name |
| Status | Pending, Bound, or Lost |
| Volume | Bound PV name |
| Capacity | Allocated capacity |
| Access Modes | Requested access modes |
| Storage Class | Requested storage class |
| Age | Time since creation |

### PVC Details

Click on a PVC to view:

- **Spec**: Requested resources, access modes, storage class
- **Status**: Phase, bound volume, capacity
- **Conditions**: Resizing status, etc.

### PVC Metrics

KubeDash displays storage usage metrics when available:

- **Used**: Current storage usage
- **Available**: Free space
- **Capacity**: Total capacity
- **Usage %**: Percentage used

!!! note
    Storage metrics require a metrics provider that exposes volume statistics.

## Volume Snapshots

Volume Snapshots provide point-in-time copies of volumes.

### Viewing Volume Snapshots

Navigate to `Storage > Volume Snapshots` to see all snapshots:

![Snapshot List](../img/storage/snapshot-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | Snapshot name |
| Source PVC | Original PVC |
| Snapshot Class | VolumeSnapshotClass used |
| Ready | Whether snapshot is ready to use |
| Age | Time since creation |

## Snapshot Classes

Snapshot Classes define how snapshots are created.

### Viewing Snapshot Classes

Navigate to `Storage > Snapshot Classes` to see all snapshot classes:

The list shows:

| Column | Description |
|--------|-------------|
| Name | Snapshot class name |
| Driver | CSI driver |
| Deletion Policy | Delete or Retain |

## ConfigMaps

ConfigMaps store non-confidential configuration data.

### Viewing ConfigMaps

Navigate to `Storage > ConfigMaps` to see all ConfigMaps in the selected namespace:

![ConfigMap List](../img/storage/configmap-list.png)

The list shows:

| Column | Description |
|--------|-------------|
| Name | ConfigMap name |
| Data | Number of keys |
| Age | Time since creation |

### ConfigMap Details

Click on a ConfigMap to view:

- **Data**: Key-value pairs
- **Binary Data**: Binary data entries (if any)
- **Metadata**: Labels, annotations

The data view shows:

- Key names
- Value contents (with syntax highlighting for common formats)
- Binary data indicators

!!! tip
    ConfigMaps are displayed with syntax highlighting for YAML, JSON, and properties files.

## Best Practices

### Storage Class Selection

- Use `WaitForFirstConsumer` binding mode for topology-aware provisioning
- Set appropriate reclaim policies (Retain for important data)
- Enable volume expansion for dynamic sizing

### PVC Management

- Always specify storage class explicitly
- Request appropriate access modes
- Monitor PVC usage to avoid capacity issues

### ConfigMap Organization

- Use meaningful names
- Group related configuration in single ConfigMaps
- Consider using Secrets for sensitive data instead

### Backup Strategy

- Use Volume Snapshots for point-in-time backups
- Test snapshot restoration regularly
- Consider external backup solutions for critical data
