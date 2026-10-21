export type StubRoute = {
  path: string
  title: string
  admin: boolean
}

/** Menu entries that have no view yet. Paths match navigation() in src/_nav.tsx. */
export const stubRoutes: StubRoute[] = [
  { path: '/dashboard/workload-map', title: 'Workload', admin: false },
  { path: '/cluster-permission/cluster-role-binding', title: 'ClusterRoleBindings', admin: false },
  { path: '/cluster/node', title: 'Nodes', admin: false },
  { path: '/cluster/crd', title: 'CRDs', admin: false },
  { path: '/workload/pods', title: 'Pods', admin: false },
  { path: '/workload/deployments', title: 'Deployments', admin: false },
  { path: '/workload/statefulsets', title: 'StatefulSets', admin: false },
  { path: '/workload/daemonsets', title: 'DaemonSets', admin: false },
  { path: '/workload/replicasets', title: 'ReplicaSets', admin: false },
  { path: '/network/service', title: 'Services', admin: false },
  { path: '/network/ingress', title: 'Ingress', admin: false },
  { path: '/storage/configmap', title: 'ConfigMaps', admin: false },
  { path: '/storage/pv', title: 'Volumes', admin: false },
  { path: '/storage/pvc', title: 'VolumeClaims', admin: false },
  { path: '/storage/volumesnapshot', title: 'VolumeSnapshot', admin: false },
  { path: '/storage/storage-class', title: 'StorageClass', admin: false },
  { path: '/storage/snapshot-class', title: 'SnapshotClass', admin: false },
  { path: '/security/network-policy', title: 'Network Policies', admin: false },
  { path: '/security/priorityclass', title: 'Priority Classes', admin: false },
  { path: '/other-resource/horizontal-pod-autoscaler', title: 'HPAs', admin: false },
  { path: '/other-resource/vertical-pod-autoscaler', title: 'VPAs', admin: false },
  { path: '/other-resource/pod-disruption-budget', title: 'Pod Disruption Budget', admin: false },
  { path: '/other-resource/resource-quota', title: 'Resource Quota', admin: false },
  { path: '/other-resource/limit-range', title: 'Limit Range', admin: false },
  { path: '/other-resource/runtimeclass', title: 'Runtime Class', admin: false },
  { path: '/settings/sso-config', title: 'Auth Provider', admin: true },
  { path: '/settings/cluster-status', title: 'HA Status', admin: true },
]
