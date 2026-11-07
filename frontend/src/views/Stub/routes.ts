export type StubRoute = {
  path: string
  title: string
  admin: boolean
}

/** Menu entries that have no view yet. Paths match navigation() in src/_nav.tsx. */
export const stubRoutes: StubRoute[] = [
  { path: '/dashboard/workload-map', title: 'Workload', admin: false },
  { path: '/workload/pods', title: 'Pods', admin: false },
  { path: '/workload/deployments', title: 'Deployments', admin: false },
  { path: '/workload/statefulsets', title: 'StatefulSets', admin: false },
  { path: '/workload/daemonsets', title: 'DaemonSets', admin: false },
  { path: '/workload/replicasets', title: 'ReplicaSets', admin: false },
  { path: '/settings/sso-config', title: 'Auth Provider', admin: true },
  { path: '/settings/cluster-status', title: 'HA Status', admin: true },
]
