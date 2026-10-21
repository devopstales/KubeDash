import { describe, expect, test } from 'vitest'
import { navigation, type NavItem } from '../src/_nav'

function flat(items: NavItem[]): { name: string; to?: string }[] {
  return items.flatMap((item) =>
    item.divider
      ? []
      : item.items
        ? [{ name: item.name }, ...flat(item.items)]
        : [{ name: item.name, to: item.to }],
  )
}

const adminLabels = [
  'Dashboard',
  'Cluster Metrics',
  'Workload',
  'Permissions',
  'Cluster Details',
  'My access',
  'User Management',
  'Users',
  'Groups',
  'Cluster Permissions',
  'ServiceAccounts',
  'Roles',
  'RoleBindings',
  'ClusterRoles',
  'ClusterRoleBindings',
  'Interface',
  'Cluster',
  'Namespaces',
  'Nodes',
  'CRDs',
  'Workloads',
  'Pods',
  'Deployments',
  'StatefulSets',
  'DaemonSets',
  'ReplicaSets',
  'Network',
  'Services',
  'Ingress',
  'Storage',
  'ConfigMaps',
  'Volumes',
  'VolumeClaims',
  'VolumeSnapshot',
  'StorageClass',
  'SnapshotClass',
  'Security',
  'Secrets',
  'Network Policies',
  'Priority Classes',
  'Other Resources',
  'HPAs',
  'VPAs',
  'Pod Disruption Budget',
  'Resource Quota',
  'Limit Range',
  'Runtime Class',
  'Settings',
  'Auth Provider',
  'Kubernetes Cluster',
  'HA Status',
  'Audit Log',
]

const banned = [
  'Plugins',
  'Cert-Manager',
  'LoadBalancers',
  'Gateway API',
  'Trivy Operator',
  'Applications',
]

describe('navigation contract', () => {
  test('menu-matches-4-1-without-plugins', () => {
    const items = navigation({ clusterId: 7, isAdmin: true })
    const names = flat(items).map((entry) => entry.name)
    expect(names).toEqual(adminLabels)
    for (const label of banned) {
      expect(names).not.toContain(label)
    }
  })

  test('cluster-details-follows-selection', () => {
    const items = navigation({ clusterId: 7, isAdmin: true })
    expect(flat(items).find((entry) => entry.name === 'Cluster Details')?.to).toBe('/clusters/7')
  })

  test('cluster-details-without-selection-opens-cluster-list', () => {
    const items = navigation({ clusterId: null, isAdmin: false })
    expect(flat(items).find((entry) => entry.name === 'Cluster Details')?.to).toBe('/clusters')
  })

  test('plugin-entries-never-appear', () => {
    for (const isAdmin of [true, false]) {
      const names = flat(navigation({ clusterId: 7, isAdmin })).map((entry) => entry.name)
      for (const label of banned) {
        expect(names).not.toContain(label)
      }
    }
  })

  test('cluster-metrics-and-kubernetes-cluster-share-cluster-list', () => {
    const entries = flat(navigation({ clusterId: 7, isAdmin: true }))
    expect(entries.find((entry) => entry.name === 'Cluster Metrics')?.to).toBe('/clusters')
    expect(entries.find((entry) => entry.name === 'Kubernetes Cluster')?.to).toBe('/clusters')
  })

  test('workload entry carries the beta badge', () => {
    const dashboard = navigation({ clusterId: 7, isAdmin: true })[0]
    const workload = dashboard.items?.find((entry) => entry.name === 'Workload')
    expect(workload?.badge).toEqual({ color: 'warning', text: 'Beta' })
    expect(workload?.to).toBe('/dashboard/workload-map')
  })
})
