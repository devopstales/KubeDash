import React, { type ReactNode } from 'react'
import { CNavGroup, CNavItem, CNavTitle } from '@coreui/react'
import CIcon from '@coreui/icons-react'
import {
  cilApplications,
  cilGroup,
  cilLan,
  cilLayers,
  cilNotes,
  cilSettings,
  cilShieldAlt,
  cilSpeedometer,
  cilStorage,
  cilUser,
} from '@coreui/icons'

/**
 * Sidebar menu for the React shell. Labels and order follow the 4.1
 * information architecture (ADR-0022) minus Plugins. Cluster Details and
 * My access are not menu entries. 4.1's Jinja templates are a visual
 * reference only; this module is the implementation.
 */

export type NavBadge = { color: 'warning'; text: 'Beta' }

export type NavItem = {
  component: React.ElementType
  name: string
  icon?: ReactNode
  badge?: NavBadge
  to?: string
  items?: NavItem[]
  divider?: boolean
  className?: string
}

const icon = (glyph: string[]) => <CIcon icon={glyph} customClassName="nav-icon" />

const leaf = (name: string, to: string): NavItem => ({
  component: CNavItem,
  name,
  to,
})

const group = (name: string, glyph: string[], items: NavItem[]): NavItem => ({
  component: CNavGroup,
  name,
  icon: icon(glyph),
  items,
})

const divider = (): NavItem => ({
  component: 'div',
  name: '',
  divider: true,
  className: 'border-top d-none d-md-flex',
})

export function navigation(input: { clusterId: number | null; isAdmin: boolean }): NavItem[] {
  const items: NavItem[] = [
    group('Dashboard', cilSpeedometer, [
      leaf('Cluster Metrics', '/dashboard/cluster-metric'),
      {
        component: CNavItem,
        name: 'Workload',
        to: '/dashboard/workload-map',
        badge: { color: 'warning', text: 'Beta' },
      },
    ]),
    divider(),
    { component: CNavTitle, name: 'Permissions' },
    group('User Management', cilUser, [leaf('Users', '/user/list'), leaf('Groups', '/user/group')]),
    group('Cluster Permissions', cilGroup, [
      leaf('ServiceAccounts', '/cluster-permission/service-account'),
      leaf('Roles', '/cluster-permission/role'),
      leaf('RoleBindings', '/cluster-permission/role-binding'),
      leaf('ClusterRoles', '/cluster-permission/cluster-role'),
      leaf('ClusterRoleBindings', '/cluster-permission/cluster-role-binding'),
    ]),
    divider(),
    { component: CNavTitle, name: 'Interface' },
    group('Cluster', cilLayers, [
      leaf('Namespaces', '/cluster/namespace'),
      leaf('Nodes', '/cluster/node'),
      leaf('CRDs', '/cluster/crd'),
    ]),
    group('Workloads', cilApplications, [
      leaf('Pods', '/workload/pods'),
      leaf('Deployments', '/workload/deployments'),
      leaf('StatefulSets', '/workload/statefulsets'),
      leaf('DaemonSets', '/workload/daemonsets'),
      leaf('ReplicaSets', '/workload/replicasets'),
    ]),
    group('Network', cilLan, [
      leaf('Services', '/network/service'),
      leaf('Ingress', '/network/ingress'),
    ]),
    group('Storage', cilStorage, [
      leaf('ConfigMaps', '/storage/configmap'),
      leaf('Volumes', '/storage/pv'),
      leaf('VolumeClaims', '/storage/pvc'),
      leaf('VolumeSnapshot', '/storage/volumesnapshot'),
      leaf('StorageClass', '/storage/storage-class'),
      leaf('SnapshotClass', '/storage/snapshot-class'),
    ]),
    group('Security', cilShieldAlt, [
      leaf('Secrets', '/security/secret'),
      leaf('Network Policies', '/security/network-policy'),
      leaf('Priority Classes', '/security/priorityclass'),
    ]),
    group('Other Resources', cilNotes, [
      leaf('HPAs', '/other-resource/horizontal-pod-autoscaler'),
      leaf('VPAs', '/other-resource/vertical-pod-autoscaler'),
      leaf('Pod Disruption Budget', '/other-resource/pod-disruption-budget'),
      leaf('Resource Quota', '/other-resource/resource-quota'),
      leaf('Limit Range', '/other-resource/limit-range'),
      leaf('Runtime Class', '/other-resource/runtimeclass'),
    ]),
  ]

  items.push(
    group('Settings', cilSettings, [
      leaf('Auth Provider', '/settings/sso-config'),
      leaf('Kubernetes Cluster', '/clusters'),
      leaf('HA Status', '/settings/cluster-status'),
      leaf('Audit Log', '/admin/permissions?tab=audit'),
    ]),
  )

  return items
}
