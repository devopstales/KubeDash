import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { beforeEach, describe, expect, test } from 'vitest'
import { server } from './msw'
import { navigation, type NavItem } from '../src/_nav'
import { useClusterStore } from '../src/store/cluster'
import { useSidebarStore } from '../src/store/sidebar'
import AppHeader from '../src/components/AppHeader'
import AppSidebar from '../src/components/AppSidebar'

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

  test('cluster-details-and-my-access-are-not-menu-entries', () => {
    const names = flat(navigation({ clusterId: 7, isAdmin: true })).map((entry) => entry.name)
    expect(names).not.toContain('Cluster Details')
    expect(names).not.toContain('My access')
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

function renderShell(role: 'admin' | 'user') {
  server.use(
    http.get('*/api/v1/auth/me', () =>
      HttpResponse.json({
        sub: 'u1',
        email: 'dev@kubedash.local',
        display_name: 'Dev',
        groups: [],
        role,
      }),
    ),
    http.get('*/api/v1/clusters', () =>
      HttpResponse.json({ items: [{ id: 7, name: 'prod', status: 'ok' }] }),
    ),
  )
  useClusterStore.setState({ selectedCluster: { id: 7, name: 'prod' } })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AppSidebar />
        <AppHeader />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('rendered sidebar', () => {
  beforeEach(() => {
    useSidebarStore.setState({ visible: true })
  })

  test('header-uses-namespace-and-4-1-links', async () => {
    server.use(
      http.get('*/api/v1/clusters/:id/resources/namespaces', () =>
        HttpResponse.json({
          items: [{ metadata: { name: 'default' } }, { metadata: { name: 'team-a' } }],
          kind: 'namespaces',
          cluster: 'prod',
        }),
      ),
    )
    const user = userEvent.setup()
    renderShell('admin')
    expect(screen.queryByRole('link', { name: 'KubeDash' })).toBeNull()
    expect(await screen.findByRole('link', { name: 'GitHub' })).toBeTruthy()
    expect(screen.getByRole('link', { name: 'GitHub' }).getAttribute('href')).toBe(
      'https://github.com/devopstales/KubeDash',
    )
    expect(screen.queryByLabelText('Select cluster')).toBeNull()
    const namespace = await screen.findByLabelText('Select Namespace')
    await user.selectOptions(namespace, 'team-a')
    await user.click(screen.getByRole('button', { name: 'Submit' }))
    expect(useClusterStore.getState().selectedNamespace).toBe('team-a')
  })

  test('sidebar-omits-cluster-details-and-my-access', async () => {
    renderShell('admin')
    const permissions = await screen.findByText('Permissions')
    const users = await screen.findByText('User Management')
    expect(
      permissions.compareDocumentPosition(users) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy()
    expect(screen.queryByRole('link', { name: 'Cluster Details' })).toBeNull()
    expect(screen.queryByRole('link', { name: 'My access' })).toBeNull()
    expect(await screen.findByText('Settings')).toBeTruthy()
  })

  test('workload-entry-shows-beta-badge', async () => {
    const user = userEvent.setup()
    renderShell('user')
    await user.click(await screen.findByText('Dashboard'))
    expect(await screen.findByText('Beta')).toBeTruthy()
    expect(screen.getByRole('link', { name: /Cluster Metrics/ })).toBeTruthy()
    expect(screen.queryByText('Beta', { selector: 'a[href="/clusters"] *' })).toBeNull()
  })

  test('settings-is-in-the-sidebar', async () => {
    renderShell('user')
    expect(await screen.findByText('Settings')).toBeTruthy()
  })

  test('header-opens-the-kubeconfig-page', async () => {
    const user = userEvent.setup()
    renderShell('user')
    await user.click(await screen.findByAltText('Dev'))
    const link = await screen.findByRole('link', { name: 'Download KubeConfig' })
    expect(link.getAttribute('href')).toBe('/settings/export')
  })

  test('header-toggler-hides-sidebar', async () => {
    const user = userEvent.setup()
    renderShell('user')
    await screen.findByText('User Management')
    const sidebar = document.querySelector('.sidebar')
    expect(sidebar?.className).not.toContain('hide')
    await user.click(screen.getByRole('button', { name: 'Toggle sidebar' }))
    expect(document.querySelector('.sidebar')?.className).toContain('hide')
  })

  test('header-toggler-restores-sidebar', async () => {
    const user = userEvent.setup()
    renderShell('user')
    await screen.findByText('User Management')
    await user.click(screen.getByRole('button', { name: 'Toggle sidebar' }))
    await user.click(screen.getByRole('button', { name: 'Toggle sidebar' }))
    expect(document.querySelector('.sidebar')?.className).not.toContain('hide')
  })

  test('folding-the-sidebar-does-not-hide-it', async () => {
    const user = userEvent.setup()
    renderShell('user')
    await screen.findByText('User Management')
    await user.click(screen.getByRole('button', { name: 'Fold sidebar' }))
    const sidebar = document.querySelector('.sidebar')
    expect(sidebar?.className).not.toContain('hide')
    expect(sidebar?.className).toContain('sidebar-narrow-unfoldable')
  })
})
