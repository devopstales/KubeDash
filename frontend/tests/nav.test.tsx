import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { useEffect, useMemo, useReducer, useRef } from 'react'
import { http, HttpResponse } from 'msw'
import { beforeEach, describe, expect, test } from 'vitest'
import { server } from './msw'
import { navigation, type NavItem } from '../src/_nav'
import { useClusterStore } from '../src/store/cluster'
import { useSidebarStore } from '../src/store/sidebar'
import AppHeader from '../src/components/AppHeader'
import AppSidebar from '../src/components/AppSidebar'
import { AppSidebarNav } from '../src/components/AppSidebarNav'
import NetworkPolicyView from '../src/views/Security/NetworkPolicy'
import NetworkPolicyDataView from '../src/views/Security/NetworkPolicyData'
import { registerNavigate } from '../src/components/ObjectRoute'
import { getActiveRef, readRegistry, setActiveRef, writeRegistry } from '../src/lib/objectRef'

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
  'Cert-Manager',
  'External Load Balancer',
  'Ingress Class',
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
  'Other Resources',
  'HPAs',
  'VPAs',
  'Pod Disruption Budget',
  'Resource Quota',
  'Limit Range',
  'Runtime Class',
  'Priority Classes',
  'Settings',
  'Auth Provider',
  'Kubernetes Cluster',
  'HA Status',
  'Audit Log',
]

// The 4.1 plugin-gated labels that 5.0 must NOT render (ADR-0022: the
// Plugins group is dropped; no 5.0 plugin system). 'Cert-Manager' +
// 'External Load Balancer' are legitimate Network leaves as of the
// 2026-10-29 certmanager-external-loadbalancer-views spec (promoted from
// the dropped Plugins group — the group itself stays banned). 'Gateway API'
// is banned again as of the 2026-11-07 menu merge: the kinds live as TABS of
// the Ingress / Ingress Class pages, not as a leaf (ADR-0022 amendment).
const banned = [
  'Plugins',
  'LoadBalancers',
  'Trivy Operator',
  'Applications',
  'Gateway API',
]

// Mirrors App.tsx's NetworkPolicyRoute dispatcher (ADR-0040 TICKET-03): the
// clean list route renders the list, or the ref-matched object detail.
const NavPolicyRoute = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const [, bump] = useReducer((c: number) => c + 1, 0)
  const ref = useMemo(() => getActiveRef(), [location, bump])
  const isPolicy =
    ref !== null &&
    (ref.kind === 'NetworkPolicy' ||
      ref.kind === 'CiliumNetworkPolicy' ||
      ref.kind === 'CiliumClusterwideNetworkPolicy')
  const seamRef = useRef(navigate)
  seamRef.current = navigate
  useEffect(() => {
    registerNavigate((path: string) => {
      seamRef.current(path)
      bump()
    })
  }, [])
  if (!isPolicy) return <NetworkPolicyView />
  return (
    <NetworkPolicyDataView name={ref!.name} kind={ref!.kind} namespace={ref!.namespace ?? ''} />
  )
}

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

  test('cluster-metrics-opens-dashboard', () => {
    // Retarget (2026-10-22): Cluster Metrics opens the cluster dashboard;
    // the Kubernetes Cluster entry (Settings) keeps the cluster list.
    const entries = flat(navigation({ clusterId: 7, isAdmin: true }))
    expect(entries.find((entry) => entry.name === 'Cluster Metrics')?.to).toBe(
      '/dashboard/cluster-metric',
    )
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

  // The full sidebar + header render with three authed fetches + userEvent
  // interactions — the default 5s is too tight under full-suite parallel
  // load (the test passes standalone but flakes in the 75-file run).
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
  }, 15000)

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
    // Scoped to the workload link: the Network group also carries Beta
    // leaves (Cert-Manager / External Load Balancer, 2026-10-29 spec), so a
    // bare text query would match more than one badge.
    expect(
      await screen.findByText('Beta', { selector: 'a[href="/dashboard/workload-map"] *' }),
    ).toBeTruthy()
    expect(screen.getByRole('link', { name: /Cluster Metrics/ })).toBeTruthy()
    expect(screen.queryByText('Beta', { selector: 'a[href="/clusters"] *' })).toBeNull()
  })

  test('nav-click-to-list-route-clears-open-ref-and-renders-list', async () => {
    // Regression (2026-11-05): a sidebar nav click must land on the target
    // list. The nav handler clears the open-object ref before the router
    // navigates; the clean list route then re-reads the (now-null) ref and
    // renders the list instead of re-rendering the open object detail.
    const denyAll = {
      apiVersion: 'networking.k8s.io/v1',
      kind: 'NetworkPolicy',
      metadata: {
        name: 'deny-all',
        namespace: 'team-a',
        creation_timestamp: '2026-10-26T10:00:00Z',
        labels: { app: 'web' },
      },
      spec: {
        pod_selector: { match_labels: { app: 'web' } },
        policy_types: ['Ingress', 'Egress'],
        ingress: [{ from: [] }],
        egress: [],
      },
    }
    server.use(
      http.get('*/api/v1/clusters/1/resources/networkpolicies', () =>
        HttpResponse.json({ kind: 'networkpolicies', cluster: 'prod', items: [denyAll] }),
      ),
      http.get('*/api/v1/clusters/1/resources/ciliumnetworkpolicies', () =>
        HttpResponse.json({ kind: 'ciliumnetworkpolicies', cluster: 'prod', items: [] }),
      ),
      http.get('*/api/v1/clusters/1/resources/ciliumclusterwidenetworkpolicies', () =>
        HttpResponse.json({ kind: 'ciliumclusterwidenetworkpolicies', cluster: 'prod', items: [] }),
      ),
    )
    const token = 'nav-list-clear-token'
    writeRegistry({
      [token]: {
        kind: 'NetworkPolicy',
        name: 'deny-all',
        namespace: 'team-a',
        ts: Date.now(),
        origin: 'click',
      },
    })
    setActiveRef(token)
    useClusterStore.setState({
      selectedCluster: { id: 1, name: 'prod' },
      selectedNamespace: 'team-a',
    })

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/security/network-policy']}>
          <AppSidebarNav items={navigation({ clusterId: 1, isAdmin: true })} />
          <Routes>
            <Route path="/security/network-policy" element={<NavPolicyRoute />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )

    expect(await screen.findByText('Network Policy Data', { selector: 'h5' })).toBeTruthy()
    const navLink = screen
      .getAllByRole('link', { name: 'Network Policies' })
      .find((l) => l.getAttribute('href') === '/security/network-policy')
    expect(navLink).toBeTruthy()
    await user.click(navLink!)
    expect(sessionStorage.getItem('kd_object_active')).toBeNull()
    expect(await screen.findByText('Network Policies', { selector: 'h5' })).toBeTruthy()
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
