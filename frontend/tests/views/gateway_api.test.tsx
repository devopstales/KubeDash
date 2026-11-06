import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import GatewayApiView from '../../src/views/Network/GatewayApi'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as priority_classes.test.tsx: renders the real row
// mapping (children-as-render-fns included) so cell assertions test the
// view's row mapping, not DataTables' DOM. The factory is async: a hoisted
// mock may not touch module-scope consts, so react is imported inline
// (`vi.mock` calls are hoisted above the imports below).
vi.mock('../../src/components/KubeDataTable', async () => {
  const React = (await import('react')) as typeof import('react')
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const cols = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map(
        (child) =>
          (
            child as React.ReactElement<{
              title: string
              data: string | null
              children?: unknown
            }>
          ).props,
      )
    return (
      <table>
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col.title}>{col.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i}>
              {cols.map((col) => {
                // `data={null}` hands the render fn the whole row (the
                // datatables.net-react contract, see Namespaces.tsx).
                const value = col.data === null ? row : row[col.data]
                const node =
                  typeof col.children === 'function'
                    ? (col.children as (v: unknown) => React.ReactNode)(value)
                    : (value as React.ReactNode)
                return <td key={col.title}>{node ?? ''}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

const renderAt = (ui: ReactElement) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/network/gateway-api']}>
        <Routes>
          <Route path="/network/gateway-api" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// FULL custom objects (camelCase — the CRD seam). ~3 days old so the Age
// column is a stable '3d'.
const envoyClass = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'GatewayClass',
  metadata: { name: 'envoy', creationTimestamp: new Date(Date.now() - 3 * 86400 * 1000).toISOString() },
  spec: { controllerName: 'envoyproxy.io/gatewayclass' },
}
const webGateway = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'Gateway',
  metadata: {
    name: 'web-gateway',
    namespace: 'team-a',
    creationTimestamp: '2026-10-26T10:00:00Z',
  },
  spec: {
    gatewayClassName: 'envoy',
    listeners: [{ name: 'web', protocol: 'HTTP', port: 8080 }],
  },
}
const webRoute = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'HTTPRoute',
  metadata: {
    name: 'web-route',
    namespace: 'team-a',
    creationTimestamp: '2026-10-26T10:00:00Z',
  },
  spec: {
    hostnames: ['a.example.com', 'b.example.com'],
    parentRefs: [{ name: 'web-gateway', namespace: 'team-a' }, { name: 'other' }],
  },
}
const allowGrant = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'ReferenceGrant',
  metadata: { name: 'allow', creationTimestamp: '2026-10-26T10:00:00Z' },
  spec: {
    from: [{ group: 'gateway.networking.k8s.io', kind: 'Gateway', namespace: 'team-a' }],
    to: [{ group: '', kind: 'Service' }],
  },
}

const fetchLog: { path: string; namespace: string | null }[] = []
const logFetch = (request: Request) => {
  const u = new URL(request.url)
  fetchLog.push({ path: u.pathname, namespace: u.searchParams.get('namespace') })
}

// gateway-api-renders-four-tabs
test('gateway-api-renders-four-tabs', async () => {
  fetchLog.length = 0
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', ({ request }) => {
      logFetch(request)
      return HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [envoyClass] })
    }),
    http.get('*/api/v1/clusters/1/resources/gateways', ({ request }) => {
      logFetch(request)
      return HttpResponse.json({ kind: 'gateways', cluster: 'prod', items: [webGateway] })
    }),
    http.get('*/api/v1/clusters/1/resources/httproutes', ({ request }) => {
      logFetch(request)
      return HttpResponse.json({ kind: 'httproutes', cluster: 'prod', items: [webRoute] })
    }),
    http.get('*/api/v1/clusters/1/resources/referencegrants', ({ request }) => {
      logFetch(request)
      return HttpResponse.json({ kind: 'referencegrants', cluster: 'prod', items: [allowGrant] })
    }),
  )
  selectProd()
  renderAt(<GatewayApiView />)

  // card title: EXACT string (the spec's pinned page title).
  expect(screen.getByRole('heading', { name: 'Gateway API' })).toBeTruthy()
  // breadcrumb: Network → Gateway API.
  expect(screen.getByText('Network')).toBeTruthy()
  // the four tabs (CoreUI CTab = button[role=tab]).
  expect(screen.getByRole('tab', { name: 'GatewayClasses' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Gateways' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'HTTPRoutes' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'ReferenceGrants' })).toBeTruthy()

  // all four tabs fetch on mount (CTabPanel keeps panels mounted). The
  // cluster-scoped tabs carry NO namespace; the namespaced tabs ride the
  // selected namespace.
  await screen.findByRole('button', { name: 'envoy' })
  const byPath = Object.fromEntries(fetchLog.map((e) => [e.path, e.namespace]))
  expect(byPath['/api/v1/clusters/1/resources/gatewayclasses']).toBeNull()
  expect(byPath['/api/v1/clusters/1/resources/gateways']).toBe('team-a')
  expect(byPath['/api/v1/clusters/1/resources/httproutes']).toBe('team-a')
  expect(byPath['/api/v1/clusters/1/resources/referencegrants']).toBeNull()

  // columns per tab (all four tables mounted; header order is the tab order).
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Controller',
    'Age',
    'Name',
    'GatewayClass',
    'Listeners',
    'Name',
    'Hostnames',
    'ParentRefs',
    'Name',
    'From',
    'To',
  ])

  // row values: the camelCase CRD field mappings.
  expect(screen.getByText('envoyproxy.io/gatewayclass')).toBeTruthy()
  expect(screen.getByText('3d')).toBeTruthy()
  // The Gateway row carries spec.gatewayClassName ('envoy') AND the
  // GatewayClasses tab's name button is 'envoy' — scope to the row.
  const gatewayRow = screen.getByRole('button', { name: 'web-gateway' }).closest('tr')
  expect(gatewayRow?.textContent).toBe('web-gatewayenvoyweb:HTTP:8080')
  expect(screen.getByText('a.example.com, b.example.com')).toBeTruthy()
  expect(screen.getByText('web-gateway/team-a, other')).toBeTruthy()
  // ReferenceGrant row: the group:kind summaries (the core group "" is
  // dropped — the 'Service' summary stands alone).
  expect(screen.getByText('gateway.networking.k8s.io:Gateway')).toBeTruthy()
  expect(screen.getByText('Service')).toBeTruthy()
})

// gateway-api-empty-tabs-pinned-copy
test('gateway-api-empty-tabs-pinned-copy', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/resources/gateways', () =>
      HttpResponse.json({ kind: 'gateways', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/resources/httproutes', () =>
      HttpResponse.json({ kind: 'httproutes', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/resources/referencegrants', () =>
      HttpResponse.json({ kind: 'referencegrants', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<GatewayApiView />)

  expect(await screen.findByText('No gateway classes found')).toBeTruthy()
  expect(screen.getByText('No gateways found')).toBeTruthy()
  expect(screen.getByText('No http routes found')).toBeTruthy()
  expect(screen.getByText('No reference grants found')).toBeTruthy()
  // no tables (every tab is in its empty state).
  expect(screen.queryAllByRole('columnheader')).toHaveLength(0)
})

// gateway-api-no-cluster-state
test('gateway-api-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<GatewayApiView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
