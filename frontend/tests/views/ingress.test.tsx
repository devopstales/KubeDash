import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import IngressView from '../../src/views/Network/Ingress'
import IngressDataView from '../../src/views/Network/IngressData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/network/ingress') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/network/ingress"
            element={
              <ObjectRoute
                kind="ingress"
                listRoute="/network/ingress"
                list={<IngressView />}
                detail={(p) => <IngressDataView name={p.name} namespace={p.namespace ?? ''} />}
              />
            }
          />
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

// kubernetes to_dict shape: snake_case. Namespaced.
const webIngress = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'Ingress',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-10-26T10:00:00Z',
  },
  spec: {
    ingress_class_name: 'nginx',
    tls: [{ secret_name: 'web-tls' }],
    rules: [
      {
        host: 'web.example.com',
        http: {
          paths: [
            {
              path: '/',
              path_type: 'Prefix',
              backend: { service: { name: 'web', port: { number: 80 } } },
            },
          ],
        },
      },
      {
        host: 'www.example.com',
        http: {
          paths: [
            {
              path: '/api',
              path_type: 'Prefix',
              backend: { service: { name: 'api', port: { name: 'http' } } },
            },
          ],
        },
      },
    ],
  },
}

// no ingress_class_name, no rule host — the "—" certainty cells.
const plainIngress = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'Ingress',
  metadata: { name: 'plain', namespace: 'team-a', creation_timestamp: '2026-10-26T10:00:00Z' },
  spec: {
    rules: [
      {
        http: {
          paths: [{ path: '/', path_type: 'Prefix', backend: { service: { name: 'plain' } } }],
        },
      },
    ],
  },
}

// FULL custom objects (camelCase — the CRD seam), ported from the
// 2026-10-28 gateway-api page tests (2026-11-07 menu merge). ~3 days old
// so the Age column is a stable '3d'.
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

// The tabbed page mounts EVERY panel (CTabPanel), so every test that
// renders the page also serves the three gateway-kind endpoints — without
// handlers those fetches fall through to onUnhandledRequest bypass and
// the tabs would sit in error state.
const gatewayTabHandlers = (
  gateways: unknown[] = [],
  httpRoutes: unknown[] = [],
  referenceGrants: unknown[] = [],
) => [
  http.get('*/api/v1/clusters/1/resources/gateways', () =>
    HttpResponse.json({ kind: 'gateways', cluster: 'prod', items: gateways }),
  ),
  http.get('*/api/v1/clusters/1/resources/httproutes', () =>
    HttpResponse.json({ kind: 'httproutes', cluster: 'prod', items: httpRoutes }),
  ),
  http.get('*/api/v1/clusters/1/resources/referencegrants', () =>
    HttpResponse.json({ kind: 'referencegrants', cluster: 'prod', items: referenceGrants }),
  ),
]

// The merged page's column set, in tab order (CTabPanel mounts all four,
// so the DOM order is the tab order).
const MERGED_COLUMNS = [
  'Name',
  'IngressClass',
  'Hostname',
  'Name',
  'GatewayClass',
  'Listeners',
  'Name',
  'Hostnames',
  'ParentRefs',
  'Name',
  'From',
  'To',
]

// list-renders-ingresses
test('list-renders-ingresses', async () => {
  let requestedPath = ''
  let namespaceParam: string | null = null
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      namespaceParam = u.searchParams.get('namespace')
      return HttpResponse.json({
        kind: 'ingresses',
        cluster: 'prod',
        items: [webIngress, plainIngress],
      })
    }),
    ...gatewayTabHandlers(),
  )
  selectProd()
  renderAt(<IngressView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'web' })
  // fetch path is EXACTLY the namespaced kind URL (the selected namespace).
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/ingresses')
  expect(namespaceParam).toBe('team-a')

  // card title: EXACT string (the spec's pinned title — 4.1's "Ingress
  // Resources" is not replicated). Pinned on the heading: the breadcrumb
  // renders the same text.
  expect(screen.getByRole('heading', { name: 'Ingress List' })).toBeTruthy()
  // breadcrumb: Network → Ingress List.
  expect(screen.getByText('Network')).toBeTruthy()
  // columns: name, ingressclass, hostname. The other three tabs are EMPTY
  // here (gatewayTabHandlers default), so their tables don't render — only
  // the Ingresses tab's table is in the DOM. The full merged column set is
  // asserted in list-renders-gateway-tabs (all four tabs with data).
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'IngressClass',
    'Hostname',
  ])
  // row: ingress_class_name + spec.rules[].host joined ", ".
  expect(screen.getByText('nginx')).toBeTruthy()
  expect(screen.getByText('web.example.com, www.example.com')).toBeTruthy()
  // the hostless / classless row renders the "—" certainty cells.
  const plainRow = screen.getByRole('button', { name: 'plain' }).closest('tr')
  expect(plainRow?.textContent).toBe('plain——')
})

// list-renders-gateway-tabs (ported from gateway-api-renders-four-tabs,
// 2026-11-07 menu merge): the three Gateway API kinds are tabs of this
// page; the gateway-kind query keys keep the 'gateway-api' prefix (the
// converter's invalidation seam).
test('list-renders-gateway-tabs', async () => {
  const fetchLog: { path: string; namespace: string | null }[] = []
  const logFetch = (request: Request) => {
    const u = new URL(request.url)
    fetchLog.push({ path: u.pathname, namespace: u.searchParams.get('namespace') })
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', ({ request }) => {
      logFetch(request)
      return HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [webIngress] })
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
  renderAt(<IngressView />)

  // the four tabs (CoreUI CTab = button[role=tab]); the Ingresses tab is
  // the default active one.
  expect(screen.getByRole('tab', { name: 'Ingresses' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Gateways' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'HTTPRoutes' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'ReferenceGrants' })).toBeTruthy()
  expect(screen.getByRole('heading', { name: 'Ingress List' })).toBeTruthy()

  // all four fetch on mount (CTabPanel keeps panels mounted). The
  // namespaced kinds ride the selected namespace; the cluster-scoped
  // ReferenceGrants tab carries NO namespace.
  await screen.findByRole('button', { name: 'web-gateway' })
  const byPath = Object.fromEntries(fetchLog.map((e) => [e.path, e.namespace]))
  expect(byPath['/api/v1/clusters/1/resources/ingresses']).toBe('team-a')
  expect(byPath['/api/v1/clusters/1/resources/gateways']).toBe('team-a')
  expect(byPath['/api/v1/clusters/1/resources/httproutes']).toBe('team-a')
  expect(byPath['/api/v1/clusters/1/resources/referencegrants']).toBeNull()

  // columns per tab (all four tables mounted; header order is the tab
  // order).
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual(MERGED_COLUMNS)

  // row values: the camelCase CRD field mappings.
  // The Gateway row carries spec.gatewayClassName ('envoy') — scope to the
  // row (the Ingresses tab may render an 'nginx' cell of its own).
  const gatewayRow = screen.getByRole('button', { name: 'web-gateway' }).closest('tr')
  expect(gatewayRow?.textContent).toBe('web-gatewayenvoyweb:HTTP:8080')
  expect(screen.getByText('a.example.com, b.example.com')).toBeTruthy()
  expect(screen.getByText('web-gateway/team-a, other')).toBeTruthy()
  // ReferenceGrant row: the group:kind summaries (the core group "" is
  // dropped — the 'Service' summary stands alone).
  expect(screen.getByText('gateway.networking.k8s.io:Gateway')).toBeTruthy()
  expect(screen.getByText('Service')).toBeTruthy()
})

// list-empty-all-tabs (ported from gateway-api-empty-tabs-pinned-copy):
// every tab in its pinned empty state, no tables.
test('list-empty-all-tabs', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [] }),
    ),
    ...gatewayTabHandlers(),
  )
  selectProd()
  renderAt(<IngressView />)

  expect(await screen.findByText('No ingresses found')).toBeTruthy()
  expect(screen.getByText('No gateways found')).toBeTruthy()
  expect(screen.getByText('No http routes found')).toBeTruthy()
  expect(screen.getByText('No reference grants found')).toBeTruthy()
  // no tables (every tab is in its empty state).
  expect(screen.queryAllByRole('columnheader')).toHaveLength(0)
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [webIngress] }),
    ),
    ...gatewayTabHandlers(),
  )
  renderAt(<IngressView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1). The ref carries the namespace (R8).
  const nameButton = await screen.findByRole('button', { name: 'web' })
  await user.click(nameButton)

  expect(await screen.findByText('Ingress Data')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// list-no-cluster-state
test('list-no-cluster-state', async () => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  renderAt(<IngressView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on ingresses' } },
        { status: 403 },
      ),
    ),
    ...gatewayTabHandlers(),
  )
  selectProd()
  renderAt(<IngressView />)

  expect(
    await screen.findByText(/Error loading ingresses: RBAC_DENIED: list on ingresses/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'web' })).toHaveLength(0)
})

// list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [] }),
    ),
    ...gatewayTabHandlers(),
  )
  selectProd()
  renderAt(<IngressView />)

  expect(await screen.findByText('No ingresses found')).toBeTruthy()
})
