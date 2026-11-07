import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ServiceView from '../../src/views/Network/Service'
import ServiceDataView from '../../src/views/Network/ServiceData'
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
const renderAt = (_ui: ReactElement, path = '/network/service') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/network/service"
            element={
              <ObjectRoute
                kind="service"
                listRoute="/network/service"
                list={<ServiceView />}
                detail={(p) => <ServiceDataView name={p.name} namespace={p.namespace ?? ''} />}
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

const selectTeamA = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// kubernetes to_dict shape: snake_case. Namespaced. spec/status NOT stripped.
const webSvc = {
  metadata: {
    name: 'web-svc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    resource_version: '4242',
    labels: { app: 'web' },
  },
  spec: {
    type: 'ClusterIP',
    cluster_ip: '10.0.0.1',
    selector: { app: 'web' },
    ports: [{ name: 'http', port: 80, target_port: 8080, protocol: 'TCP' }],
  },
}

// LoadBalancer with an ingress — the External IP cell renders the ip.
const lbSvc = {
  metadata: { name: 'lb-svc', namespace: 'team-a', creation_timestamp: '2026-01-03T00:00:00Z' },
  spec: { type: 'LoadBalancer', cluster_ip: '10.0.0.2', selector: { app: 'lb' } },
  status: { load_balancer: { ingress: [{ ip: '203.0.113.9' }] } },
}

// LoadBalancer with NO ingress yet (pending) — 4.1's deep index 500s here;
// 5.0 renders "—" (the certified 500 fix).
const pendingLbSvc = {
  metadata: {
    name: 'pending-lb-svc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-04T00:00:00Z',
  },
  spec: { type: 'LoadBalancer', selector: { app: 'pending' } },
}

// list-renders-rows-with-data-links: the fetch is for the header-selected
// namespace; the name cells are openObject buttons (ADR-0040) — clicking
// opens the data detail on the CLEAN route (the 5.0 form of 4.1's
// /data?name=&namespace= link).
test('list-renders-rows-with-data-links', async () => {
  const user = userEvent.setup()
  let requestedNamespace = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/services', ({ request }) => {
      requestedNamespace = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'services', items: [webSvc, lbSvc] })
    }),
  )
  selectTeamA()
  renderAt(<ServiceView />)

  await screen.findByRole('button', { name: 'web-svc' })
  expect(requestedNamespace).toBe('team-a')
  // The card title + breadcrumb stay EXACTLY "Service List" (the e2e-smoke
  // contract) — both occurrences exact.
  expect(screen.getAllByText('Service List')).toHaveLength(2)
  // The breadcrumb names the Network group.
  expect(screen.getByText('Network')).toBeTruthy()
  // The 4.1 column set, in order.
  const headers = screen.getAllByRole('columnheader').map((h) => h.textContent)
  expect(headers).toEqual(['Name', 'Type', 'Cluster IP', 'External IP'])

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'web-svc' })
  await user.click(nameButton)
  expect(await screen.findByText('Service Data')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// list-external-ip-cell: LoadBalancer renders status.load_balancer.ingress[0].ip;
// non-LoadBalancer renders "—"; a pending LoadBalancer (no ingress) renders
// "—" (the 4.1 deep-index 500 fix).
test('list-external-ip-cell', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/services', () =>
      HttpResponse.json({ kind: 'services', items: [webSvc, lbSvc, pendingLbSvc] }),
    ),
  )
  selectTeamA()
  renderAt(<ServiceView />)

  // Row scoping through the name button's <tr> (the a11y tree exposes no
  // row name from cell contents).
  const lbRow = (await screen.findByRole('button', { name: 'lb-svc' })).closest('tr')!
  expect(within(lbRow).getByText('203.0.113.9')).toBeTruthy()

  const webRow = screen.getByRole('button', { name: 'web-svc' }).closest('tr')!
  expect(within(webRow).getByText('—')).toBeTruthy()

  const pendingRow = screen.getByRole('button', { name: 'pending-lb-svc' }).closest('tr')!
  // Two "—" cells: no cluster_ip AND no ingress (the pending LB).
  expect(within(pendingRow).getAllByText('—')).toHaveLength(2)
})

// list-no-cluster-state: no cluster selected — no resource fetch at all.
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  renderAt(<ServiceView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0)
})

// list-empty-state: an empty namespace renders the pinned first-class empty
// state (NOT an error).
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/services', () =>
      HttpResponse.json({ kind: 'services', items: [] }),
    ),
  )
  selectTeamA()
  renderAt(<ServiceView />)

  expect(await screen.findByText('No services found')).toBeTruthy()
})

// list-error-state: an API error renders the red error line.
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/services', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'cannot list services' } },
        { status: 403 },
      ),
    ),
  )
  selectTeamA()
  renderAt(<ServiceView />)

  expect(await screen.findByText('Error loading services: RBAC_DENIED: cannot list services')).toBeTruthy()
})
