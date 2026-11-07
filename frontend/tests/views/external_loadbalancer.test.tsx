import { useEffect, useMemo, useReducer, useRef } from 'react'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import type { HttpHandler } from 'msw'
import { server } from '../msw'
import { getActiveRef } from '../../src/lib/objectRef'
import { registerNavigate } from '../../src/components/ObjectRoute'
import ExternalLoadBalancerView from '../../src/views/Network/ExternalLoadBalancer'
import ExternalLoadBalancerDataView from '../../src/views/Network/ExternalLoadBalancerData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// Mirrors App.tsx's ExternalLoadBalancerRoute dispatcher (the test does not
// import the whole app): the clean list route renders the 4-tab list, or the
// ref-matched object detail for the four external-LB kinds.
const ExlbTestRoute = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [, bump] = useReducer((c: number) => c + 1, 0)
  const ref = useMemo(() => getActiveRef(), [location, bump])
  const isKind =
    ref !== null &&
    (ref.kind === 'ipaddresspool' ||
      ref.kind === 'l2advertisement' ||
      ref.kind === 'bgppeers' ||
      ref.kind === 'bgpadvertisement')
  const seamRef = useRef(navigate)
  seamRef.current = navigate
  useEffect(() => {
    registerNavigate((path: string) => {
      seamRef.current(path)
      bump()
    })
  }, [])
  if (!isKind) return <ExternalLoadBalancerView />
  return (
    <ExternalLoadBalancerDataView name={ref!.name} kind={ref!.kind} namespace={ref!.namespace ?? ''} />
  )
}

// ADR-0040: render through the dispatcher route so the detail is ref-driven
// (name + kind + namespace from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/network/external-loadbalancer') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/network/external-loadbalancer" element={<ExlbTestRoute />} />
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

// The detected-provider fixtures: each item carries the backend's `provider`
// tag (the view's Type column). MetalLB-primary and Cilium-fallback shapes.
const metalLbPool = {
  metadata: { name: 'pool-a', creation_timestamp: '2026-01-01T00:00:00Z' },
  provider: 'metallb',
  spec: { addresses: ['192.168.10.0/24'], autoAssign: true },
}
const ciliumPool = {
  metadata: { name: 'pool-b', creation_timestamp: '2026-01-02T00:00:00Z' },
  provider: 'cilium',
  spec: { cidrs: ['10.96.0.0/16'] },
}

const metalLbL2 = {
  metadata: { name: 'l2-a', creation_timestamp: '2026-01-03T00:00:00Z' },
  provider: 'metallb',
  spec: { ipAddressPools: ['pool-a'] },
}
const ciliumL2 = {
  metadata: { name: 'l2-b', creation_timestamp: '2026-01-04T00:00:00Z' },
  provider: 'cilium',
  spec: { serviceSelector: { matchLabels: { app: 'web' } } },
}

const metalLbPeer = {
  metadata: { name: 'peer-a', creation_timestamp: '2026-01-05T00:00:00Z' },
  provider: 'metallb',
  spec: { peerAddress: '10.0.0.99', myASN: 65001, peerASN: 65002 },
}
// The list cell renders the FIRST neighbor's peerAddress (the single-
// identity list contract).
const ciliumPeer = {
  metadata: { name: 'peer-b', creation_timestamp: '2026-01-06T00:00:00Z' },
  provider: 'cilium',
  spec: {
    virtualRouters: [
      {
        localASN: 64512,
        neighbors: [{ peerAddress: '10.0.0.50', peerASN: 64500 }, { peerAddress: '10.0.0.51', peerASN: 64501 }],
      },
    ],
  },
}

const bgpAdv = {
  metadata: { name: 'adv-a', creation_timestamp: '2026-01-07T00:00:00Z' },
  provider: 'metallb',
  spec: { ipAddressPools: ['pool-a'], peers: ['peer-a'], aggregationLength: 24 },
}

// One handler per the four registry resources; records every request's
// namespace param (all four ride the selected namespace — the backend's
// provider detection decides namespaced-vs-cluster reads server-side).
const serve = (items: Record<string, unknown[]>) => {
  const requests: { resource: string; name: string | null; namespace: string | null }[] = []
  const handlers: HttpHandler[] = Object.entries(items).map(([resource, list]) =>
    http.get(`*/api/v1/clusters/1/resources/${resource}`, ({ request }) => {
      const u = new URL(request.url)
      requests.push({
        resource,
        name: u.searchParams.get('name'),
        namespace: u.searchParams.get('namespace'),
      })
      return HttpResponse.json({ kind: resource, items: list })
    }),
  )
  return { requests, handlers }
}

const allItems = () => ({
  ipaddresspools: [metalLbPool, ciliumPool],
  l2advertisements: [metalLbL2, ciliumL2],
  bgppeers: [metalLbPeer, ciliumPeer],
  bgpadvertisements: [bgpAdv],
})

// list-renders-4tabs: the card title is EXACTLY "LoadBalancer Objects"; the
// four 4.1 tabs (IP Address Pools / L2 Advertisements / BGP Peers / BGP
// Advertisements); ALL four fetch on mount (CTabPanel keeps every panel
// mounted); every fetch carries the selected namespace.
test('list-renders-4tabs', async () => {
  const { requests, handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<ExternalLoadBalancerView />)

  expect(screen.getAllByText('LoadBalancer Objects')).toHaveLength(2)
  expect(screen.getByText('Network')).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'IP Address Pools' })).toHaveAttribute('aria-selected', 'true')
  expect(screen.getByRole('tab', { name: 'L2 Advertisements' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'BGP Peers' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'BGP Advertisements' })).toBeTruthy()

  await screen.findByRole('button', { name: 'pool-a' })
  const byResource = new Map(requests.map((r) => [r.resource, r.namespace]))
  expect(byResource.get('ipaddresspools')).toBe('team-a')
  expect(byResource.get('l2advertisements')).toBe('team-a')
  expect(byResource.get('bgppeers')).toBe('team-a')
  expect(byResource.get('bgpadvertisements')).toBe('team-a')
})

// list-type-column: the Type cell renders the detected `provider` tag
// (metallb / cilium — the certified 5.0 deviation: 4.1 hardcoded the type).
test('list-type-column', async () => {
  const { handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<ExternalLoadBalancerView />)

  const poolARow = (await screen.findByRole('button', { name: 'pool-a' })).closest('tr')!
  expect(within(poolARow).getByText('metallb')).toBeTruthy()
  const poolBRow = screen.getByRole('button', { name: 'pool-b' }).closest('tr')!
  expect(within(poolBRow).getByText('cilium')).toBeTruthy()
})

// list-kind-specific-columns: the provider-specific field per tab —
// IP Address Pools: Addresses (MetalLB spec.addresses / Cilium spec.cidrs);
// L2 Advertisements: Pools (MetalLB spec.ipAddressPools / Cilium
// spec.serviceSelector); BGP Peers: Peer (MetalLB spec.peerAddress / Cilium
// the first virtualRouters[].neighbors[].peerAddress).
test('list-kind-specific-columns', async () => {
  const { handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<ExternalLoadBalancerView />)

  // IP Address Pools (the default tab).
  const poolARow = (await screen.findByRole('button', { name: 'pool-a' })).closest('tr')!
  expect(within(poolARow).getByText('192.168.10.0/24')).toBeTruthy()
  const poolBRow = screen.getByRole('button', { name: 'pool-b' }).closest('tr')!
  expect(within(poolBRow).getByText('10.96.0.0/16')).toBeTruthy()

  // L2 Advertisements.
  const l2ARow = screen.getByRole('button', { name: 'l2-a' }).closest('tr')!
  expect(within(l2ARow).getByText('pool-a')).toBeTruthy()
  const l2BRow = screen.getByRole('button', { name: 'l2-b' }).closest('tr')!
  expect(within(l2BRow).getByText('app=web')).toBeTruthy()

  // BGP Peers.
  const peerARow = screen.getByRole('button', { name: 'peer-a' }).closest('tr')!
  expect(within(peerARow).getByText('10.0.0.99')).toBeTruthy()
  const peerBRow = screen.getByRole('button', { name: 'peer-b' }).closest('tr')!
  expect(within(peerBRow).getByText('10.0.0.50')).toBeTruthy()

  // BGP Advertisements: the pool references.
  const advRow = screen.getByRole('button', { name: 'adv-a' }).closest('tr')!
  expect(within(advRow).getByText('pool-a')).toBeTruthy()
})

// list-name-links: the Name cell is an openObject button (ADR-0040) —
// clicking opens the per-type data detail on the CLEAN route; the detail
// fetches the single object by ?name= + ?namespace=.
test('list-name-links', async () => {
  const user = userEvent.setup()
  const { requests, handlers } = serve(allItems())
  server.use(...handlers)
  selectTeamA()
  renderAt(<ExternalLoadBalancerView />)

  await user.click(await screen.findByRole('button', { name: 'pool-a' }))

  // The per-type data card title (the 4.1 shape: `<type> Objects`).
  expect(await screen.findByText('ipaddresspool Objects')).toBeTruthy()
  expect(window.location.search).toBe('')
  expect(
    requests.some(
      (r) => r.resource === 'ipaddresspools' && r.name === 'pool-a' && r.namespace === 'team-a',
    ),
  ).toBe(true)
})

// list-no-cluster-state: no cluster selected — no external-LB fetch at all.
test('list-no-cluster-state', async () => {
  const { requests, handlers } = serve(allItems())
  server.use(...handlers)
  renderAt(<ExternalLoadBalancerView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(requests).toHaveLength(0)
})

// list-empty-tabs: every empty tab renders its pinned first-class empty
// state (both-providers-absent is the same shape — the seam returns []).
test('list-empty-tabs', async () => {
  const { handlers } = serve({
    ipaddresspools: [],
    l2advertisements: [],
    bgppeers: [],
    bgpadvertisements: [],
  })
  server.use(...handlers)
  selectTeamA()
  renderAt(<ExternalLoadBalancerView />)

  expect(await screen.findByText('No IP address pools found')).toBeTruthy()
  expect(screen.getByText('No L2 advertisements found')).toBeTruthy()
  expect(screen.getByText('No BGP peers found')).toBeTruthy()
  expect(screen.getByText('No BGP advertisements found')).toBeTruthy()
})

// list-error-state: an API error renders the red error line with the pinned
// prefix.
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ipaddresspools', () =>
      HttpResponse.json({ error: { code: 'InternalError', message: 'boom' } }, { status: 500 }),
    ),
    ...serve({
      l2advertisements: [metalLbL2, ciliumL2],
      bgppeers: [metalLbPeer, ciliumPeer],
      bgpadvertisements: [bgpAdv],
    }).handlers,
  )
  selectTeamA()
  renderAt(<ExternalLoadBalancerView />)

  expect(
    await screen.findByText('Error loading load-balancer objects: InternalError: boom'),
  ).toBeTruthy()
})
