import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ExternalLoadBalancerDataView from '../../src/views/Network/ExternalLoadBalancerData'
import { useClusterStore } from '../../src/store/cluster'

// Render the data view directly (no dispatcher) for view-level state
// assertions; the dispatcher and the legacy /data redirect both feed it the
// same props (kind + name + namespace).
const renderDataAt = (kind: string, name: string, namespace = 'team-a') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/network/external-loadbalancer/data']}>
        <ExternalLoadBalancerDataView name={name} kind={kind} namespace={namespace} />
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
    selectedNamespace: 'default',
  })

// Row scoping for the metadata CTable: the a11y tree exposes no row name
// from cell contents, so scope through the th label's closest <tr>.
const row = (label: string) => within(screen.getByText(`${label}:`).closest('tr') as HTMLElement)

// The detected-provider fixtures: each item carries the backend's `provider`
// tag (the row set + the Type row are keyed by it).
const metalLbPool = {
  metadata: { name: 'pool-a', creation_timestamp: '2026-01-01T00:00:00Z' },
  provider: 'metallb',
  spec: {
    addresses: ['192.168.10.0/24', '192.168.11.0/24'],
    autoAssign: true,
    serviceAllocation: { namespaces: ['team-a'] },
  },
}

const ciliumPool = {
  metadata: { name: 'pool-b', creation_timestamp: '2026-01-02T00:00:00Z' },
  provider: 'cilium',
  spec: { cidrs: ['10.96.0.0/16'], allowFirstLastIPs: true, ipFamilyPolicy: 'SingleStack' },
}

const ciliumL2 = {
  metadata: { name: 'l2-b', creation_timestamp: '2026-01-04T00:00:00Z' },
  provider: 'cilium',
  spec: {
    serviceSelector: { matchLabels: { app: 'web' } },
    nodeSelector: { matchLabels: { role: 'lb' } },
    interfaces: ['eth0'],
  },
}

const metalLbPeer = {
  metadata: { name: 'peer-a', creation_timestamp: '2026-01-05T00:00:00Z' },
  provider: 'metallb',
  spec: { peerAddress: '10.0.0.99', myASN: 65001, peerASN: 65002 },
}

const ciliumPeer = {
  metadata: { name: 'peer-b', creation_timestamp: '2026-01-06T00:00:00Z' },
  provider: 'cilium',
  spec: {
    virtualRouters: [
      {
        localASN: 64512,
        exportPodCIDR: false,
        neighbors: [{ peerAddress: '10.0.0.50', peerASN: 64500 }],
      },
    ],
  },
}

const bgpAdv = {
  metadata: { name: 'adv-a', creation_timestamp: '2026-01-07T00:00:00Z' },
  provider: 'metallb',
  spec: { aggregationLength: 24, communities: ['65000:100'], ipAddressPools: ['pool-a'], peers: ['peer-a'] },
}

const serveOne = (resource: string, item: unknown, track?: (u: URL) => void) =>
  http.get(`*/api/v1/clusters/1/resources/${resource}`, ({ request }) => {
    const u = new URL(request.url)
    track?.(u)
    return HttpResponse.json({ kind: resource, items: item ? [item] : [] })
  })

// data-ipaddresspool-metallb-rows: the MetalLB row set (Addresses / Auto
// assign / ...); the Type row renders the provider; the fetch carries
// ?name= + ?namespace= (all four external-LB kinds ride the namespace —
// the provider detection picks the read server-side).
test('data-ipaddresspool-metallb-rows', async () => {
  const seen: URL[] = []
  server.use(serveOne('ipaddresspools', metalLbPool, (u) => seen.push(u)))
  selectTeamA()
  renderDataAt('ipaddresspool', 'pool-a')

  expect(await screen.findByText('ipaddresspool Objects')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(seen).toHaveLength(1)
  expect(seen[0].searchParams.get('name')).toBe('pool-a')
  expect(seen[0].searchParams.get('namespace')).toBe('team-a')

  expect(row('Name').getByText('pool-a')).toBeTruthy()
  expect(row('Type').getByText('metallb')).toBeTruthy()
  expect(
    row('Addresses').getByText('192.168.10.0/24, 192.168.11.0/24'),
  ).toBeTruthy()
  expect(row('Auto assign').getByText('true')).toBeTruthy()
  // Absent fields render "—" (the certainty rule).
  expect(row('Avoid buggy IPs').getByText('—')).toBeTruthy()
  expect(
    row('Allocation Namespaces').getByText('team-a'),
  ).toBeTruthy()
  // The full-object JSON block.
  expect(document.body.textContent).toContain('"provider": "metallb"')
})

// data-ipaddresspool-cilium-rows: the Cilium row set (Blocks / Allow First
// Last IPs / ...) — NO Addresses row (the provider selects the row set).
test('data-ipaddresspool-cilium-rows', async () => {
  server.use(serveOne('ipaddresspools', ciliumPool))
  selectTeamA()
  renderDataAt('ipaddresspool', 'pool-b')

  expect(await screen.findByText('ipaddresspool Objects')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(row('Type').getByText('cilium')).toBeTruthy()
  expect(row('Blocks').getByText('10.96.0.0/16')).toBeTruthy()
  expect(row('Allow First Last IPs').getByText('true')).toBeTruthy()
  expect(
    row('IP Family Policy').getByText('SingleStack'),
  ).toBeTruthy()
  // The MetalLB-only row is absent for the Cilium provider.
  expect(screen.queryByText('Addresses:')).toBeNull()
})

// data-l2advertisement-cilium-rows: the Cilium L2 row set (Service Selector
// rendered from the LabelSelector, one selector compactly).
test('data-l2advertisement-cilium-rows', async () => {
  server.use(serveOne('l2advertisements', ciliumL2))
  selectTeamA()
  renderDataAt('l2advertisement', 'l2-b')

  expect(await screen.findByText('l2advertisement Objects')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(row('Service Selector').getByText('app=web')).toBeTruthy()
  expect(row('Node Selector').getByText('role=lb')).toBeTruthy()
  expect(row('Interfaces').getByText('eth0')).toBeTruthy()
})

// data-bgppeers-metallb-rows: the MetalLB BGP Peer row set (My ASN / Peer
// Address / Peer ASN — the numeric fields rendered as text).
test('data-bgppeers-metallb-rows', async () => {
  server.use(serveOne('bgppeers', metalLbPeer))
  selectTeamA()
  renderDataAt('bgppeers', 'peer-a')

  expect(await screen.findByText('bgppeers Objects')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(row('My ASN').getByText('65001')).toBeTruthy()
  expect(row('Peer Address').getByText('10.0.0.99')).toBeTruthy()
  expect(row('Peer ASN').getByText('65002')).toBeTruthy()
  // Absent fields render "—".
  expect(row('Source Address').getByText('—')).toBeTruthy()
})

// data-bgppeers-cilium-rows: the Cilium BGP Peer row set — the
// virtualRouters render (localASN / exportPodCIDR / neighbors with
// peerAddress / peerASN).
test('data-bgppeers-cilium-rows', async () => {
  server.use(serveOne('bgppeers', ciliumPeer))
  selectTeamA()
  renderDataAt('bgppeers', 'peer-b')

  expect(await screen.findByText('bgppeers Objects')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(row('Virtual Routers').getByText(
    'localASN: 64512, exportPodCIDR: false, neighbors: 10.0.0.50(64500)',
  )).toBeTruthy()
  // The MetalLB-only rows are absent for the Cilium provider.
  expect(screen.queryByText('My ASN:')).toBeNull()
})

// data-bgpadvertisement-rows: the BGP Advertisement row set (MetalLB-only
// kind — the row set does not branch on provider).
test('data-bgpadvertisement-rows', async () => {
  server.use(serveOne('bgpadvertisements', bgpAdv))
  selectTeamA()
  renderDataAt('bgpadvertisement', 'adv-a')

  expect(await screen.findByText('bgpadvertisement Objects')).toBeTruthy()
  await screen.findByText('Name:') // the table renders once the query settles
  expect(row('Aggregation Length').getByText('24')).toBeTruthy()
  expect(row('Communities').getByText('65000:100')).toBeTruthy()
  expect(row('IP Address Pools').getByText('pool-a')).toBeTruthy()
  expect(row('Peers').getByText('peer-a')).toBeTruthy()
})

// data-not-found-state: a ?name= miss (items: []) is the pinned muted state
// (never an error style; the both-providers-absent state is the same shape).
test('data-not-found-state', async () => {
  server.use(serveOne('ipaddresspools', null))
  selectTeamA()
  renderDataAt('ipaddresspool', 'ghost')

  const notFound = await screen.findByText("No ipaddresspool 'ghost' found")
  expect(notFound.className).toContain('text-muted')
  expect(screen.queryByText(/Error/)).toBeNull()
})

// data-missing-name: no name -> the pinned error line (red), no fetch.
test('data-missing-name', async () => {
  let calls = 0
  server.use(
    http.get('*/api/v1/clusters/1/resources/bgppeers', () => {
      calls += 1
      return HttpResponse.json({ kind: 'bgppeers', items: [] })
    }),
  )
  selectTeamA()
  renderDataAt('bgppeers', '')

  const el = await screen.findByText('Error: bgppeers name not provided')
  expect(el.className).toContain('text-danger')
  expect(calls).toBe(0)
})

// data-unknown-kind: a kind outside the closed set renders the error line
// with NO network hit (the query is disabled before the fetch).
test('data-unknown-kind', async () => {
  let calls = 0
  server.use(
    http.get('*/api/v1/clusters/1/resources/*', () => {
      calls += 1
      return HttpResponse.json({ items: [] })
    }),
  )
  selectTeamA()
  renderDataAt('nonsense', 'x')

  const el = await screen.findByText('Error: unknown external load balancer kind: nonsense')
  expect(el.className).toContain('text-danger')
  expect(calls).toBe(0)
})

// data-error-state: an API error renders the red error line (the pinned
// prefix + the API error).
test('data-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ipaddresspools', () =>
      HttpResponse.json(
        { error: { code: 'InternalError', message: 'boom' } },
        { status: 500 },
      ),
    ),
  )
  selectTeamA()
  renderDataAt('ipaddresspool', 'pool-a')

  const el = await screen.findByText('Error loading ip address pool: InternalError: boom')
  expect(el.className).toContain('text-danger')
})
