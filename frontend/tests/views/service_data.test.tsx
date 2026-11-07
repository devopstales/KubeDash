import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ServiceDataView from '../../src/views/Network/ServiceData'
import { useClusterStore } from '../../src/store/cluster'

// Render the data view directly (no ObjectRoute) for view-level state
// assertions; the ObjectRoute detail and the legacy /data redirect both feed
// it the same props.
const renderDataAt = (name: string, namespace: string) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/network/service/data']}>
        <ServiceDataView name={name} namespace={namespace} />
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

// kubernetes to_dict shape: snake_case. The data page reads spec.ports,
// spec.selector, and status.load_balancer off the FULL object (NOT stripped).
const webSvc = {
  metadata: {
    name: 'web-svc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    resource_version: '4242',
    labels: { app: 'web' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"Service"}',
      owner: 'platform',
    },
  },
  spec: {
    type: 'ClusterIP',
    cluster_ip: '10.0.0.1',
    selector: { app: 'web' },
    ports: [{ name: 'http', port: 80, target_port: 8080, protocol: 'TCP' }],
  },
}

// No spec.ports — the Ports tab renders "No ports".
const noPortSvc = {
  metadata: { name: 'noport-svc', namespace: 'team-a', creation_timestamp: '2026-01-05T00:00:00Z' },
  spec: { type: 'ClusterIP', selector: { app: 'nop' } },
}

// spec.selector = {} (headless) — the Pods tab must NOT fetch pods.
const emptySelSvc = {
  metadata: {
    name: 'empty-sel-svc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-06T00:00:00Z',
  },
  spec: { type: 'ClusterIP', selector: {} },
}

// kubernetes to_dict pods (the existing list_pods shape — the view projects).
const pod1 = {
  metadata: {
    name: 'web-abc',
    namespace: 'team-a',
    owner_references: [{ kind: 'ReplicaSet', name: 'web-abc123' }],
  },
  status: { phase: 'Running', pod_ip: '10.1.0.5' },
  spec: { node_name: 'node-1' },
}
const pod2 = {
  metadata: { name: 'web-def', namespace: 'team-a' },
  status: { phase: 'Pending' },
}

const serveService = (item: unknown) =>
  http.get('*/api/v1/clusters/1/resources/services', () =>
    HttpResponse.json({ kind: 'services', items: item ? [item] : [] }),
  )

// data-renders-three-tabs: the page renders the Service/Ports/Pods CTabs
// (Service default active) and fetches the Service ONCE with ?name= AND
// ?namespace= (the single-fetch contract — not 4.1's list-then-filter).
test('data-renders-three-tabs', async () => {
  const seen: { name?: string | null; namespace?: string | null }[] = []
  server.use(
    http.get('*/api/v1/clusters/1/resources/services', ({ request }) => {
      const u = new URL(request.url)
      seen.push({ name: u.searchParams.get('name'), namespace: u.searchParams.get('namespace') })
      return HttpResponse.json({ kind: 'services', items: [webSvc] })
    }),
  )
  selectTeamA()
  renderDataAt('web-svc', 'team-a')

  expect(await screen.findByText('Service Data')).toBeTruthy()
  // The three tabs (CoreUI CTabs — the 4.1 Bootstrap-JS tabs, re-implemented
  // as React tabs). They render once the service query settles, so poll.
  const serviceTab = await screen.findByRole('tab', { name: 'Service' })
  expect(screen.getByRole('tab', { name: 'Ports' })).toBeTruthy()
  expect(screen.getByRole('tab', { name: 'Pods' })).toBeTruthy()
  // Service default active.
  expect(serviceTab).toHaveAttribute('aria-selected', 'true')

  // The single ?name=&namespace= fetch (R2).
  expect(seen).toHaveLength(1)
  expect(seen[0]).toEqual({ name: 'web-svc', namespace: 'team-a' })
})

// data-service-tab: the Service tab's CTable (the 4.1 row set) + the
// annotations sub-table renders VERBATIM (no trimAnnotations) + the
// full-object JSON block.
test('data-service-tab', async () => {
  server.use(serveService(webSvc))
  selectTeamA()
  renderDataAt('web-svc', 'team-a')

  await screen.findByText('Name:') // the tabs render once the query settles
  expect(row('Name').getByText('web-svc')).toBeTruthy()
  expect(row('Type').getByText('ClusterIP')).toBeTruthy()
  // External IP: "—" for a ClusterIP (the R4 expression).
  expect(row('External IP').getByText('—')).toBeTruthy()
  expect(
    row('Cluster IP').getByText('10.0.0.1'),
  ).toBeTruthy()
  // The Created row (formatTimestamp — the browser's local time).
  expect(screen.getByText('Created:')).toBeTruthy()

  // Annotations render VERBATIM — BOTH the last-applied-configuration key
  // AND the plain key (the 4.1 inline filter is NOT replicated).
  expect(screen.getByText('kubectl.kubernetes.io/last-applied-configuration')).toBeTruthy()
  expect(row('Annotations').getByText('platform')).toBeTruthy()
  // The Labels sub-table.
  expect(row('Labels').getByText('web')).toBeTruthy()

  // The full-object JSON block (the 5.0 addition, json grammar). The
  // highlighter splits tokens across <code class="hljs-*"> spans, so assert
  // on the concatenated text (the house pattern).
  expect(document.body.textContent).toContain('"cluster_ip": "10.0.0.1"')
})

// data-ports-tab: one row per spec.ports entry (Name/Port/Protocol/Target/
// Node Port — "—" when a field is absent; a ClusterIP port has no node_port).
test('data-ports-tab', async () => {
  const user = userEvent.setup()
  server.use(serveService(webSvc))
  selectTeamA()
  renderDataAt('web-svc', 'team-a')

  await user.click(await screen.findByRole('tab', { name: 'Ports' }))

  const portRow = screen.getByText('http').closest('tr')!
  expect(within(portRow).getByText('80')).toBeTruthy()
  expect(within(portRow).getByText('TCP')).toBeTruthy()
  expect(within(portRow).getByText('8080')).toBeTruthy()
  // Node Port: absent on a ClusterIP port -> "—".
  expect(within(portRow).getByText('—')).toBeTruthy()
})

// data-no-ports: a Service with no spec.ports renders the pinned "No ports"
// state on the Ports tab.
test('data-no-ports', async () => {
  const user = userEvent.setup()
  server.use(serveService(noPortSvc))
  selectTeamA()
  renderDataAt('noport-svc', 'team-a')

  await user.click(await screen.findByRole('tab', { name: 'Ports' }))

  expect(await screen.findByText('No ports')).toBeTruthy()
})

// data-pods-tab: a SECOND fetch on the pods route with
// ?labelSelector=<built-from-spec.selector>; the owner cell is
// `kind.lower() + "/" + name` (the 4.1 stray-"s" typo fixed).
test('data-pods-tab', async () => {
  const user = userEvent.setup()
  let podSelector = ''
  server.use(
    serveService(webSvc),
    http.get('*/api/v1/clusters/1/resources/pods', ({ request }) => {
      podSelector = new URL(request.url).searchParams.get('labelSelector') ?? ''
      return HttpResponse.json({ kind: 'pods', items: [pod1, pod2] })
    }),
  )
  selectTeamA()
  renderDataAt('web-svc', 'team-a')

  await user.click(await screen.findByRole('tab', { name: 'Pods' }))

  // The owner format (the load-bearing 4.1 typo fix).
  expect(await screen.findByText('replicaset/web-abc123')).toBeTruthy()
  expect(podSelector).toBe('app=web')
  // The matched pod's cells.
  const podRow = screen.getByText('web-abc').closest('tr')!
  expect(within(podRow).getByText('10.1.0.5')).toBeTruthy()
  expect(within(podRow).getByText('node-1')).toBeTruthy()
  // The second pod (Pending — no ip/node/owner).
  const pod2Row = screen.getByText('web-def').closest('tr')!
  expect(within(pod2Row).getByText('Pending')).toBeTruthy()
  expect(within(pod2Row).getAllByText('—')).toBeTruthy()
})

// data-pods-tab-empty-selector: a Service with spec.selector = {} renders the
// muted empty state AND NO pods fetch is made (the load-bearing enabled gate).
test('data-pods-tab-empty-selector', async () => {
  let podsCalls = 0
  server.use(
    serveService(emptySelSvc),
    http.get('*/api/v1/clusters/1/resources/pods', () => {
      podsCalls += 1
      return HttpResponse.json({ kind: 'pods', items: [] })
    }),
  )
  selectTeamA()
  renderDataAt('empty-sel-svc', 'team-a')

  expect(
    await screen.findByText("No pods match this service's selector"),
  ).toBeTruthy()
  // Wait for the service fetch to settle, then assert the pods query never
  // fired.
  await screen.findByText('Name:')
  expect(document.body.textContent).toContain('"selector": {}')
  expect(podsCalls).toBe(0)
})

// data-pods-tab-no-match: a non-empty selector whose pods fetch returns
// items: [] renders the SAME muted empty state (NOT an error).
test('data-pods-tab-no-match', async () => {
  server.use(
    serveService(webSvc),
    http.get('*/api/v1/clusters/1/resources/pods', () =>
      HttpResponse.json({ kind: 'pods', items: [] }),
    ),
  )
  selectTeamA()
  renderDataAt('web-svc', 'team-a')

  const empty = await screen.findByText("No pods match this service's selector")
  expect(empty.className).toContain('text-muted')
  expect(screen.queryByText(/Error/)).toBeNull()
})

// data-not-found-state: a ?name= miss (items: []) is the pinned muted state
// — never an error style.
test('data-not-found-state', async () => {
  server.use(serveService(null))
  selectTeamA()
  renderDataAt('ghost', 'team-a')

  const notFound = await screen.findByText("No Service 'ghost' found")
  expect(notFound.className).toContain('text-muted')
  expect(screen.queryByText(/Error/)).toBeNull()
})

// data-missing-name: no name -> the pinned error line (red).
test('data-missing-name', async () => {
  server.use(serveService(webSvc))
  selectTeamA()
  renderDataAt('', 'team-a')

  expect(await screen.findByText('Error: service name not provided')).toBeTruthy()
})
