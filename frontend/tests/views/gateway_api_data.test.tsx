import { useEffect, useMemo, useReducer, useRef } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import GatewayApiView from '../../src/views/Network/GatewayApi'
import GatewayApiDataView from '../../src/views/Network/GatewayApiData'
import { getActiveRef } from '../../src/lib/objectRef'
import { registerNavigate } from '../../src/components/ObjectRoute'
import { useClusterStore } from '../../src/store/cluster'

// Mirrors App.tsx's GatewayApiRoute dispatcher (the test does not import the
// whole app): the clean list route renders the tabbed list, or the
// ref-matched object detail for the three Gateway API kinds.
const GatewayApiTestRoute = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [, bump] = useReducer((c: number) => c + 1, 0)
  const ref = useMemo(
    () => getActiveRef(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [location, bump],
  )
  const isKind =
    ref !== null && (ref.kind === 'gateway' || ref.kind === 'httproute' || ref.kind === 'referencegrant')
  const seamRef = useRef(navigate)
  seamRef.current = navigate
  useEffect(() => {
    registerNavigate((path: string) => {
      seamRef.current(path)
      bump()
    })
  }, [])
  if (!isKind) return <GatewayApiView />
  return <GatewayApiDataView name={ref!.name} kind={ref!.kind} namespace={ref!.namespace ?? ''} />
}

// ADR-0040: render through the dispatcher route so the detail is ref-driven
// (name + kind + namespace from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/network/gateway-api']}>
        <Routes>
          <Route path="/network/gateway-api" element={<GatewayApiTestRoute />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's identity now
// comes from the route's dispatcher ref, not the URL).
const seedActiveRef = (name: string, kind: string, namespace?: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({ [token]: { kind, name, namespace, ts: Date.now(), origin: 'click' } }),
  )
  sessionStorage.setItem('kd_object_active', token)
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// FULL custom objects (camelCase — the CRD seam).
const webGateway = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'Gateway',
  metadata: {
    name: 'web-gateway',
    namespace: 'team-a',
    creationTimestamp: '2026-10-26T10:00:00Z',
    labels: { app: 'web' },
    annotations: { note: 'kept for upgrades' },
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
    parentRefs: [{ name: 'web-gateway', namespace: 'team-a' }],
  },
}
const allowGrant = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'ReferenceGrant',
  metadata: {
    name: 'allow',
    creationTimestamp: '2026-10-26T10:00:00Z',
    labels: { app: 'web' },
  },
  spec: {
    from: [{ group: 'gateway.networking.k8s.io', kind: 'Gateway', namespace: 'team-a' }],
    to: [{ group: '', kind: 'Service' }],
  },
}

const inTable = async (text: string) =>
  (await screen.findAllByText(text)).some((el) => el.closest('table'))

/** Wait for the detail fetch to land (the JSON block renders the item). */
async function detailRendered(name: string): Promise<void> {
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    const pre = document.querySelector('pre')
    expect(pre?.textContent).toContain(name)
  })
}

// gateway-detail-renders-json
test('gateway-detail-renders-json', async () => {
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/gateways', ({ request }) => {
      searchParams = new URL(request.url).searchParams
      return HttpResponse.json({ kind: 'gateways', cluster: 'prod', items: [webGateway] })
    }),
  )
  selectProd()
  seedActiveRef('web-gateway', 'gateway', 'team-a')
  renderAt()

  // R1: the URL never carries identity.
  expect(window.location.search).toBe('')
  await detailRendered('web-gateway')
  // single read: EXACTLY the namespaced ?name= URL (R8).
  expect(searchParams.get('name')).toBe('web-gateway')
  expect(searchParams.get('namespace')).toBe('team-a')
  expect(screen.getByRole('heading', { name: 'Gateway Data' })).toBeTruthy()
  expect(screen.getByText('Network')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Gateway API' })
  expect(listLink.getAttribute('href')).toBe('/network/gateway-api')
  // the kind's field rows (the same field set as the list tab).
  expect(await inTable('envoy')).toBe(true)
  expect(await inTable('web:HTTP:8080')).toBe(true)
  // labels/annotations render (trimAnnotations keeps both keys here).
  expect(await inTable('app')).toBe(true)
  expect(await inTable('note')).toBe(true)
})

// httproute-detail-renders-json
test('httproute-detail-renders-json', async () => {
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/httproutes', ({ request }) => {
      searchParams = new URL(request.url).searchParams
      return HttpResponse.json({ kind: 'httproutes', cluster: 'prod', items: [webRoute] })
    }),
  )
  selectProd()
  seedActiveRef('web-route', 'httproute', 'team-a')
  renderAt()

  expect(window.location.search).toBe('')
  await detailRendered('web-route')
  expect(searchParams.get('name')).toBe('web-route')
  expect(searchParams.get('namespace')).toBe('team-a')
  expect(screen.getByRole('heading', { name: 'HTTPRoute Data' })).toBeTruthy()
  expect(await inTable('a.example.com, b.example.com')).toBe(true)
  expect(await inTable('web-gateway/team-a')).toBe(true)
})

// referencegrant-detail-renders-json (cluster-scoped: NO namespace param)
test('referencegrant-detail-renders-json', async () => {
  let searchParams = new URLSearchParams()
  server.use(
    http.get('*/api/v1/clusters/1/resources/referencegrants', ({ request }) => {
      searchParams = new URL(request.url).searchParams
      return HttpResponse.json({ kind: 'referencegrants', cluster: 'prod', items: [allowGrant] })
    }),
  )
  selectProd()
  seedActiveRef('allow', 'referencegrant')
  renderAt()

  expect(window.location.search).toBe('')
  await detailRendered('allow')
  expect(searchParams.get('name')).toBe('allow')
  // cluster-scoped: the fetched URL has no namespace param at all.
  expect(searchParams.get('namespace')).toBeNull()
  expect(screen.getByRole('heading', { name: 'ReferenceGrant Data' })).toBeTruthy()
  expect(await inTable('gateway.networking.k8s.io:Gateway')).toBe(true)
  // the core group is "" — filter(Boolean) drops it, rendering 'Service'.
  expect(await inTable('Service')).toBe(true)
})

// detail-not-found-states (pinned per-kind copy — a state, never an error)
test('gateway-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gateways', () =>
      HttpResponse.json({ kind: 'gateways', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'gateway', 'team-a')
  const { container } = renderAt()

  expect(window.location.search).toBe('')
  expect(await screen.findByText("No Gateway 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
})

test('httproute-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/httproutes', () =>
      HttpResponse.json({ kind: 'httproutes', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'httproute', 'team-a')
  renderAt()
  expect(await screen.findByText("No HTTPRoute 'ghost' found")).toBeTruthy()
})

test('referencegrant-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/referencegrants', () =>
      HttpResponse.json({ kind: 'referencegrants', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'referencegrant')
  renderAt()
  expect(await screen.findByText("No ReferenceGrant 'ghost' found")).toBeTruthy()
})

// The closed-set validation: a bad kind renders the error line with NO
// network hit (the query is disabled).
test('bad-kind-error-no-fetch', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/:kind', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <GatewayApiDataView name="x" kind="pod" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: unknown gateway api kind: pod')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})

test('detail-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  seedActiveRef('web-gateway', 'gateway', 'team-a')
  renderAt()

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// click-name-renders-detail-with-clean-url (R1) — the load-bearing
// ADR-0040 flow through the dispatcher: the tab's name button writes the
// ref, the dispatcher re-reads it, the detail renders, the URL stays clean.
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/resources/gateways', () =>
      HttpResponse.json({ kind: 'gateways', cluster: 'prod', items: [webGateway] }),
    ),
    http.get('*/api/v1/clusters/1/resources/httproutes', () =>
      HttpResponse.json({ kind: 'httproutes', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/resources/referencegrants', () =>
      HttpResponse.json({ kind: 'referencegrants', cluster: 'prod', items: [] }),
    ),
  )
  renderAt()

  // Clicking the Gateway tab's name button opens the detail via openObject.
  const nameButton = await screen.findByRole('button', { name: 'web-gateway' })
  await user.click(nameButton)

  expect(await screen.findByText('Gateway Data')).toBeTruthy()
  // The URL is clean: no query string (R1).
  expect(window.location.search).toBe('')
})
