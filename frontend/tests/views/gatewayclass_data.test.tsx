import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import GatewayClassView from '../../src/views/Network/GatewayClass'
import GatewayClassDataView from '../../src/views/Network/GatewayClassData'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// name comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path: string) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/network/gateway-class"
            element={
              <ObjectRoute
                kind="gatewayclass"
                listRoute="/network/gateway-class"
                list={<GatewayClassView />}
                detail={(p) => <GatewayClassDataView name={p.name} />}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's name now
// comes from ObjectRoute's ref, not the URL).
const seedActiveRef = (name: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({ [token]: { kind: 'gatewayclass', name, ts: Date.now(), origin: 'click' } }),
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

// FULL custom object (camelCase — the CRD seam). Cluster-scoped — no
// namespace field.
const traefikClass = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'GatewayClass',
  metadata: {
    name: 'traefik',
    creationTimestamp: '2026-10-26T10:00:00Z',
    labels: { env: 'prod' },
    annotations: { note: 'kept for upgrades' },
  },
  spec: {
    controllerName: 'traefik.io/gatewayclass',
    conditions: [{ type: 'Accepted', status: 'True', reason: 'Accepted', message: 'ok' }],
  },
}

// detail-renders-gateway-class-json
test('detail-renders-gateway-class-json', async () => {
  let searchParams = new URLSearchParams()
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', ({ request }) => {
      const u = new URL(request.url)
      searchParams = u.searchParams
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'gatewayclasses',
        cluster: 'prod',
        items: [traefikClass],
      })
    }),
  )
  selectProd()
  // ADR-0040: the detail is ref-driven — seed the active ref, render at the
  // clean route, and assert the URL stays clean (R1).
  seedActiveRef('traefik')
  const { container } = renderAt(<GatewayClassDataView name="traefik" />, '/network/gateway-class')

  // R1: the URL never carries identity.
  expect(window.location.search).toBe('')
  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('traefik.io/gatewayclass')
  })
  // single read: EXACTLY the cluster-scoped ?name= URL (no list, no dispatch).
  expect(searchParams.get('name')).toBe('traefik')
  // cluster-scoped: the fetched URL has no namespace substring at all.
  expect(requestedUrl).not.toContain('namespace')
  expect(searchParams.get('namespace')).toBeNull()
  // breadcrumb: Network → GatewayClass List → name.
  expect(screen.getByText('Network')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'GatewayClass List' })
  expect(listLink.getAttribute('href')).toBe('/network/gateway-class')
  // metadata table: the item's spec fields and metadata are shown. The same
  // values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('traefik.io/gatewayclass')).toBe(true)
  // labels/annotations render (trimAnnotations keeps both keys here).
  expect(await inTable('env')).toBe(true)
  expect(await inTable('note')).toBe(true)
  // created renders as a local time (formatTimestamp), not a raw ISO (the
  // JSON block carries the raw string inside quoted hljs spans, which
  // `getByText`'s exact matcher does not match — query, don't find).
  expect(screen.queryAllByText('2026-10-26T10:00:00Z').some((el) => el.closest('table'))).toBe(false)
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('traefik')
  expect(pre!.textContent).toContain('traefik.io/gatewayclass')
})

// detail-not-found-state (CRD-absent is the same pinned copy — never an
// error style).
test('detail-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost')
  const { container } = renderAt(<GatewayClassDataView name="ghost" />, '/network/gateway-class')

  // R1: the URL stays clean even for a not-found object.
  expect(window.location.search).toBe('')
  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No GatewayClass 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
})

// ADR-0040: with no active ref, ObjectRoute renders the list (not the
// detail), so the missing-name error state is unreachable through the route
// (R6). The data view itself still guards an empty name (no /data URL
// shipped, but the guard keeps the view total).
test('data-view-empty-name-client-error', async () => {
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
        <GatewayClassDataView name="" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: gateway class name not provided')).toBeTruthy()
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
  seedActiveRef('traefik')
  renderAt(<GatewayClassDataView name="traefik" />, '/network/gateway-class')

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
