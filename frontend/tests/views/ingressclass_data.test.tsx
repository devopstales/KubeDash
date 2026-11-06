import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import IngressClassView from '../../src/views/Network/IngressClass'
import IngressClassDataView from '../../src/views/Network/IngressClassData'
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
            path="/network/ingress-class"
            element={
              <ObjectRoute
                kind="ingressclass"
                listRoute="/network/ingress-class"
                list={<IngressClassView />}
                detail={(p) => <IngressClassDataView name={p.name} />}
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
    JSON.stringify({ [token]: { kind: 'ingressclass', name, ts: Date.now(), origin: 'click' } }),
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

// kubernetes to_dict shape: snake_case. Cluster-scoped — no namespace field.
const nginxClass = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'IngressClass',
  metadata: {
    name: 'nginx',
    creation_timestamp: '2026-10-26T10:00:00Z',
    labels: { env: 'prod' },
    annotations: { note: 'kept for upgrades' },
  },
  spec: {
    controller: 'k8s.io/ingress-nginx',
    parameters: { api_version: 'networking.k8s.io/v1', kind: 'Parameters', name: 'params' },
  },
}

// detail-renders-ingress-class-json
test('detail-renders-ingress-class-json', async () => {
  let searchParams = new URLSearchParams()
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingressclasses', ({ request }) => {
      const u = new URL(request.url)
      searchParams = u.searchParams
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'ingressclasses',
        cluster: 'prod',
        items: [nginxClass],
      })
    }),
  )
  selectProd()
  // ADR-0040: the detail is ref-driven — seed the active ref, render at the
  // clean route, and assert the URL stays clean (R1).
  seedActiveRef('nginx')
  const { container } = renderAt(<IngressClassDataView name="nginx" />, '/network/ingress-class')

  // R1: the URL never carries identity.
  expect(window.location.search).toBe('')
  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('ingress-nginx')
  })
  // single read: EXACTLY the cluster-scoped ?name= URL (no list, no dispatch).
  expect(searchParams.get('name')).toBe('nginx')
  // cluster-scoped: the fetched URL has no namespace substring at all.
  expect(requestedUrl).not.toContain('namespace')
  expect(searchParams.get('namespace')).toBeNull()
  // breadcrumb: Network → IngressClass List → name.
  expect(screen.getByText('Network')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'IngressClass List' })
  expect(listLink.getAttribute('href')).toBe('/network/ingress-class')
  // metadata table: the item's spec fields and metadata are shown. The same
  // values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('k8s.io/ingress-nginx')).toBe(true)
  // labels/annotations render (trimAnnotations keeps both keys here).
  expect(await inTable('env')).toBe(true)
  expect(await inTable('note')).toBe(true)
  // the 4.1 Parameters table: Kind / Name / API Version rows.
  expect(await inTable('Kind:')).toBe(true)
  expect(await inTable('API Version:')).toBe(true)
  expect(await inTable('networking.k8s.io/v1')).toBe(true)
  expect(await inTable('Parameters')).toBe(true)
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('nginx')
  expect(pre!.textContent).toContain('ingress-nginx')
})

// detail-missing-parameters
test('detail-missing-parameters', async () => {
  const noParams = { ...nginxClass, spec: { controller: 'k8s.io/ingress-nginx' } }
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingressclasses', () =>
      HttpResponse.json({ kind: 'ingressclasses', cluster: 'prod', items: [noParams] }),
    ),
  )
  selectProd()
  seedActiveRef('nginx')
  renderAt(<IngressClassDataView name="nginx" />, '/network/ingress-class')

  // spec.parameters absent → the 4.1 pinned state, not an error.
  expect(await screen.findByText('No parameters')).toBeTruthy()
  expect(screen.queryByText('API Version:')).toBeNull()
})

// detail-not-found-state
test('detail-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingressclasses', () =>
      HttpResponse.json({ kind: 'ingressclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost')
  const { container } = renderAt(<IngressClassDataView name="ghost" />, '/network/ingress-class')

  // R1: the URL stays clean even for a not-found object.
  expect(window.location.search).toBe('')
  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No IngressClass 'ghost' found")).toBeTruthy()
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
        <IngressClassDataView name="" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: ingress class name not provided')).toBeTruthy()
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
  seedActiveRef('nginx')
  renderAt(<IngressClassDataView name="nginx" />, '/network/ingress-class')

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
