import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import IngressView from '../../src/views/Network/Ingress'
import IngressDataView from '../../src/views/Network/IngressData'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// name + namespace come from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path: string) => {
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

// Seed an active ref for the detail to render (the data view's identity now
// comes from ObjectRoute's ref, not the URL). Namespaced: the ref carries
// the namespace (R8).
const seedActiveRef = (name: string, namespace = 'team-a') => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({ [token]: { kind: 'ingress', name, namespace, ts: Date.now(), origin: 'click' } }),
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

// kubernetes to_dict shape: snake_case. Namespaced.
const webIngress = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'Ingress',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-10-26T10:00:00Z',
    labels: { app: 'web' },
    annotations: { note: 'kept for upgrades' },
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

// detail-renders-ingress-json
test('detail-renders-ingress-json', async () => {
  let searchParams = new URLSearchParams()
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', ({ request }) => {
      const u = new URL(request.url)
      searchParams = u.searchParams
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'ingresses',
        cluster: 'prod',
        items: [webIngress],
      })
    }),
  )
  selectProd()
  // ADR-0040: the detail is ref-driven — seed the active ref, render at the
  // clean route, and assert the URL stays clean (R1).
  seedActiveRef('web', 'team-a')
  const { container } = renderAt(<IngressDataView name="web" namespace="team-a" />, '/network/ingress')

  // R1: the URL never carries identity.
  expect(window.location.search).toBe('')
  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('web.example.com')
  })
  // single read: EXACTLY the namespaced ?name=+?namespace= URL (the ref's
  // namespace is authoritative, R8).
  expect(searchParams.get('name')).toBe('web')
  expect(searchParams.get('namespace')).toBe('team-a')
  // breadcrumb: Network → Ingress List → name.
  expect(screen.getByText('Network')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Ingress List' })
  expect(listLink.getAttribute('href')).toBe('/network/ingress')
  // metadata table: the item's spec fields and metadata are shown. The same
  // values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('nginx')).toBe(true)
  // labels/annotations render (trimAnnotations keeps both keys here).
  expect(await inTable('app')).toBe(true)
  expect(await inTable('note')).toBe(true)
  // Rules table: one row per spec.rules[].http.paths[] — Host/Path/PathType/
  // Service/Port/TLS. Port renders the number (80) else the name (http);
  // TLS is "yes" (spec.tls non-empty).
  expect(await inTable('web.example.com')).toBe(true)
  expect(await inTable('www.example.com')).toBe(true)
  expect(await inTable('Prefix')).toBe(true)
  expect(await inTable('80')).toBe(true)
  expect(await inTable('http')).toBe(true)
  expect(await inTable('yes')).toBe(true)
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('web')
  expect(pre!.textContent).toContain('web.example.com')
})

// detail-no-rules
test('detail-no-rules', async () => {
  const noRules = { ...webIngress, spec: { ingress_class_name: 'nginx' } }
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [noRules] }),
    ),
  )
  selectProd()
  seedActiveRef('web', 'team-a')
  renderAt(<IngressDataView name="web" namespace="team-a" />, '/network/ingress')

  // spec.rules absent → the pinned "No rules" state, not an error.
  expect(await screen.findByText('No rules')).toBeTruthy()
  // no rule rows (the header row is the Rules sub-table's, so scope to
  // body cells: "yes"/"Prefix" must be absent).
  expect(screen.queryByText('yes')).toBeNull()
  expect(screen.queryByText('Prefix')).toBeNull()
})

// detail-not-found-state
test('detail-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<IngressDataView name="ghost" namespace="team-a" />, '/network/ingress')

  // R1: the URL stays clean even for a not-found object.
  expect(window.location.search).toBe('')
  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No Ingress 'ghost' found")).toBeTruthy()
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
        <IngressDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: ingress name not provided')).toBeTruthy()
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
  seedActiveRef('web', 'team-a')
  renderAt(<IngressDataView name="web" namespace="team-a" />, '/network/ingress')

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// detail-convert-button-opens-converter-panel (R4 entry point)
test('detail-convert-button-opens-converter-panel', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({
        kind: 'ingresses',
        cluster: 'prod',
        items: [webIngress],
      }),
    ),
  )
  selectProd()
  seedActiveRef('web', 'team-a')
  renderAt(<IngressDataView name="web" namespace="team-a" />, '/network/ingress')

  // The button appears once the item is loaded; the panel is closed.
  const button = await screen.findByRole('button', { name: 'Convert to Gateway API' })
  expect(screen.queryByRole('button', { name: 'Convert' })).toBeNull()
  fireEvent.click(button)
  // The panel opens: its card title + the Convert action.
  expect(screen.getByText('Convert to Gateway API')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Convert' })).toBeTruthy()
  expect(screen.getByRole('combobox', { name: 'Gateway API provider' })).toBeTruthy()
})
