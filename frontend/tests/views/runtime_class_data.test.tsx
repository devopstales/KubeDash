import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import RuntimeClassDataView from '../../src/views/OtherResource/RuntimeClassData'
import RuntimeClassView from '../../src/views/OtherResource/RuntimeClass'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/other-resource/runtimeclass') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/runtimeclass"
            element={
              <ObjectRoute
                kind="runtimeclass"
                listRoute="/other-resource/runtimeclass"
                list={<RuntimeClassView />}
                detail={(p) => (<RuntimeClassDataView name={p.name} />)}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's identity now
// comes from ObjectRoute's ref, not the URL). Cluster-scoped: no namespace.
const seedActiveRef = (name: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({ [token]: { kind: 'runtimeclass', name, ts: Date.now(), origin: 'click' } }),
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
const runc = {
  apiVersion: 'node.k8s.io/v1',
  kind: 'RuntimeClass',
  metadata: {
    name: 'runc',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { provider: 'docker' },
  },
  handler: 'runc',
  overwrite_node_sel_no_toleration: false,
  scheduling: { node_selector: { 'kubernetes.io/runtime': 'runc' }, tolerations: [] },
  pod_level_overhead: { memory: '128Mi', cpu: '100m' },
}

// runtimeclass-data-renders-detail
test('data-renders-detail', async () => {
  const requested: string[] = []
  server.use(
    http.get('*/api/v1/clusters/1/resources/runtimeclasses', ({ request }) => {
      requested.push(request.url)
      return HttpResponse.json({
        kind: 'runtimeclasses',
        cluster: 'prod',
        items: [runc],
      })
    }),
  )
  selectProd()
  seedActiveRef('runc')
  const { container } = renderAt(<RuntimeClassDataView name="runc" />)

  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('handler')
  })
  // single read: EXACTLY the cluster-scoped ?name= URL (no list, no dispatch).
  expect(requested).toHaveLength(1)
  const u = new URL(requested[0])
  expect(u.searchParams.get('name')).toBe('runc')
  // cluster-scoped: the fetched URL has no namespace substring at all
  // (the kind is cluster-scoped; the list URL and the data link carry none).
  expect(requested[0]).not.toContain('namespace')
  expect(u.searchParams.get('namespace')).toBeNull()
  // breadcrumb: Other Resources → Runtime Classes → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Runtime Classes' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/runtimeclass')
  // metadata table: the item's spec fields and metadata are shown. The same
  // values repeat in the JSON block below, so scope to the metadata table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('RuntimeClass')).toBe(true)
  expect(await inTable('false')).toBe(true)
  expect(await inTable('100m / 128Mi')).toBe(true)
  // labels render. The key `provider` is unique; the label VALUE `docker`
  // appears in the labels table and the JSON block — assert presence.
  expect(await inTable('provider')).toBe(true)
  expect(screen.getAllByText('docker').length).toBeGreaterThanOrEqual(1)
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"handler": "runc"')
  expect(pre!.textContent).toContain('runc')
})

// runtimeclass-data-not-found-state
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/runtimeclasses', () =>
      HttpResponse.json({ kind: 'runtimeclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost')
  const { container } = renderAt(<RuntimeClassDataView name="runc" />)

  // empty items upstream is a state, not an error: pinned copy, no fetch-error line.
  expect(await screen.findByText("No RuntimeClass 'ghost' found")).toBeTruthy()
  expect(container.textContent).not.toContain('Error')
})

// runtimeclass-data-missing-name
test('data-missing-name', async () => {
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
        <RuntimeClassDataView name="" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: runtime class name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})

test('data-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  seedActiveRef('runc')
  renderAt(<RuntimeClassDataView name="runc" />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
