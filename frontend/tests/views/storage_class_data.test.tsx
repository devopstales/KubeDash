import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import StorageClassDataView from '../../src/views/Storage/StorageClassData'
import StorageClassView from '../../src/views/Storage/StorageClass'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/storage/storage-class') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/storage-class"
            element={
              <ObjectRoute
                kind="storageclass"
                listRoute="/storage/storage-class"
                list={<StorageClassView />}
                detail={(p) => (<StorageClassDataView name={p.name} />)}
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
    JSON.stringify({ [token]: { kind: 'storageclass', name, ts: Date.now(), origin: 'click' } }),
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
const csiFast = {
  apiVersion: 'storage.k8s.io/v1',
  kind: 'StorageClass',
  metadata: {
    name: 'csi-fast',
    creation_timestamp: '2026-01-02T03:04:05Z',
    annotations: { 'storageclass.kubernetes.io/is-default-class': 'true' },
    labels: { team: 'a' },
  },
  provisioner: 'csi.example.com',
  reclaim_policy: 'Delete',
  volume_binding_mode: 'WaitForFirstConsumer',
  parameters: { type: 'standard' },
}

// no parameters field: the Parameters table renders "No parameters".
const noParamsSc = { ...csiFast, parameters: undefined }

// storage-class-data-renders-detail
test('data-renders-detail', async () => {
  const requested: string[] = []
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', ({ request }) => {
      requested.push(request.url)
      return HttpResponse.json({
        kind: 'storageclasses',
        cluster: 'prod',
        items: [csiFast],
      })
    }),
  )
  selectProd()
  seedActiveRef('csi-fast')
  const { container } = renderAt(<StorageClassDataView name="csi-fast" />)

  // wait for the fetch to land before reading what the view asked for.
  // The highlighter splits tokens across <code class="hljs-*"> spans, so
  // `findByText` cannot match a whole token; poll the DOM text instead.
  await waitFor(() => {
    expect(container.textContent).toContain('provisioner')
  })
  // single read: EXACTLY the cluster-scoped ?name= URL (no list, no dispatch).
  expect(requested).toHaveLength(1)
  const u = new URL(requested[0])
  expect(u.searchParams.get('name')).toBe('csi-fast')
  // cluster-scoped: the fetched URL has no namespace substring at all
  // (the kind is cluster-scoped; the list URL and the data open carry none).
  expect(requested[0]).not.toContain('namespace')
  expect(u.searchParams.get('namespace')).toBeNull()
  // breadcrumb: Storage → Storage Classes List → name.
  expect(screen.getByText('Storage')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Storage Classes List' })
  expect(listLink.getAttribute('href')).toBe('/storage/storage-class')
  // metadata table: the item's spec fields and metadata are shown. The same
  // values repeat in the JSON block below, so scope to the metadata table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('csi-fast')).toBe(true)
  expect(await inTable('Delete')).toBe(true)
  expect(await inTable('WaitForFirstConsumer')).toBe(true)
  expect(await inTable('csi.example.com')).toBe(true)
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp —
  // scoped to the metadata table: the JSON block below carries the raw
  // creation_timestamp.
  const firstTable = container.querySelector('table')
  expect(firstTable?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(firstTable?.textContent).toMatch(/2026/)
  // labels render: the key `team` is unique; the label VALUE `a` also
  // appears in the JSON block — assert the key is in a table.
  expect(await inTable('team')).toBe(true)
  // annotations render the is-default-class key verbatim.
  expect(await inTable('storageclass.kubernetes.io/is-default-class')).toBe(true)
  // the Parameters table has a row per parameters entry (key `type`,
  // value `standard`).
  expect(await inTable('type')).toBe(true)
  expect(await inTable('standard')).toBe(true)
  // the full object is rendered as a highlighted JSON block.
  const pre = container.querySelector('pre')
  expect(pre).not.toBeNull()
  expect(pre!.textContent).toContain('"reclaim_policy": "Delete"')
  expect(pre!.textContent).toContain('"volume_binding_mode": "WaitForFirstConsumer"')
})

// storage-class-data-missing-parameters
test('data-missing-parameters', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', () =>
      HttpResponse.json({ kind: 'storageclasses', cluster: 'prod', items: [noParamsSc] }),
    ),
  )
  selectProd()
  seedActiveRef('csi-fast')
  renderAt(<StorageClassDataView name="csi-fast" />)

  expect(await screen.findByText('No parameters')).toBeTruthy()
})

// storage-class-data-not-found-state
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', () =>
      HttpResponse.json({ kind: 'storageclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost')
  const { container } = renderAt(<StorageClassDataView name="ghost" />)

  // empty items upstream is a state, not an error: pinned copy, no
  // fetch-error line (no .text-danger node).
  expect(await screen.findByText("No StorageClass 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
  expect(container.textContent).not.toContain('Error')
})

// storage-class-data-missing-name
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
        <StorageClassDataView name="" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: storage class name not provided')).toBeTruthy()
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
  seedActiveRef('csi-fast')
  renderAt(<StorageClassDataView name="csi-fast" />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})
