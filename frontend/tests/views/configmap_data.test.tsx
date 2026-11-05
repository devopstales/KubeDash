import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ConfigMapDataView from '../../src/views/Storage/ConfigMapData'
import ConfigMapView from '../../src/views/Storage/ConfigMap'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/storage/configmap') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/configmap"
            element={
              <ObjectRoute
                kind="configmap"
                listRoute="/storage/configmap"
                list={<ConfigMapView />}
                detail={(p) => (<ConfigMapDataView name={p.name} namespace={p.namespace ?? ''} />)}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Seed an active ref for the detail to render (the data view's identity now
// comes from ObjectRoute's ref, not the URL).
const seedActiveRef = (name: string, namespace: string) => {
  const token = 'testref1'
  sessionStorage.setItem(
    'kd_object_refs',
    JSON.stringify({
      [token]: { kind: 'configmap', name, namespace, ts: Date.now(), origin: 'click' },
    }),
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

// kubernetes to_dict shape: snake_case, 2 data keys + the kubectl noise
// annotation (rendered verbatim on this page — trimAnnotations is NOT
// replicated, unlike the Secret view).
const appConfig = {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    name: 'app-config',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    resource_version: '4242',
    labels: { app: 'web' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{}',
      owner: 'platform',
    },
  },
  data: { LOG_LEVEL: 'info', URL: 'https://internal' },
}

// No data field at all: the Data table renders "No data" (not an error).
const noDataCm = {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    name: 'no-data-cm',
    namespace: 'team-a',
    creation_timestamp: '2026-01-04T00:00:00Z',
  },
}

// configmap-data-renders-detail
test('data-renders-detail', async () => {
  let fetchCount = 0
  const handlers: AnyHandler[] = [
    http.get('*/api/v1/clusters/1/resources/configmaps', ({ request }) => {
      fetchCount++
      const u = new URL(request.url)
      if (u.searchParams.get('name') !== 'app-config' || u.searchParams.get('namespace') !== 'team-a') {
        return HttpResponse.json({ error: { code: 'UNEXPECTED', message: u.href } }, { status: 500 })
      }
      return HttpResponse.json({ kind: 'configmaps', cluster: 'prod', items: [appConfig] })
    }),
  ]
  server.use(...handlers)
  selectProd()
  seedActiveRef('app-config', 'team-a')
  const { container } = renderAt(<ConfigMapDataView name="app-config" namespace="team-a" />)

  // Wait for the fetch to land (the highlighter splits tokens across spans,
  // so poll the DOM text instead of findByText on a token).
  await waitFor(() => {
    expect(container.textContent).toContain('https://internal')
  })
  // single read: EXACTLY the ?name=&namespace= URL.
  expect(fetchCount).toBe(1)
  // card title.
  expect(screen.getByText('Configmap Data')).toBeTruthy()
  // breadcrumb: Storage → Configmaps List → name.
  expect(screen.getByText('Storage')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Configmaps List' })
  expect(listLink.getAttribute('href')).toBe('/storage/configmap')
  // CTable rows: Name / Namespace / Kind / Version / labels / annotations.
  // The same values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string | RegExp) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('app-config')).toBe(true)
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('ConfigMap')).toBe(true)
  expect(await inTable('4242')).toBe(true)
  expect(await inTable('app')).toBe(true)
  expect(await inTable('web')).toBe(true)
  // Annotations: the machine-managed kubectl key is trimmed from the table
  // (2026-11-05 trimAnnotations replication, user decision — overrides the
  // recorded "render verbatim" deviation); real annotations still render.
  // (queryByText: the key no longer renders unquoted anywhere — the JSON
  // block's token spans carry quotes, so no exact-text match exists.)
  expect(screen.queryByText('kubectl.kubernetes.io/last-applied-configuration')).toBeNull()
  expect(await inTable('owner')).toBe(true)
  expect(await inTable('platform')).toBe(true)
  // Data table: one row per data entry, the key as the row label (rendered
  // with a trailing colon) and the value in a <pre><code> block.
  expect(await inTable(/^LOG_LEVEL:$/)).toBe(true)
  expect(await inTable('info')).toBe(true)
  expect(await inTable('https://internal')).toBe(true)
  // Created: rendered via formatTimestamp — no raw ISO 'T' in the table row.
  const createdCells = (await screen.findAllByText(/2026/)).filter((el) => el.closest('table'))
  expect(createdCells.length).toBeGreaterThanOrEqual(1)
  expect(createdCells[0].textContent).not.toContain('T03:04:05Z')
  // the full object is rendered as a JSON-highlighted block (truthful
  // classifier: the block is JSON.stringify of the to_dict item).
  await waitFor(() => {
    expect(container.textContent).toContain('"LOG_LEVEL": "info"')
  })
  expect(container.querySelector('pre')).not.toBeNull()
})

// configmap-data-value-is-plain-pre
test('data-value-is-plain-pre', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ kind: 'configmaps', cluster: 'prod', items: [appConfig] }),
    ),
  )
  selectProd()
  seedActiveRef('app-config', 'team-a')
  const { container } = renderAt(<ConfigMapDataView name="app-config" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('https://internal')
  })
  // The Data table's value is a plain <pre><code> block, rendered verbatim
  // (NO base64 decode, NO language detection — the secretLanguage heuristic
  // is Secret-only; ConfigMap values are plain strings). The JSON block's
  // <code> holds the whole object (spans), so the exact-text match picks
  // the per-key value cell.
  const valueCode = Array.from(container.querySelectorAll('pre code')).find(
    (c) => c.textContent === 'https://internal',
  )
  expect(valueCode).toBeTruthy()
  const pre = valueCode!.closest('pre')
  expect(pre).not.toBeNull()
  expect(pre!.style.whiteSpace).toBe('pre-wrap')
  // NO eye/lock toggle (the Secret base64-decode affordance): the value
  // cell is text-only.
  const valueCell = valueCode!.closest('td')
  expect(valueCell?.querySelector('svg')).toBeNull()
  expect(valueCell?.querySelector('button')).toBeNull()
})

// configmap-data-missing-data
test('data-missing-data', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ kind: 'configmaps', cluster: 'prod', items: [noDataCm] }),
    ),
  )
  selectProd()
  seedActiveRef('no-data-cm', 'team-a')
  const { container } = renderAt(<ConfigMapDataView name="no-data-cm" namespace="team-a" />)

  // no data field -> "No data" (a state, not an error).
  expect(await screen.findByText('No data')).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// configmap-data-not-found-state
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ kind: 'configmaps', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<ConfigMapDataView name="ghost" namespace="team-a" />)

  // empty items upstream is a STATE, not an error: pinned copy, no error
  // styling.
  expect(await screen.findByText("No ConfigMap 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// configmap-data-missing-name
test('data-missing-name', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  selectProd()
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <ConfigMapDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: configmap name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
