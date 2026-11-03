import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ResourceQuotaDataView from '../../src/views/OtherResource/ResourceQuotaData'
import ResourceQuotaView from '../../src/views/OtherResource/ResourceQuota'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/other-resource/resource-quota') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/other-resource/resource-quota"
            element={
              <ObjectRoute
                kind="resourcequota"
                listRoute="/other-resource/resource-quota"
                list={<ResourceQuotaView />}
                detail={(p) => (<ResourceQuotaDataView name={p.name} namespace={p.namespace ?? ''} />)}
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
      [token]: { kind: 'resourcequota', name, namespace, ts: Date.now(), origin: 'click' },
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

// kubernetes to_dict shape: snake_case, namespaced, all four 4.1 dimensions.
const compute = {
  apiVersion: 'v1',
  kind: 'ResourceQuota',
  metadata: {
    name: 'compute',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: { 'quota.kubernetes.io/managed-by': 'kubedash' },
  },
  spec: {
    hard: {
      'requests.cpu': '4',
      'requests.memory': '10Gi',
      'limits.cpu': '8',
      'limits.memory': '20Gi',
    },
    scopes: ['NotBestEffort'],
  },
  status: {
    hard: {
      'requests.cpu': '4',
      'requests.memory': '10Gi',
      'limits.cpu': '8',
      'limits.memory': '20Gi',
    },
    used: {
      'requests.cpu': '2',
      'requests.memory': '4Gi',
      'limits.cpu': '4',
      'limits.memory': '8Gi',
    },
  },
}

// A pods-only quota: none of the four cpu/memory dimensions present in
// status (4.1's template would KeyError here).
const podsOnly = {
  apiVersion: 'v1',
  kind: 'ResourceQuota',
  metadata: {
    name: 'objects',
    namespace: 'team-a',
    creation_timestamp: '2026-01-03T04:05:06Z',
    labels: {},
    annotations: {},
  },
  spec: { hard: { pods: '20' } },
  status: { hard: { pods: '20' }, used: { pods: '10' } },
}

// resourcequota-data-renders-detail
test('data-renders-detail', async () => {
  let fetchCount = 0
  const handlers: AnyHandler[] = [
    http.get('*/api/v1/clusters/1/resources/resourcequotas', ({ request }) => {
      fetchCount++
      const u = new URL(request.url)
      if (u.searchParams.get('name') !== 'compute' || u.searchParams.get('namespace') !== 'team-a') {
        return HttpResponse.json({ error: { code: 'UNEXPECTED', message: u.href } }, { status: 500 })
      }
      return HttpResponse.json({ kind: 'resourcequotas', cluster: 'prod', items: [compute] })
    }),
  ]
  server.use(...handlers)
  selectProd()
  seedActiveRef('compute', 'team-a')
  const { container } = renderAt(<ResourceQuotaDataView name="compute" namespace="team-a" />)

  // Wait for the fetch to land (the highlighter splits tokens across spans,
  // so poll the DOM text instead of findByText on a token).
  await waitFor(() => {
    expect(container.textContent).toContain('NotBestEffort')
  })
  // single read: EXACTLY the ?name=&namespace= URL.
  expect(fetchCount).toBe(1)
  // card title.
  expect(screen.getByText('Resource Quota Data')).toBeTruthy()
  // breadcrumb: Other Resources → Resource Quota List → name.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Resource Quota List' })
  expect(listLink.getAttribute('href')).toBe('/other-resource/resource-quota')
  // CTable rows: Name / Namespace / Scope / labels / annotations. The same
  // values repeat in the JSON block below, so scope to a table.
  const inTable = async (text: string) =>
    (await screen.findAllByText(text)).some((el) => el.closest('table'))
  expect(await inTable('compute')).toBe(true)
  expect(await inTable('team-a')).toBe(true)
  expect(await inTable('NotBestEffort')).toBe(true)
  expect(await inTable('team')).toBe(true)
  expect(await inTable('quota.kubernetes.io/managed-by')).toBe(true)
  expect(await inTable('kubedash')).toBe(true)
  // Created: rendered via formatTimestamp — no raw ISO 'T' in the table row.
  const createdCells = (await screen.findAllByText(/2026/)).filter((el) => el.closest('table'))
  expect(createdCells.length).toBeGreaterThanOrEqual(1)
  expect(createdCells[0].textContent).not.toContain('T03:04:05Z')
  // Status table: the four 4.1 dimensions with used/hard values.
  expect(await inTable('limits.cpu')).toBe(true)
  expect(await inTable('requests.memory')).toBe(true)
  const statusRows = (await screen.findAllByText('8Gi')).filter((el) => el.closest('table'))
  expect(statusRows.length).toBeGreaterThanOrEqual(1)
  // the full object is rendered as a JSON-highlighted block (truthful
  // classifier: the block is JSON.stringify of the to_dict item). The
  // highlighter splits tokens across spans, so poll the DOM text — the
  // "scopes" key is unique to the JSON block (the CTable says "Scope").
  await waitFor(() => {
    expect(container.textContent).toContain('"scopes"')
  })
  expect(container.textContent).toContain('NotBestEffort')
  expect(container.querySelector('pre')).not.toBeNull()
})

// resourcequota-data-missing-status-keys
test('data-missing-status-keys', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', () =>
      HttpResponse.json({ kind: 'resourcequotas', cluster: 'prod', items: [podsOnly] }),
    ),
  )
  selectProd()
  seedActiveRef('objects', 'team-a')
  const { container } = renderAt(<ResourceQuotaDataView name="compute" namespace="team-a" />)

  await waitFor(() => {
    expect(container.textContent).toContain('Hard Limit')
  })
  // certainty rule: a key missing from status.used or status.hard renders
  // "—" — 4.1 would KeyError the template; 5.0 never guesses (no throw,
  // no blank, no "undefined").
  const statusTable = Array.from(document.querySelectorAll('table')).find((t) =>
    t.textContent?.includes('Hard Limit'),
  )
  expect(statusTable).toBeTruthy()
  const rows = Array.from(statusTable!.querySelectorAll('tbody tr'))
  const dims = rows.map((r) => r.textContent)
  expect(dims.some((d) => d?.includes('limits.cpu') && d?.includes('—'))).toBe(true)
  expect(dims.some((d) => d?.includes('requests.memory') && d?.includes('—'))).toBe(true)
  expect(container.textContent).not.toContain('undefined')
})

// resourcequota-data-not-found-state
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', () =>
      HttpResponse.json({ kind: 'resourcequotas', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<ResourceQuotaDataView name="compute" namespace="team-a" />)

  // empty items upstream is a STATE, not an error: pinned copy, no error
  // styling.
  expect(await screen.findByText("No ResourceQuota 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// resourcequota-data-missing-name
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
        <ResourceQuotaDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: resource quota name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
