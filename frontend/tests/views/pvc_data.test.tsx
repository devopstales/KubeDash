import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PvcDataView from '../../src/views/Storage/PvcData'
import PvcView from '../../src/views/Storage/Pvc'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/storage/pvc') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/pvc"
            element={
              <ObjectRoute
                kind="pvc"
                listRoute="/storage/pvc"
                list={<PvcView />}
                detail={(p) => <PvcDataView name={p.name} namespace={p.namespace ?? ''} />}
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
      [token]: { kind: 'pvc', name, namespace, ts: Date.now(), origin: 'click' },
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

// kubernetes to_dict form (snake_case, spec + status intact).
const boundPvc = {
  metadata: {
    name: 'data-pvc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: { 'kubectl.kubernetes.io/last-applied-configuration': '{}' },
  },
  spec: {
    storage_class_name: 'csi-fast',
    volume_name: 'pv-1',
    access_modes: ['ReadWriteOnce'],
    volume_mode: 'Filesystem',
  },
  status: { phase: 'Bound', capacity: { storage: '10Gi' } },
}

// A claim with no volume, no capacity, no phase, no labels/annotations
// (the 4.1 KeyError-500 case): every absent key renders "—".
const barePvc = {
  metadata: {
    name: 'bare-pvc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-06T00:00:00Z',
  },
  spec: {},
  status: {},
}

// The <td> value adjacent to a CTable row label (`<th>Label:</th>`).
const rowCell = async (label: string): Promise<Element | null> => {
  const ths = await screen.findAllByText(new RegExp(`^${label}:$`), { selector: 'th' })
  for (const th of ths) {
    const td = th.closest('tr')?.querySelector('td')
    if (td) return td
  }
  return null
}

const rowValue = async (label: string): Promise<string | null> =>
  (await rowCell(label))?.textContent ?? null

// pvc-data-renders-detail
test('data-renders-detail', async () => {
  let fetchCount = 0
  const handlers: AnyHandler[] = [
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', ({ request }) => {
      fetchCount++
      const u = new URL(request.url)
      if (u.searchParams.get('name') !== 'data-pvc' || u.searchParams.get('namespace') !== 'team-a') {
        return HttpResponse.json({ error: { code: 'UNEXPECTED', message: u.href } }, { status: 500 })
      }
      return HttpResponse.json({ kind: 'persistentvolumeclaims', cluster: 'prod', items: [boundPvc] })
    }),
  ]
  server.use(...handlers)
  selectProd()
  seedActiveRef('data-pvc', 'team-a')
  const { container } = renderAt(<PvcDataView name="data-pvc" namespace="team-a" />)

  // Wait for the fetch to land (the highlighter splits tokens across spans,
  // so poll the DOM text instead of findByText on a token).
  await waitFor(() => {
    expect(container.textContent).toContain('"phase": "Bound"')
  })
  // single read: EXACTLY the ?name=&namespace= URL.
  expect(fetchCount).toBe(1)
  // card title.
  expect(screen.getByText('Persistent Volume Claim Data')).toBeTruthy()
  // breadcrumb: Storage → Persistent Volume Claim List → name.
  expect(screen.getByText('Storage')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Persistent Volume Claim List' })
  expect(listLink.getAttribute('href')).toBe('/storage/pvc')
  // CTable rows: the 4.1 data row set. The same values repeat in the JSON
  // block below, so scope to the row cells.
  expect(await rowValue('Name')).toBe('data-pvc')
  expect(await rowValue('Namespace')).toBe('team-a')
  expect(await rowValue('Access Mode')).toBe('ReadWriteOnce')
  expect(await rowValue('Volume Mode')).toBe('Filesystem')
  expect(await rowValue('Capacity')).toBe('10Gi')
  expect(await rowValue('StorageClass')).toBe('csi-fast')
  expect(await rowValue('Persistent Volume')).toBe('pv-1')
  // Status: Bound → success badge.
  const statusCell = await rowCell('Status')
  expect(statusCell?.textContent).toBe('Bound')
  expect(statusCell?.querySelector('.badge')?.className).toContain('bg-success')
  // Labels / Annotations sub-tables render the key/value pairs (verbatim —
  // 4.1's trimAnnotations is NOT replicated).
  expect(await screen.findByText('team')).toBeTruthy()
  expect(await screen.findByText('a')).toBeTruthy()
  expect(await screen.findByText('kubectl.kubernetes.io/last-applied-configuration')).toBeTruthy()
  // Created: rendered via formatTimestamp — no raw ISO 'T' in the table row.
  const created = await rowValue('Created')
  expect(created).toMatch(/2026/)
  expect(created).not.toContain('T03:04:05Z')
  // the full object is rendered as a JSON-highlighted block (truthful
  // classifier: the block is JSON.stringify of the to_dict item).
  await waitFor(() => {
    expect(container.textContent).toContain('"storage_class_name": "csi-fast"')
  })
  expect(container.querySelector('pre')).not.toBeNull()
})

// pvc-data-missing-optional-fields — absent keys render "—" (no crash,
// no KeyError); empty labels/annotations render the pinned states.
test('data-missing-fields', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', cluster: 'prod', items: [barePvc] }),
    ),
  )
  selectProd()
  seedActiveRef('bare-pvc', 'team-a')
  const { container } = renderAt(<PvcDataView name="bare-pvc" namespace="team-a" />)

  // Wait for the JSON block to land (a stable key present on every item).
  await waitFor(() => {
    expect(container.textContent).toContain('"name": "bare-pvc"')
  })
  expect(await rowValue('Name')).toBe('bare-pvc')
  expect(await rowValue('Persistent Volume')).toBe('—') // no volume_name
  expect(await rowValue('Capacity')).toBe('—') // no capacity
  expect(await rowValue('Access Mode')).toBe('—') // no access_modes
  expect(await rowValue('Volume Mode')).toBe('—') // no volume_mode
  expect(await rowValue('StorageClass')).toBe('—') // no storage_class_name
  // no phase → "—" with no badge.
  const statusCell = await rowCell('Status')
  expect(statusCell?.textContent).toBe('—')
  expect(statusCell?.querySelector('.badge')).toBeNull()
  // empty labels/annotations render the pinned states, not an error.
  expect(await screen.findByText('No labels')).toBeTruthy()
  expect(await screen.findByText('No annotations')).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// pvc-data-not-found-state — empty items (a miss) is a STATE, not an error:
// pinned copy, no error styling.
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<PvcDataView name="ghost" namespace="team-a" />)

  expect(await screen.findByText("No PVC 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// pvc-data-missing-name
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
        <PvcDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: pvc name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
