import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse, type AnyHandler } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import VolumeSnapshotDataView from '../../src/views/Storage/VolumeSnapshotData'
import VolumeSnapshotView from '../../src/views/Storage/VolumeSnapshot'
import { useClusterStore } from '../../src/store/cluster'

// ADR-0040: render through ObjectRoute so the detail is ref-driven (the
// identity comes from the active ref, never from the URL) and
// window.location.search === '' (R1) is assertable.
const renderAt = (_ui: ReactElement, path = '/storage/volumesnapshot') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/volumesnapshot"
            element={
              <ObjectRoute
                kind="volumesnapshot"
                listRoute="/storage/volumesnapshot"
                list={<VolumeSnapshotView />}
                detail={(p) => (
                  <VolumeSnapshotDataView name={p.name} namespace={p.namespace ?? ''} />
                )}
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
      [token]: { kind: 'volumesnapshot', name, namespace, ts: Date.now(), origin: 'click' },
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

// Full custom object (camelCase wire form, spec + status intact).
const snapA = {
  apiVersion: 'snapshot.storage.k8s.io/v1',
  kind: 'VolumeSnapshot',
  metadata: {
    name: 'snap-a',
    namespace: 'team-a',
    creationTimestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'alpha' },
    annotations: { 'snapshot.storage.kubernetes.io/xxx': 'yyy' },
  },
  spec: {
    source: { persistentVolumeClaimName: 'pvc-snap-a' },
    volumeSnapshotClassName: 'csi-snap',
  },
  status: {
    readyToUse: true,
    restoreSize: '1Gi',
    boundVolumeSnapshotContentName: 'content-snap-a',
  },
}

// A SourceMode-less snapshot (4.1's deep-index 500 case): no
// persistentVolumeClaimName, no volumeSnapshotClassName, empty status.
const bareSnap = {
  apiVersion: 'snapshot.storage.k8s.io/v1',
  kind: 'VolumeSnapshot',
  metadata: {
    name: 'bare-snap',
    namespace: 'team-a',
    creationTimestamp: '2026-01-06T00:00:00Z',
  },
  spec: { source: {} },
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

// volumesnapshot-data-renders-detail
test('data-renders-detail', async () => {
  let fetchCount = 0
  const handlers: AnyHandler[] = [
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', ({ request }) => {
      fetchCount++
      const u = new URL(request.url)
      if (u.searchParams.get('name') !== 'snap-a' || u.searchParams.get('namespace') !== 'team-a') {
        return HttpResponse.json({ error: { code: 'UNEXPECTED', message: u.href } }, { status: 500 })
      }
      return HttpResponse.json({ kind: 'volumesnapshots', cluster: 'prod', items: [snapA] })
    }),
  ]
  server.use(...handlers)
  selectProd()
  seedActiveRef('snap-a', 'team-a')
  const { container } = renderAt(<VolumeSnapshotDataView name="snap-a" namespace="team-a" />)

  // Wait for the fetch to land (the highlighter splits tokens across spans,
  // so poll the DOM text instead of findByText on a token).
  await waitFor(() => {
    expect(container.textContent).toContain('"readyToUse": true')
  })
  // single read: EXACTLY the ?name=&namespace= URL.
  expect(fetchCount).toBe(1)
  // card title.
  expect(screen.getByText('Volume Snapshot Data')).toBeTruthy()
  // breadcrumb: Storage → Volume Snapshot List → name.
  expect(screen.getByText('Storage')).toBeTruthy()
  const listLink = screen.getByRole('link', { name: 'Volume Snapshot List' })
  expect(listLink.getAttribute('href')).toBe('/storage/volumesnapshot')
  // CTable rows: the 4.1 list columns + labels/annotations. The same values
  // repeat in the JSON block below, so scope to the row cells.
  expect(await rowValue('Name')).toBe('snap-a')
  expect(await rowValue('Source')).toBe('pvc-snap-a')
  expect(await rowValue('SnapshotClass')).toBe('csi-snap')
  expect(await rowValue('Restore Size')).toBe('1Gi')
  expect(await rowValue('Bound Content')).toBe('content-snap-a')
  // Ready To Use: readyToUse true → success "Ready" badge.
  const readyCell = await rowCell('Ready To Use')
  expect(readyCell?.textContent).toBe('Ready')
  expect(readyCell?.querySelector('.badge')?.className).toContain('bg-success')
  // Labels / Annotations sub-tables render the key/value pairs.
  expect(await screen.findByText('team')).toBeTruthy()
  expect(await screen.findByText('alpha')).toBeTruthy()
  expect(await screen.findByText('snapshot.storage.kubernetes.io/xxx')).toBeTruthy()
  expect(await screen.findByText('yyy')).toBeTruthy()
  // Created: rendered via formatTimestamp — no raw ISO 'T' in the table row.
  const created = await rowValue('Created')
  expect(created).toMatch(/2026/)
  expect(created).not.toContain('T03:04:05Z')
  // the full object is rendered as a JSON-highlighted block (truthful
  // classifier: the block is JSON.stringify of the raw custom object).
  await waitFor(() => {
    expect(container.textContent).toContain('"boundVolumeSnapshotContentName": "content-snap-a"')
  })
  expect(container.querySelector('pre')).not.toBeNull()
})

// volumesnapshot-data-missing-fields — the 4.1 deep-index 500 is fixed:
// every absent key renders "—" (no crash, no KeyError).
test('data-missing-fields', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({ kind: 'volumesnapshots', cluster: 'prod', items: [bareSnap] }),
    ),
  )
  selectProd()
  seedActiveRef('bare-snap', 'team-a')
  const { container } = renderAt(<VolumeSnapshotDataView name="bare-snap" namespace="team-a" />)

  // Wait for the JSON block to land (a stable key present on every item).
  await waitFor(() => {
    expect(container.textContent).toContain('"kind": "VolumeSnapshot"')
  })
  expect(await rowValue('Name')).toBe('bare-snap')
  expect(await rowValue('Source')).toBe('—') // no persistentVolumeClaimName
  expect(await rowValue('SnapshotClass')).toBe('—') // no volumeSnapshotClassName
  expect(await rowValue('Ready To Use')).toBe('—') // no readyToUse
  expect(await rowValue('Restore Size')).toBe('—') // no restoreSize
  expect(await rowValue('Bound Content')).toBe('—') // no boundVolumeSnapshotContentName
  // empty labels/annotations render the pinned states, not an error.
  expect(await screen.findByText('No labels')).toBeTruthy()
  expect(await screen.findByText('No annotations')).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// volumesnapshot-data-not-found-state — empty items (a miss OR the CRD
// absent) is a STATE, not an error: pinned copy, no error styling.
test('data-not-found-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({ kind: 'volumesnapshots', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  seedActiveRef('ghost', 'team-a')
  const { container } = renderAt(<VolumeSnapshotDataView name="ghost" namespace="team-a" />)

  expect(await screen.findByText("No VolumeSnapshot 'ghost' found")).toBeTruthy()
  expect(container.querySelector('.text-danger')).toBeNull()
})

// volumesnapshot-data-missing-name
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
        <VolumeSnapshotDataView name="" namespace="team-a" />
      </MemoryRouter>
    </QueryClientProvider>,
  )

  expect(await screen.findByText('Error: volume snapshot name not provided')).toBeTruthy()
  expect(seen).toHaveLength(0) // no fetch
})
