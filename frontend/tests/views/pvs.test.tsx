import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test } from 'vitest'
import { server } from '../msw'
import { getActiveRef } from '../../src/lib/objectRef'
import ObjectRoute from '../../src/components/ObjectRoute'
import PvView from '../../src/views/Storage/Pv'
import PvcView from '../../src/views/Storage/Pvc'
import PvcDataView from '../../src/views/Storage/PvcData'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable fake — faithful to the datatables.net-react quirk that
// bit the Usage column: the real wrapper binds Column render fns to the
// table instance only at INITIALISATION and re-renders cells only when
// the data prop changes. A render fn closing over a second query's data
// goes stale when that query resolves after the list (cell stuck at "—"
// until a remount). The fake therefore captures the column definitions
// on first render and renders the CURRENT data with the CAPTURED render
// fns — join-in-the-row (pure render fns) is the only way cells update,
// exactly like the real component. The factory is async: a hoisted mock
// may not touch module-scope consts, so react is imported inline
// (`vi.mock` calls are hoisted above the imports below).
vi.mock('../../src/components/KubeDataTable', async () => {
  const React = (await import('react')) as typeof import('react')
  const Column = () => null
  type ColProps = { title: string; data: string | null; children?: unknown }
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    // The real wrapper captures the column definitions at table init and
    // never re-reads them — replicate that here.
    const colsRef = React.useRef<ColProps[] | null>(null)
    if (colsRef.current === null) {
      colsRef.current = React.Children.toArray(children)
        .filter(React.isValidElement)
        .map((child) => (child as React.ReactElement<ColProps>).props)
    }
    const cols = colsRef.current
    return (
      <table>
        <thead>
          <tr>
            {cols.map((col) => (
              <th key={col.title}>{col.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, i) => (
            <tr key={i}>
              {cols.map((col) => {
                const value = col.data === null ? row : row[col.data]
                const node =
                  typeof col.children === 'function'
                    ? (col.children as (v: unknown) => React.ReactNode)(value)
                    : (value as React.ReactNode)
                return <td key={col.title}>{node ?? ''}</td>
              })}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

const renderAt = (_ui: ReactElement, path = '/storage/pv') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/pv"
            element={
              <ObjectRoute
                kind="persistentvolume"
                listRoute="/storage/pv"
                list={<PvView />}
                detail={(p) => (<div>pv-detail:{p.name}</div>)}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  sessionStorage.clear()
})

const selectProd = () =>
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })

// kubernetes to_dict shape: snake_case. Cluster-scoped — no namespace field.
const pvA = {
  metadata: { name: 'pv-a', creation_timestamp: '2026-01-02T03:04:05Z' },
  spec: {
    capacity: { storage: '10Gi' },
    claim_ref: { name: 'data-pvc', namespace: 'team-a' },
    storage_class_name: 'csi-fast',
    csi: { driver: 'csi.example.com', fs_type: 'ext4' },
  },
  status: { phase: 'Bound' },
}

const pvFree = {
  ...pvA,
  metadata: { name: 'pv-free' },
  spec: {
    capacity: { storage: '1Gi' },
    host_path: { path: '/var/local-path/pv-free' },
  },
  status: { phase: 'Available' },
}

const pvDel = {
  ...pvA,
  metadata: { name: 'pv-del', deletion_timestamp: '2026-01-03T04:05:06Z' },
  status: { phase: 'Terminating' },
}

// The claim the pvA row points at (the consumer-side test's detail fetch).
const pvcData = {
  metadata: {
    name: 'data-pvc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
  },
  spec: {
    access_modes: ['ReadWriteOnce'],
    volume_mode: 'Filesystem',
    storage_class_name: 'csi-fast',
    volume_name: 'pv-a',
    resources: { requests: { storage: '10Gi' } },
  },
  status: { phase: 'Bound', capacity: { storage: '10Gi' } },
}

// /metrics/pvcs response (the PVC list's observed tier — the PV Usage
// column joins this by claim name).
const usageResponse = (overrides: Record<string, unknown> = {}) => ({
  cluster: 'prod',
  namespace: 'team-a',
  source: 'kubelet stats/summary',
  metrics_available: true,
  metrics_denied: false,
  items: [
    {
      name: 'data-pvc',
      capacity_bytes: 10737418240,
      used_bytes: 4543730954,
      available_bytes: 6193687286,
      percentage_used: 42.3,
    },
  ],
  ...overrides,
})

// Columns: Status(0) / Name(1) / StorageClass(2) / VolumeClaim(3) /
// Capacity(4) / Usage(5) — same shape as pvcs.test.tsx's cellOf.
const cellOf = (name: string, idx: number): string | null => {
  const row = screen.queryByRole('button', { name })?.closest('tr')
  return row?.children[idx]?.textContent ?? null
}

test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvA] }),
    ),
  )
  renderAt(<PvView />)
  const nameButton = await screen.findByRole('button', { name: 'pv-a' })
  await user.click(nameButton)
  expect(await screen.findByText('pv-detail:pv-a')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('list-renders-pvs-with-claim-ns-param', async () => {
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', ({ request }) => {
      requestedUrl = request.url
      return HttpResponse.json({
        kind: 'persistentvolumes',
        cluster: 'prod',
        items: [pvA, pvFree],
      })
    }),
  )
  selectProd()
  renderAt(<PvView />)

  // Await the row so the fetch (and the URL capture) has happened.
  expect(await screen.findByRole('button', { name: 'pv-a' })).toBeTruthy()
  // The claim filter rides in the query (4.1 parity), NOT a scope.
  expect(requestedUrl).toContain(
    '/api/v1/clusters/1/resources/persistentvolumes?namespace=team-a',
  )
  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  expect(screen.getByRole('heading', { name: 'Persistent Volume List' })).toBeTruthy()
  // columns: 4.1's order (Status, Name, StorageClass, VolumeClaim,
  // Capacity) + the 5.0 Usage addition (the PVC list's observed tier).
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Status',
    'Name',
    'StorageClass',
    'VolumeClaim',
    'Capacity',
    'Usage',
  ])
  // row pv-a: Bound success badge, linked storage class + claim, capacity.
  expect(screen.getByText('Bound')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'csi-fast' })).toBeTruthy()
  expect(screen.getByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(screen.getByText('10Gi')).toBeTruthy()
})

// pv-list-terminating-override
test('list-terminating-override', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvDel, pvA] }),
    ),
  )
  selectProd()
  renderAt(<PvView />)

  // The deleting PV shows the danger Terminating badge (the deletion
  // timestamp overrides the displayed status — 4.1's behavior).
  const delRow = (await screen.findByRole('button', { name: 'pv-del' })).closest('tr')
  expect(delRow?.textContent).toContain('Terminating')
  expect(delRow?.querySelector('.badge')?.className).toContain('bg-danger')
})

// pv-list-free-pv-dashes
test('list-free-pv-dashes', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvFree] }),
    ),
  )
  selectProd()
  renderAt(<PvView />)

  // A free PV (no claim_ref, no storage_class_name) renders — in both
  // linked cells AND the Usage cell (free PVs have no claim to join the
  // observed tier against — certainty rule: never guess); capacity still
  // renders.
  const freeRow = (await screen.findByRole('button', { name: 'pv-free' })).closest('tr')
  const dashes = freeRow ? (freeRow.textContent?.match(/—/g) ?? []).length : 0
  expect(dashes).toBe(3)
  expect(freeRow?.textContent).toContain('1Gi')
})

// cross-kind cells open the target kind's ref (the claim ref carries the
// claim's own namespace — R8). Each cell gets its own render: the click
// navigates away from the list route (the target route is unregistered here).
test('storageclass-cell-opens-sc-ref', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvA] }),
    ),
  )
  renderAt(<PvView />)
  await user.click(await screen.findByRole('button', { name: 'csi-fast' }))
  expect(getActiveRef()?.kind).toBe('storageclass')
  expect(getActiveRef()?.name).toBe('csi-fast')
  expect(getActiveRef()?.namespace).toBeUndefined()
})

test('volumeclaim-cell-opens-pvc-ref-with-claim-ns', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ items: [pvA] }),
    ),
  )
  renderAt(<PvView />)
  await user.click(await screen.findByRole('button', { name: 'data-pvc' }))
  // The ref kind is the TARGET route's registry kind ('pvc' — App.tsx
  // ObjectRoute kind="pvc"), not the k8s resource name: ObjectRoute
  // matches ref.kind === kind verbatim (R6).
  expect(getActiveRef()?.kind).toBe('pvc')
  expect(getActiveRef()?.name).toBe('data-pvc')
  expect(getActiveRef()?.namespace).toBe('team-a')
})

// The consumer side of the PV→PVC cross-kind contract (the emit-side test
// above pins only the ref the cell writes): with BOTH routes wired as in
// App.tsx, clicking the claim cell navigates to /storage/pvc and the PVC
// route's ObjectRoute (kind="pvc") renders the claim's DETAIL — not the
// PVC list (R6).
test('volumeclaim-cell-opens-pvc-detail', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes*', () =>
      HttpResponse.json({ items: [pvA] }),
    ),
    http.get(
      '*/api/v1/clusters/1/resources/persistentvolumeclaims?name=data-pvc&namespace=team-a',
      () => HttpResponse.json({ items: [pvcData] }),
    ),
  )
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/storage/pv']}>
        <Routes>
          <Route
            path="/storage/pv"
            element={
              <ObjectRoute
                kind="persistentvolume"
                listRoute="/storage/pv"
                list={<PvView />}
                detail={(p) => (<div>pv-detail:{p.name}</div>)}
              />
            }
          />
          <Route
            path="/storage/pvc"
            element={
              <ObjectRoute
                kind="pvc"
                listRoute="/storage/pvc"
                list={<PvcView />}
                detail={(p) => (<PvcDataView name={p.name} namespace={p.namespace ?? ''} />)}
              />
            }
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  await user.click(await screen.findByRole('button', { name: 'data-pvc' }))
  // The detail renders: the card title is detail-only, and the 'Status:'
  // row label (with colon) is the detail CTable's — the list's table
  // header is 'Status' (no colon), so neither appears when the list
  // renders. Before the kind fix, the kind mismatch fell through to the
  // list and the detail title never appeared.
  await screen.findByText('Persistent Volume Claim Data')
  expect(screen.getByText('Status:')).toBeTruthy()
})

test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  renderAt(<PvView />)
  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// pv-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ kind: 'persistentvolumes', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<PvView />)
  expect(await screen.findByText('No persistent volumes found')).toBeTruthy()
})

// pv-list-usage-join — the Usage column joins /metrics/pvcs by claim name
// (the claim-ns filter means every bound PV shown is bound in the
// selected namespace); a free PV renders "—".
test('list-usage-join', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ kind: 'persistentvolumes', cluster: 'prod', items: [pvA, pvFree] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', ({ request }) => {
      const u = new URL(request.url)
      // The usage fetch carries the SAME namespace as the claim filter —
      // the join is per-ns (the PVC list's contract, mirrored).
      expect(u.searchParams.get('namespace')).toBe('team-a')
      return HttpResponse.json(usageResponse())
    }),
  )
  selectProd()
  renderAt(<PvView />)

  // pv-a is bound to data-pvc, which is in the usage items: one decimal + " %".
  expect(await screen.findByRole('button', { name: 'pv-a' })).toBeTruthy()
  expect(cellOf('pv-a', 5)).toBe('42.3 %')
  // pv-free has no claim_ref: "—".
  expect(await screen.findByRole('button', { name: 'pv-free' })).toBeTruthy()
  expect(cellOf('pv-free', 5)).toBe('—')
})

// pv-list-usage-late-resolution — the observed bug: the usage fetch
// (kubelet fan-out) resolves AFTER the list (informer cache). The
// faithful fake above reproduces datatables.net-react's init-time
// capture, so a render fn closing over the usage query would leave the
// cell stuck at "—" until a remount. The join in the rows (pure render
// fns) must update the cell IN PLACE.
test('list-usage-late-resolution-updates-in-place', async () => {
  let resolveUsage: (v: unknown) => void = () => {}
  const usageGate = new Promise((r) => {
    resolveUsage = r
  })
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ kind: 'persistentvolumes', cluster: 'prod', items: [pvA, pvFree] }),
    ),
    http.get(
      '*/api/v1/clusters/1/metrics/pvcs',
      () => usageGate.then(() => HttpResponse.json(usageResponse())),
    ),
  )
  selectProd()
  renderAt(<PvView />)

  // The rows render before the usage resolves: Usage degrades to "—".
  expect(await screen.findByRole('button', { name: 'pv-a' })).toBeTruthy()
  expect(cellOf('pv-a', 5)).toBe('—')
  expect(cellOf('pv-free', 5)).toBe('—')

  // The usage resolves late: the bound row's cell updates in place
  // (no remount); the free row has no claim to join.
  resolveUsage(undefined)
  await screen.findAllByText('42.3 %')
  expect(cellOf('pv-a', 5)).toBe('42.3 %')
  expect(cellOf('pv-free', 5)).toBe('—')
})

// pv-list-usage-degrades-to-em-dash — the observed tier never fails the
// list: unavailable, denied, or a failed fetch all render "—".
test('list-usage-unavailable-degrades-to-em-dash', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ kind: 'persistentvolumes', items: [pvA] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json(usageResponse({ metrics_available: false, items: [] })),
    ),
  )
  selectProd()
  renderAt(<PvView />)

  expect(await screen.findByRole('button', { name: 'pv-a' })).toBeTruthy()
  expect(cellOf('pv-a', 5)).toBe('—')
})

test('list-usage-denied-degrades-to-em-dash', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ kind: 'persistentvolumes', items: [pvA] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json(usageResponse({ metrics_denied: true, items: [] })),
    ),
  )
  selectProd()
  renderAt(<PvView />)

  expect(await screen.findByRole('button', { name: 'pv-a' })).toBeTruthy()
  expect(cellOf('pv-a', 5)).toBe('—')
})

test('list-usage-fetch-fail-degrades-column-not-list', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumes', () =>
      HttpResponse.json({ kind: 'persistentvolumes', items: [pvA] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json({ error: { code: 'CLUSTER_UNREACHABLE', message: 'stats down' } }, { status: 502 }),
    ),
  )
  selectProd()
  renderAt(<PvView />)

  // The list STILL renders its row; the Usage column degrades to "—"
  // (the usage query's error never surfaces as a list error).
  expect(await screen.findByRole('button', { name: 'pv-a' })).toBeTruthy()
  expect(cellOf('pv-a', 5)).toBe('—')
  expect(screen.queryByText(/Error loading persistent volumes/)).toBeNull()
})
