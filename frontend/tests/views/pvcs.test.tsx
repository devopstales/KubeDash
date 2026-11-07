import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import PvcView from '../../src/views/Storage/Pvc'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// faithful to the datatables.net-react quirk that bit the Usage column:
// the real wrapper binds Column render fns to the table instance only at
// INITIALISATION and re-renders cells only when the data prop changes. A
// render fn closing over a second query's data goes stale when that query
// resolves after the list (cell stuck at "—" until a remount). The fake
// therefore captures the column definitions on first render and renders
// the CURRENT data with the CAPTURED render fns — join-in-the-row (pure
// render fns) is the only way cells update, exactly like the real
// component.
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity). The
// data view lands with Task 4 of this change; this file pins the list-side
// contract with an inline detail marker, so it does not import the data view.
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
                detail={(p) => (<div>pvc-detail:{p.name}:{p.namespace ?? ''}</div>)}
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

// An unbound claim: Pending, no volume_name (no volume yet), no capacity.
const unboundPvc = {
  metadata: {
    name: 'unbound-pvc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-03T00:00:00Z',
  },
  spec: { storage_class_name: 'csi-fast', access_modes: ['ReadWriteOnce'] },
  status: { phase: 'Pending' },
}

// The Terminating badge tier (4.1's danger pair).
const terminatingPvc = {
  ...boundPvc,
  metadata: { ...boundPvc.metadata, name: 'terminating-pvc' },
  status: { phase: 'Terminating', capacity: { storage: '10Gi' } },
}

// No phase at all: the "—" absent tier (certainty rule).
const barePvc = {
  metadata: {
    name: 'bare-pvc',
    namespace: 'team-a',
    creation_timestamp: '2026-01-04T00:00:00Z',
  },
  spec: {},
  status: {},
}

// The row's own namespace differs from the store's: the openObject ref must
// follow the row, not the store.
const otherNsPvc = {
  ...boundPvc,
  metadata: { ...boundPvc.metadata, name: 'other-pvc', namespace: 'other-team' },
}

// One usage entry (the list's Usage column is joined by PVC name).
const USAGE_ITEMS = [
  {
    name: 'data-pvc',
    capacity_bytes: 10737418240,
    used_bytes: 4529848320,
    available_bytes: 6207569920,
    percentage_used: 42.3,
  },
]

const usageResponse = (overrides: Record<string, unknown> = {}) => ({
  cluster: 'prod',
  namespace: 'team-a',
  source: 'kubelet stats/summary',
  metrics_available: true,
  metrics_denied: false,
  items: USAGE_ITEMS,
  ...overrides,
})

// Columns: Status / Name / StorageClass / Volume / Capacity / Usage / Created.
const cellOf = (name: string, idx: number): string | null => {
  const row = screen.queryByRole('button', { name })?.closest('tr')
  return row ? (row.querySelectorAll('td')[idx]?.textContent ?? null) : null
}

// The Status cell's badge class (bg-success / bg-danger / bg-warning) — null
// for the absent "—" tier (no badge).
const statusBadgeOf = (name: string): string | null => {
  const row = screen.queryByRole('button', { name })?.closest('tr')
  const cell = row?.querySelectorAll('td')[0]
  return cell?.querySelector('.badge')?.className ?? null
}

// pvc-list-clicks-open-detail-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', items: [boundPvc] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json(usageResponse()),
    ),
  )
  renderAt(<PvcView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1). The ref carries the namespace (R8).
  const nameButton = await screen.findByRole('button', { name: 'data-pvc' })
  await user.click(nameButton)

  expect(await screen.findByText('pvc-detail:data-pvc:team-a')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// The ref follows the ROW's namespace, not the header's selected one
// (R8: the ref's namespace is authoritative for the data page).
test('click-name-carries-row-namespace', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', items: [otherNsPvc] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json(usageResponse()),
    ),
  )
  renderAt(<PvcView />)

  const nameButton = await screen.findByRole('button', { name: 'other-pvc' })
  await user.click(nameButton)

  expect(await screen.findByText('pvc-detail:other-pvc:other-team')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// pvc-list-renders-rows-with-data-links
test('list-renders-pvc-rows', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'persistentvolumeclaims',
        cluster: 'prod',
        items: [boundPvc],
      })
    }),
    http.get('*/api/v1/clusters/1/metrics/pvcs', ({ request }) => {
      const u = new URL(request.url)
      // The usage fetch carries the same namespace (the join is per-ns).
      expect(u.searchParams.get('namespace')).toBe('team-a')
      return HttpResponse.json(usageResponse())
    }),
  )
  selectProd()
  renderAt(<PvcView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL never
  // carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'data-pvc' })
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/persistentvolumeclaims')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke contract). Pinned on the
  // heading: the breadcrumb renders the same text, and a card-title
  // regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Persistent Volume Claim List' })).toBeTruthy()
  // breadcrumb: Storage → Persistent Volume Claim List.
  expect(screen.getByText('Storage')).toBeTruthy()
  // columns: status, name (openObject button), storageclass, volume,
  // capacity, usage, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Status',
    'Name',
    'StorageClass',
    'Volume',
    'Capacity',
    'Usage',
    'Created',
  ])
  // the 4.1 list cells render the spec/status values.
  expect(cellOf('data-pvc', 2)).toBe('csi-fast')
  expect(cellOf('data-pvc', 3)).toBe('pv-1')
  expect(cellOf('data-pvc', 4)).toBe('10Gi')
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// pvc-list-status-phase-badges — 4.1's three-tier badge pair.
test('list-status-phase-badges', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({
        kind: 'persistentvolumeclaims',
        cluster: 'prod',
        items: [boundPvc, unboundPvc, terminatingPvc, barePvc],
      }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () => HttpResponse.json(usageResponse())),
  )
  selectProd()
  renderAt(<PvcView />)

  // Bound → success badge.
  expect(await screen.findByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(cellOf('data-pvc', 0)).toBe('Bound')
  expect(statusBadgeOf('data-pvc')).toContain('bg-success')
  // Pending → warning badge (the "everything else" tier).
  expect(await screen.findByRole('button', { name: 'unbound-pvc' })).toBeTruthy()
  expect(cellOf('unbound-pvc', 0)).toBe('Pending')
  expect(statusBadgeOf('unbound-pvc')).toContain('bg-warning')
  // Terminating → danger badge.
  expect(await screen.findByRole('button', { name: 'terminating-pvc' })).toBeTruthy()
  expect(cellOf('terminating-pvc', 0)).toBe('Terminating')
  expect(statusBadgeOf('terminating-pvc')).toContain('bg-danger')
  // no phase → "—" with no badge (certainty rule).
  expect(await screen.findByRole('button', { name: 'bare-pvc' })).toBeTruthy()
  expect(cellOf('bare-pvc', 0)).toBe('—')
  expect(statusBadgeOf('bare-pvc')).toBeNull()
})

// pvc-list-usage-join — the second fetch joined by PVC name.
test('list-usage-join', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({
        kind: 'persistentvolumeclaims',
        cluster: 'prod',
        items: [boundPvc, unboundPvc],
      }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () => HttpResponse.json(usageResponse())),
  )
  selectProd()
  renderAt(<PvcView />)

  // data-pvc is in the usage items: percentage one-decimal + " %".
  expect(await screen.findByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(cellOf('data-pvc', 5)).toBe('42.3 %')
  // unbound-pvc is ABSENT from the usage items (no pods using it): "—".
  expect(await screen.findByRole('button', { name: 'unbound-pvc' })).toBeTruthy()
  expect(cellOf('unbound-pvc', 5)).toBe('—')
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
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({
        kind: 'persistentvolumeclaims',
        items: [boundPvc, unboundPvc],
      }),
    ),
    http.get(
      '*/api/v1/clusters/1/metrics/pvcs',
      () => usageGate.then(() => HttpResponse.json(usageResponse())),
    ),
  )
  selectProd()
  renderAt(<PvcView />)

  // The rows render before the usage resolves: Usage degrades to "—".
  expect(await screen.findByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(cellOf('data-pvc', 5)).toBe('—')
  expect(cellOf('unbound-pvc', 5)).toBe('—')

  // The usage resolves late: the cell updates in place (no remount).
  resolveUsage(undefined)
  await screen.findAllByText('42.3 %')
  expect(cellOf('data-pvc', 5)).toBe('42.3 %')
  expect(cellOf('unbound-pvc', 5)).toBe('—') // still absent from the items
})

// pvc-list-usage-degrades-to-em-dash — the observed tier never fails the
// list: unavailable, denied, or a failed fetch all render "—".
test('list-usage-unavailable-degrades-to-em-dash', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', items: [boundPvc] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json(usageResponse({ metrics_available: false, items: [] })),
    ),
  )
  selectProd()
  renderAt(<PvcView />)

  expect(await screen.findByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(cellOf('data-pvc', 5)).toBe('—')
})

test('list-usage-denied-degrades-to-em-dash', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', items: [boundPvc] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json(usageResponse({ metrics_denied: true, items: [] })),
    ),
  )
  selectProd()
  renderAt(<PvcView />)

  expect(await screen.findByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(cellOf('data-pvc', 5)).toBe('—')
})

test('list-usage-fetch-fail-degrades-column-not-list', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', items: [boundPvc] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () =>
      HttpResponse.json({ error: { code: 'CLUSTER_UNREACHABLE', message: 'stats down' } }, { status: 502 }),
    ),
  )
  selectProd()
  renderAt(<PvcView />)

  // The list STILL renders its row; the Usage column degrades to "—"
  // (the usage query's error never surfaces as a list error).
  expect(await screen.findByRole('button', { name: 'data-pvc' })).toBeTruthy()
  expect(cellOf('data-pvc', 5)).toBe('—')
  expect(screen.queryByText(/Error loading persistent volume claims/)).toBeNull()
})

// pvc-list-missing-fields — absent keys render "—" (no crash).
test('list-missing-fields', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', items: [unboundPvc] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () => HttpResponse.json(usageResponse())),
  )
  selectProd()
  renderAt(<PvcView />)

  expect(await screen.findByRole('button', { name: 'unbound-pvc' })).toBeTruthy()
  expect(cellOf('unbound-pvc', 2)).toBe('csi-fast') // storage_class_name present
  expect(cellOf('unbound-pvc', 3)).toBe('—') // no volume_name
  expect(cellOf('unbound-pvc', 4)).toBe('—') // no capacity
})

// pvc-list-no-cluster — no fetch is made.
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
    http.get('*/api/v1/clusters/:id/metrics/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json(usageResponse())
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<PvcView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // neither fetch is made
})

// pvc-list-error-state — a LIST error is an error line (the usage column
// is a different tier; the list fetch is not).
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on persistentvolumeclaims' } },
        { status: 403 },
      ),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () => HttpResponse.json(usageResponse())),
  )
  selectProd()
  renderAt(<PvcView />)

  expect(
    await screen.findByText(/Error loading persistent volume claims: RBAC_DENIED: list on persistentvolumeclaims/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'data-pvc' })).toHaveLength(0)
})

// pvc-list-empty-state — first-class, not an error.
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/persistentvolumeclaims', () =>
      HttpResponse.json({ kind: 'persistentvolumeclaims', cluster: 'prod', items: [] }),
    ),
    http.get('*/api/v1/clusters/1/metrics/pvcs', () => HttpResponse.json(usageResponse())),
  )
  selectProd()
  renderAt(<PvcView />)

  expect(await screen.findByText('No persistent volume claims found')).toBeTruthy()
})
