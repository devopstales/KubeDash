import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import VolumeSnapshotView from '../../src/views/Storage/VolumeSnapshot'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as configmaps.test.tsx: renders the real row
// mapping (children-as-render-fns included) so cell assertions test the
// view's `toRow` output, not DataTables' DOM. The factory is async: a
// hoisted mock may not touch module-scope consts, so react is imported
// inline (`vi.mock` calls are hoisted above the imports below).
vi.mock('../../src/components/KubeDataTable', async () => {
  const React = (await import('react')) as typeof import('react')
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    const cols = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map(
        (child) =>
          (
            child as React.ReactElement<{
              title: string
              data: string | null
              children?: unknown
            }>
          ).props,
      )
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
                    ? (col.children as (v: unknown, r: unknown) => React.ReactNode)(
                        value,
                        row,
                      )
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

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity). The
// data view lands with Task 3 of this change; this file pins the list-side
// contract with an inline detail marker, so it does not import the data view.
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
                detail={(p) => (<div>volumesnapshot-detail:{p.name}:{p.namespace ?? ''}</div>)}
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

// Full custom object (camelCase wire form, spec + status intact).
const snapA = {
  apiVersion: 'snapshot.storage.k8s.io/v1',
  kind: 'VolumeSnapshot',
  metadata: {
    name: 'snap-a',
    namespace: 'team-a',
    creationTimestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
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

// readyToUse: false → the danger "Not Ready" badge tier.
const snapNotReady = {
  ...snapA,
  metadata: { ...snapA.metadata, name: 'snap-not-ready' },
  status: { ...snapA.status, readyToUse: false },
}

// A SourceMode-less snapshot (4.1's deep-index 500 case): no
// persistentVolumeClaimName, no volumeSnapshotClassName, no status.
const bareSnap = {
  apiVersion: 'snapshot.storage.k8s.io/v1',
  kind: 'VolumeSnapshot',
  metadata: {
    name: 'bare-snap',
    namespace: 'team-a',
    creationTimestamp: '2026-01-06T00:00:00Z',
    annotations: {},
  },
  spec: { source: {} },
  status: {},
}

// The row's own namespace differs from the store's: the openObject ref must
// follow the row, not the store.
const otherNsSnap = {
  ...snapA,
  metadata: { ...snapA.metadata, name: 'other-snap', namespace: 'other-team' },
}

// Cell text of a row by column index (columns: Name / Usable /
// SnapshotClass / VolumeClaim / Restore Size / Created).
const cellOf = (name: string, idx: number): string | null => {
  const row = screen.queryByRole('button', { name })?.closest('tr')
  return row ? (row.querySelectorAll('td')[idx]?.textContent ?? null) : null
}

// The Usable cell's badge class (badge-success / badge-danger) — null for
// the absent "—" tier (no badge).
const usableBadgeOf = (name: string): string | null => {
  const row = screen.queryByRole('button', { name })?.closest('tr')
  const cell = row?.querySelectorAll('td')[1]
  return cell?.querySelector('.badge')?.className ?? null
}

// volumesnapshot-list-clicks-open-detail-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({ items: [snapA] }),
    ),
  )
  renderAt(<VolumeSnapshotView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1). The ref carries the namespace (R8).
  const nameButton = await screen.findByRole('button', { name: 'snap-a' })
  await user.click(nameButton)

  expect(await screen.findByText('volumesnapshot-detail:snap-a:team-a')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// The ref follows the ROW's namespace, not the header's selected one
// (R8: the ref's namespace is authoritative for the data page).
test('click-name-carries-row-namespace', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({ items: [otherNsSnap] }),
    ),
  )
  renderAt(<VolumeSnapshotView />)

  const nameButton = await screen.findByRole('button', { name: 'other-snap' })
  await user.click(nameButton)

  expect(await screen.findByText('volumesnapshot-detail:other-snap:other-team')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// volumesnapshot-list-renders-rows-with-data-links
test('list-renders-snapshot-rows', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'volumesnapshots',
        cluster: 'prod',
        items: [snapA],
      })
    }),
  )
  selectProd()
  renderAt(<VolumeSnapshotView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL never
  // carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'snap-a' })
  // the namespaced fetch EXACTLY: cluster path + the header's namespace
  // (a fix for 4.1's hardcoded all-namespaces read).
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/volumesnapshots')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke contract). Pinned on the
  // heading: the breadcrumb renders the same text, and a card-title
  // regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Volume Snapshot List' })).toBeTruthy()
  // breadcrumb: Storage → Volume Snapshot List.
  expect(screen.getByText('Storage')).toBeTruthy()
  // columns: name (openObject button), usable, snapshotclass, volumeclaim,
  // restore size, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Usable',
    'SnapshotClass',
    'VolumeClaim',
    'Restore Size',
    'Created',
  ])
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// volumesnapshot-list-ready-class-pvc-cells
test('list-ready-class-pvc-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({
        kind: 'volumesnapshots',
        cluster: 'prod',
        items: [snapA, snapNotReady],
      }),
    ),
  )
  selectProd()
  renderAt(<VolumeSnapshotView />)

  // snap-a: readyToUse true → success "Ready" badge; the 4.1 list columns
  // render the deep-indexed values (no KeyError on a well-formed snapshot).
  expect(await screen.findByRole('button', { name: 'snap-a' })).toBeTruthy()
  expect(cellOf('snap-a', 1)).toBe('Ready')
  expect(usableBadgeOf('snap-a')).toContain('bg-success')
  expect(cellOf('snap-a', 2)).toBe('csi-snap')
  expect(cellOf('snap-a', 3)).toBe('pvc-snap-a')
  expect(cellOf('snap-a', 4)).toBe('1Gi')

  // snap-not-ready: readyToUse false → danger "Not Ready" badge.
  expect(await screen.findByRole('button', { name: 'snap-not-ready' })).toBeTruthy()
  expect(cellOf('snap-not-ready', 1)).toBe('Not Ready')
  expect(usableBadgeOf('snap-not-ready')).toContain('bg-danger')
})

// volumesnapshot-list-missing-fields — the 4.1 deep-index 500 is fixed:
// a SourceMode-less snapshot renders "—" for every absent key (no crash).
test('list-missing-fields', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({
        kind: 'volumesnapshots',
        cluster: 'prod',
        items: [bareSnap],
      }),
    ),
  )
  selectProd()
  renderAt(<VolumeSnapshotView />)

  expect(await screen.findByRole('button', { name: 'bare-snap' })).toBeTruthy()
  expect(cellOf('bare-snap', 1)).toBe('—') // no readyToUse
  expect(cellOf('bare-snap', 2)).toBe('—') // no volumeSnapshotClassName
  expect(cellOf('bare-snap', 3)).toBe('—') // no persistentVolumeClaimName
  expect(cellOf('bare-snap', 4)).toBe('—') // no restoreSize
  // the absent tier renders no badge.
  expect(usableBadgeOf('bare-snap')).toBeNull()
})

// list-no-cluster-state
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<VolumeSnapshotView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on volumesnapshots' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<VolumeSnapshotView />)

  expect(
    await screen.findByText(/Error loading volume snapshots: RBAC_DENIED: list on volumesnapshots/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'snap-a' })).toHaveLength(0)
})

// volumesnapshot-list-empty-state — ALSO the CRD-absent state (same copy).
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshots', () =>
      HttpResponse.json({ kind: 'volumesnapshots', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<VolumeSnapshotView />)

  // first-class empty state, not an error (the snapshot operator may be
  // absent; the read degrades to []).
  expect(await screen.findByText('No volume snapshots found')).toBeTruthy()
})
