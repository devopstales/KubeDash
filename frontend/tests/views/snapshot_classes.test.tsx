import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import SnapshotClassView from '../../src/views/Storage/SnapshotClass'
import { useClusterStore } from '../../src/store/cluster'

// KubeDataTable is faked in ../components/kube-data-table.test-utils.tsx —
// the fleet's shared fake (the factory is async: a hoisted mock may not
// touch module-scope consts, so the shared module is imported inside it).
vi.mock('../../src/components/KubeDataTable', async () => {
  const utils = await import('../components/kube-data-table.test-utils')
  return { default: utils.KubeDataTable, Column: utils.Column }
})

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity). The
// data view lands with Task 3 of this change; this file pins the list-side
// contract with an inline detail marker, so it does not import the data view.
const renderAt = (_ui: ReactElement, path = '/storage/snapshot-class') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/storage/snapshot-class"
            element={
              <ObjectRoute
                kind="snapshotclass"
                listRoute="/storage/snapshot-class"
                list={<SnapshotClassView />}
                detail={(p) => (<div>snapshot-class-detail:{p.name}</div>)}
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

// Custom-object wire form: camelCase. Cluster-scoped — no namespace field.
const csiDefault = {
  apiVersion: 'snapshot.storage.k8s.io/v1',
  kind: 'VolumeSnapshotClass',
  metadata: {
    name: 'csi-default',
    creationTimestamp: '2026-01-02T03:04:05Z',
    annotations: { 'snapshot.storage.kubernetes.io/is-default-class': 'true' },
    labels: { team: 'a' },
  },
  driver: 'csi-driver.example.com',
  deletionPolicy: 'Delete',
  parameters: { blockVolume: 'true', fstype: 'ext4' },
}

// no is-default-class annotation, no deletionPolicy, no driver —
// those three cells render an em dash (parameters stays: it is not a column).
const bareSc = {
  ...csiDefault,
  metadata: { ...csiDefault.metadata, name: 'bare', annotations: {} },
  deletionPolicy: undefined,
  driver: undefined,
}

// snapshot-class-list-renders-rows-with-data-links

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshotclasses', () =>
      HttpResponse.json({ items: [csiDefault] }),
    ),
  )
  renderAt(<SnapshotClassView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'csi-default' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched) and the URL is
  // clean: no query string (R1).
  expect(await screen.findByText('snapshot-class-detail:csi-default')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('list-renders-snapshot-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshotclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'volumesnapshotclasses',
        cluster: 'prod',
        items: [csiDefault],
      })
    }),
  )
  selectProd()
  renderAt(<SnapshotClassView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL
  // never carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'csi-default' })
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/volumesnapshotclasses')
  expect(requestedUrl).not.toContain('namespace')

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Snapshot Classes List' })).toBeTruthy()
  // breadcrumb: Storage → Snapshot Classes List.
  expect(screen.getByText('Storage')).toBeTruthy()
  // columns: name, default, deletion policy, driver, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Default',
    'Deletion Policy',
    'Driver',
    'Created',
  ])
  // row: Default = the is-default-class annotation value, Deletion Policy =
  // deletionPolicy, Driver = driver.
  expect(screen.getByText('true')).toBeTruthy()
  expect(screen.getByText('Delete')).toBeTruthy()
  expect(screen.getByText('csi-driver.example.com')).toBeTruthy()
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// snapshot-class-list-missing-fields
test('list-missing-fields', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshotclasses', () =>
      HttpResponse.json({
        kind: 'volumesnapshotclasses',
        cluster: 'prod',
        items: [csiDefault, bareSc],
      }),
    ),
  )
  selectProd()
  renderAt(<SnapshotClassView />)

  // the first row renders the real values...
  expect(await screen.findByText('csi-driver.example.com')).toBeTruthy()
  // ...the second row (no is-default-class annotation, no deletionPolicy,
  // no driver) renders the em dash in all three cells
  // (certainty rule: never guess).
  const bareRow = screen.getByRole('button', { name: 'bare' }).closest('tr')
  const dashes = bareRow ? (bareRow.textContent?.match(/—/g) ?? []).length : 0
  expect(dashes).toBe(3)
})

// list-no-cluster-state
test('list-no-cluster-state', async () => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  renderAt(<SnapshotClassView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshotclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on volumesnapshotclasses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<SnapshotClassView />)

  expect(
    await screen.findByText(/Error loading snapshot classes: RBAC_DENIED: list on volumesnapshotclasses/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'csi-default' })).toHaveLength(0)
})

// snapshot-class-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/volumesnapshotclasses', () =>
      HttpResponse.json({ kind: 'volumesnapshotclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<SnapshotClassView />)

  expect(await screen.findByText('No snapshot classes found')).toBeTruthy()
})
