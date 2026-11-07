import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import StorageClassView from '../../src/views/Storage/StorageClass'
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
                detail={(p) => (<div>storage-class-detail:{p.name}</div>)}
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

// no is-default-class annotation, no reclaim_policy, no volume_binding_mode —
// those three cells render an em dash (provisioner stays: it is not a column).
const bareSc = {
  ...csiFast,
  metadata: { ...csiFast.metadata, name: 'bare', annotations: {} },
  reclaim_policy: undefined,
  volume_binding_mode: undefined,
}

// storage-class-list-renders-rows-with-data-links

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', () =>
      HttpResponse.json({ items: [csiFast] }),
    ),
  )
  renderAt(<StorageClassView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'csi-fast' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched) and the URL is
  // clean: no query string (R1).
  expect(await screen.findByText('storage-class-detail:csi-fast')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('list-renders-storage-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'storageclasses',
        cluster: 'prod',
        items: [csiFast],
      })
    }),
  )
  selectProd()
  renderAt(<StorageClassView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL
  // never carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'csi-fast' })
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/storageclasses')
  expect(requestedUrl).not.toContain('namespace')

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Storage Classes List' })).toBeTruthy()
  // breadcrumb: Storage → Storage Classes List.
  expect(screen.getByText('Storage')).toBeTruthy()
  // columns: name, default, reclaim policy, volume binding mode, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Default',
    'Reclaim Policy',
    'Volume Binding Mode',
    'Created',
  ])
  // row: Default = the is-default-class annotation value, Reclaim Policy =
  // reclaim_policy, Volume Binding Mode = volume_binding_mode.
  expect(screen.getByText('true')).toBeTruthy()
  expect(screen.getByText('Delete')).toBeTruthy()
  expect(screen.getByText('WaitForFirstConsumer')).toBeTruthy()
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// storage-class-list-missing-fields
test('list-missing-fields', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', () =>
      HttpResponse.json({
        kind: 'storageclasses',
        cluster: 'prod',
        items: [csiFast, bareSc],
      }),
    ),
  )
  selectProd()
  renderAt(<StorageClassView />)

  // the first row renders the real values...
  expect(await screen.findByText('WaitForFirstConsumer')).toBeTruthy()
  // ...the second row (no is-default-class annotation, no reclaim_policy,
  // no volume_binding_mode) renders the em dash in all three cells
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
  renderAt(<StorageClassView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on storageclasses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<StorageClassView />)

  expect(
    await screen.findByText(/Error loading storage classes: RBAC_DENIED: list on storageclasses/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'csi-fast' })).toHaveLength(0)
})

// storage-class-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/storageclasses', () =>
      HttpResponse.json({ kind: 'storageclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<StorageClassView />)

  expect(await screen.findByText('No storage classes found')).toBeTruthy()
})
