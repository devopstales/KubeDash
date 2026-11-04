import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import ConfigMapView from '../../src/views/Storage/ConfigMap'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as resource_quotas.test.tsx: renders the real row
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
                    ? // datatables.net-react slotRenderer: a 2-arg slot fn
                      // receives (data, row); 1-arg fns get the data value.
                      (col.children as (v: unknown, r: unknown) => React.ReactNode)(
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
                detail={(p) => (<div>configmap-detail:{p.name}:{p.namespace ?? ''}</div>)}
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

// kubernetes to_dict shape: snake_case, 2 data keys + the kubectl noise
// annotation (rendered verbatim on the data page, not here).
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

// An empty data object: Data Keys is "0" (a valid count, NOT "—").
const emptyCm = {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    name: 'empty-cm',
    namespace: 'team-a',
    creation_timestamp: '2026-01-03T00:00:00Z',
  },
  data: {},
}

// No data field at all: Data Keys is "—" (certainty rule).
const noDataCm = {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    name: 'no-data-cm',
    namespace: 'team-a',
    creation_timestamp: '2026-01-04T00:00:00Z',
  },
}

// Only binaryData (no data field): Data Keys is "—" — the count is
// data-only (4.1's list read projected only `data`).
const binaryOnly = {
  apiVersion: 'v1',
  kind: 'ConfigMap',
  metadata: {
    name: 'binary-only',
    namespace: 'team-a',
    creation_timestamp: '2026-01-05T00:00:00Z',
  },
  binaryData: { icon: 'aWtl' },
}

// The row's own namespace differs from the store's: the openObject ref must
// follow the row, not the store.
const otherNsCm = {
  ...appConfig,
  metadata: { ...appConfig.metadata, name: 'other-cm', namespace: 'other-team' },
}

// The second data cell of a row (columns: Name / Data Keys / Created).
const dataKeysOf = (name: string): string | null => {
  const row = screen.queryByRole('button', { name })?.closest('tr')
  return row ? (row.querySelectorAll('td')[1]?.textContent ?? null) : null
}

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ items: [appConfig] }),
    ),
  )
  renderAt(<ConfigMapView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1). The ref carries the namespace (R8).
  const nameButton = await screen.findByRole('button', { name: 'app-config' })
  await user.click(nameButton)

  expect(await screen.findByText('configmap-detail:app-config:team-a')).toBeTruthy()
  expect(window.location.search).toBe('')
})

// The ref follows the ROW's namespace, not the header's selected one
// (R8: the ref's namespace is authoritative for the data page).
test('click-name-carries-row-namespace', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ items: [otherNsCm] }),
    ),
  )
  renderAt(<ConfigMapView />)

  const nameButton = await screen.findByRole('button', { name: 'other-cm' })
  await user.click(nameButton)

  expect(await screen.findByText('configmap-detail:other-cm:other-team')).toBeTruthy()
  expect(window.location.search).toBe('')
})

test('list-renders-configmap-rows-with-data-links', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'configmaps',
        cluster: 'prod',
        items: [appConfig],
      })
    }),
  )
  selectProd()
  renderAt(<ConfigMapView />)

  // ADR-0040: the name cell is a button (not a Link) — the URL never
  // carries object identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'app-config' })
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/configmaps')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string, 4.1's casing verbatim (the e2e smoke
  // contract). Pinned on the heading: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Configmaps List' })).toBeTruthy()
  // breadcrumb: Storage → Configmaps List.
  expect(screen.getByText('Storage')).toBeTruthy()
  // columns: name (openObject button), data keys, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Data Keys',
    'Created',
  ])
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// configmap-list-data-keys-column
test('list-data-keys-column', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({
        kind: 'configmaps',
        cluster: 'prod',
        items: [appConfig, emptyCm, noDataCm],
      }),
    ),
  )
  selectProd()
  renderAt(<ConfigMapView />)

  // 2 keys → "2"; an EMPTY data object → "0" (a valid count, NOT "—");
  // no data field at all → "—" (certainty rule).
  expect(await screen.findByRole('button', { name: 'app-config' })).toBeTruthy()
  expect(dataKeysOf('app-config')).toBe('2')
  expect(dataKeysOf('empty-cm')).toBe('0')
  expect(dataKeysOf('no-data-cm')).toBe('—')
})

// configmap-list-never-counts-binarydata
test('list-never-counts-binarydata', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ kind: 'configmaps', cluster: 'prod', items: [binaryOnly] }),
    ),
  )
  selectProd()
  renderAt(<ConfigMapView />)

  // The count is data-only: binaryData keys are NOT counted (4.1's list
  // read projected only `data`).
  expect(await screen.findByRole('button', { name: 'binary-only' })).toBeTruthy()
  expect(dataKeysOf('binary-only')).toBe('—')
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
  renderAt(<ConfigMapView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on configmaps' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<ConfigMapView />)

  expect(
    await screen.findByText(/Error loading configmaps: RBAC_DENIED: list on configmaps/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('button', { name: 'app-config' })).toHaveLength(0)
})

// configmap-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/configmaps', () =>
      HttpResponse.json({ kind: 'configmaps', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<ConfigMapView />)

  // first-class empty state, not an error.
  expect(await screen.findByText('No configmaps found')).toBeTruthy()
})
