import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import RuntimeClassView from '../../src/views/OtherResource/RuntimeClass'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as priority_classes.test.tsx: renders the real row
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
                // `data={null}` hands the render fn the whole row (the
                // datatables.net-react contract, see Namespaces.tsx).
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

const renderAt = (ui: ReactElement, path = '/other-resource/runtimeclass') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
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
const runc = {
  apiVersion: 'node.k8s.io/v1',
  kind: 'RuntimeClass',
  metadata: {
    name: 'runc',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { provider: 'docker' },
  },
  handler: 'runc',
  overwrite_node_sel_no_toleration: false,
  scheduling: { node_selector: { 'kubernetes.io/runtime': 'runc' }, tolerations: [] },
  pod_level_overhead: { memory: '128Mi', cpu: '100m' },
}

// no overhead: pod_level_overhead absent — the cell renders an em dash.
const gvisor = {
  apiVersion: 'node.k8s.io/v1',
  kind: 'RuntimeClass',
  metadata: {
    name: 'gvisor',
    creation_timestamp: '2026-01-02T03:04:05Z',
  },
  handler: 'runsc',
  overwrite_node_sel_no_toleration: true,
  scheduling: { node_selector: {}, tolerations: [] },
}

// runtimeclass-list-renders-rows-with-data-links
test('list-renders-runtime-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/runtimeclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'runtimeclasses',
        cluster: 'prod',
        items: [runc],
      })
    }),
  )
  selectProd()
  renderAt(<RuntimeClassView />)

  const link = await screen.findByRole('link', { name: 'runc' })
  expect(link.getAttribute('href')).toBe('/other-resource/runtimeclass/data?name=runc')
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/runtimeclasses')
  expect(requestedUrl).not.toContain('namespace')

  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'Runtime Classes' })).toBeTruthy()
  // breadcrumb: Other Resources → Runtime Classes.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns: name, handler, overwrite flag, overhead, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Handler',
    'Overwrite Node Sel No Toleration',
    'Pod Level Overhead',
    'Created',
  ])
  // row: handler, overwrite flag, overhead.
  expect(screen.getByText('false')).toBeTruthy()
  expect(screen.getByText('100m / 128Mi')).toBeTruthy()
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  const nameCell = link.closest('tr')
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// runtimeclass-list-overhead-rendering
test('list-overhead-absent-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/runtimeclasses', () =>
      HttpResponse.json({
        kind: 'runtimeclasses',
        cluster: 'prod',
        items: [runc, gvisor],
      }),
    ),
  )
  selectProd()
  renderAt(<RuntimeClassView />)

  // the first row renders the compact cpu / memory form; the second row
  // (no pod_level_overhead) renders an em dash.
  expect(await screen.findByText('100m / 128Mi')).toBeTruthy()
  const dashCells = screen.getAllByText('—')
  expect(dashCells.length).toBeGreaterThanOrEqual(1)
  const gvisorRow = screen.getByRole('link', { name: 'gvisor' }).closest('tr')
  expect(gvisorRow?.textContent).toContain('—')
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
  renderAt(<RuntimeClassView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/runtimeclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on runtimeclasses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<RuntimeClassView />)

  expect(
    await screen.findByText(/Error loading runtime classes: RBAC_DENIED: list on runtimeclasses/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('link', { name: 'runc' })).toHaveLength(0)
})

// runtimeclass-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/runtimeclasses', () =>
      HttpResponse.json({ kind: 'runtimeclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<RuntimeClassView />)

  expect(await screen.findByText('No runtime classes found')).toBeTruthy()
})
