import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ResourceQuotaView from '../../src/views/OtherResource/ResourceQuota'
import { useClusterStore } from '../../src/store/cluster'

// Same KubeDataTable fake as network_policies.test.tsx: renders the real row
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

const renderAt = (ui: ReactElement, path = '/other-resource/resource-quota') => {
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

// kubernetes to_dict shape: snake_case, all four 4.1 dimensions present.
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

// No cpu/memory keys in status (an object-count quota): every 4.1
// dimension is missing (the 4.1 template would KeyError).
const objects = {
  apiVersion: 'v1',
  kind: 'ResourceQuota',
  metadata: {
    name: 'objects',
    namespace: 'team-a',
    creation_timestamp: '2026-01-03T04:05:06Z',
    labels: {},
    annotations: {},
  },
  spec: {
    hard: { pods: '20' },
  },
  status: {
    hard: { pods: '20' },
    used: { pods: '10' },
  },
}

// list-renders-rows-with-data-links
test('list-renders-resource-quotas-with-data-links', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'resourcequotas',
        cluster: 'prod',
        items: [compute],
      })
    }),
  )
  selectProd()
  renderAt(<ResourceQuotaView />)

  const link = await screen.findByRole('link', { name: 'compute' })
  // the list view is the sole producer of the data page's query strings.
  expect(link.getAttribute('href')).toBe(
    '/other-resource/resource-quota/data?name=compute&namespace=team-a',
  )
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/resourcequotas')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Resource Quota List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Other Resources → Resource Quota List.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns: name, namespace, request/limit badge pairs, created.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Requests',
    'Limits',
    'Created',
  ])
  const nameCell = link.closest('tr')
  // row: the namespace is shown (the namespaced kind).
  expect(nameCell?.textContent).toContain('team-a')
  // created: local time (no raw ISO 'T'), rendered by formatTimestamp.
  expect(nameCell?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(nameCell?.textContent).toMatch(/2026/)
})

// list-request-limit-cells
test('list-request-limit-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', () =>
      HttpResponse.json({ kind: 'resourcequotas', cluster: 'prod', items: [compute] }),
    ),
  )
  selectProd()
  renderAt(<ResourceQuotaView />)

  const nameCell = (await screen.findByRole('link', { name: 'compute' })).closest('tr')
  // 4.1's badge pairs: `<key>: <used> / <hard>`, one line per dimension.
  expect(nameCell?.textContent).toContain('requests.cpu: 2 / 4')
  expect(nameCell?.textContent).toContain('requests.memory: 4Gi / 10Gi')
  expect(nameCell?.textContent).toContain('limits.cpu: 4 / 8')
  expect(nameCell?.textContent).toContain('limits.memory: 8Gi / 20Gi')
})

// list-missing-status-keys
test('list-missing-status-keys', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', () =>
      HttpResponse.json({ kind: 'resourcequotas', cluster: 'prod', items: [objects] }),
    ),
  )
  selectProd()
  renderAt(<ResourceQuotaView />)

  const nameCell = (await screen.findByRole('link', { name: 'objects' })).closest('tr')
  // certainty rule: a key missing from status.used or status.hard renders
  // "—" — 4.1 would KeyError the template; 5.0 never guesses.
  expect(nameCell?.textContent).toContain('limits.cpu: — / —')
  expect(nameCell?.textContent).toContain('requests.memory: — / —')
  expect(nameCell?.textContent).not.toContain('undefined')
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
  renderAt(<ResourceQuotaView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on resourcequotas' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<ResourceQuotaView />)

  expect(
    await screen.findByText(/Error loading resource quotas: RBAC_DENIED: list on resourcequotas/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('link', { name: 'compute' })).toHaveLength(0)
})

// list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/resourcequotas', () =>
      HttpResponse.json({ kind: 'resourcequotas', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<ResourceQuotaView />)

  // first-class empty state, not an error.
  expect(await screen.findByText('No resource quotas found')).toBeTruthy()
})
