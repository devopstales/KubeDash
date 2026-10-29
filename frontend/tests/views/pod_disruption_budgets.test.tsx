import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import PodDisruptionBudgetView from '../../src/views/OtherResource/PodDisruptionBudget'
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

const renderAt = (ui: ReactElement, path = '/other-resource/pod-disruption-budget') => {
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

// kubernetes to_dict shape: snake_case, min_available set, status present.
const web = {
  apiVersion: 'policy/v1',
  kind: 'PodDisruptionBudget',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: { 'pdb.kubernetes.io/managed-by': 'kubedash' },
  },
  spec: {
    min_available: 3,
    selector: { match_labels: { app: 'web' } },
    unhealthy_pod_eviction_policy: 'AlwaysAllow',
  },
  status: {
    observed_generation: 1,
    current_healthy: 4,
    desired: 3,
    total_pods: 4,
    expected_pods: 3,
    disruptions_allowed: 1,
    conditions: [
      {
        type: 'Available',
        status: 'True',
        reason: 'SufficientPods',
        message: 'PodDisruptionBudget is available',
      },
    ],
  },
}

// max_unavailable instead of min_available (the k8s API enforces exactly
// one of the pair). Named so the row can be found by its link.
const maxBudget = {
  ...web,
  metadata: { ...web.metadata, name: 'max-budget' },
  spec: { ...web.spec, min_available: undefined, max_unavailable: 1 },
}
// A fresh PDB has no status (the controller fills it); 4.1's Jinja would
// UndefinedError on `status.disruptions_allowed`.
const freshBudget = { ...web, status: undefined }

// pdb-list-renders-rows-with-data-links
test('list-renders-pdb-rows-with-data-links', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'poddisruptionbudgets',
        cluster: 'prod',
        items: [web],
      })
    }),
  )
  selectProd()
  renderAt(<PodDisruptionBudgetView />)

  const link = await screen.findByRole('link', { name: 'web' })
  // the list view is the sole producer of the data page's query strings.
  expect(link.getAttribute('href')).toBe(
    '/other-resource/pod-disruption-budget/data?name=web&namespace=team-a',
  )
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/poddisruptionbudgets')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Pod Disruption Budget List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Other Resources → Pod Disruption Budget List.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns: name, namespace, the 4.1 trio.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Min Available',
    'Max Unavailable',
    'Allowed Disruptions',
  ])
  const nameCell = link.closest('tr')
  // row: the namespace is shown (the namespaced kind).
  expect(nameCell?.textContent).toContain('team-a')
})

// pdb-list-min-max-cells
test('list-min-max-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json({
        kind: 'poddisruptionbudgets',
        cluster: 'prod',
        items: [web, maxBudget],
      }),
    ),
  )
  selectProd()
  renderAt(<PodDisruptionBudgetView />)

  // The k8s API enforces exactly one of min_available/max_unavailable; the
  // absent one renders "—" (certainty rule: 4.1 rendered blank). Check the
  // exact Min Available / Max Unavailable cells.
  const cells = (tr: Element | null) => Array.from(tr?.querySelectorAll('td') ?? [])
  const webRow = (await screen.findByRole('link', { name: 'web' })).closest('tr')
  expect(cells(webRow).map((td) => td.textContent)).toEqual([
    'web',
    'team-a',
    '3', // Min Available
    '—', // Max Unavailable: absent
    '1', // Allowed Disruptions
  ])

  const maxRow = (await screen.findByRole('link', { name: 'max-budget' })).closest('tr')
  expect(cells(maxRow).map((td) => td.textContent)).toEqual([
    'max-budget',
    'team-a',
    '—', // Min Available: absent
    '1', // Max Unavailable
    '1', // Allowed Disruptions
  ])
})

// pdb-list-missing-status
test('list-missing-status', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json({
        kind: 'poddisruptionbudgets',
        cluster: 'prod',
        items: [freshBudget],
      }),
    ),
  )
  selectProd()
  renderAt(<PodDisruptionBudgetView />)

  const nameCell = (await screen.findByRole('link', { name: 'web' })).closest('tr')
  // certainty rule: a fresh PDB has no status; 4.1 would UndefinedError —
  // 5.0 renders "—", never guesses, never throws.
  expect(nameCell?.textContent).toContain('—')
  expect(nameCell?.textContent).not.toContain('undefined')
})

// pdb-list-no-cluster-state
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<PodDisruptionBudgetView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// pdb-list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on poddisruptionbudgets' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<PodDisruptionBudgetView />)

  expect(
    await screen.findByText(/Error loading pod disruption budgets: RBAC_DENIED: list on poddisruptionbudgets/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('link', { name: 'web' })).toHaveLength(0)
})

// pdb-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/poddisruptionbudgets', () =>
      HttpResponse.json({ kind: 'poddisruptionbudgets', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<PodDisruptionBudgetView />)

  // first-class empty state, not an error.
  expect(await screen.findByText('No pod disruption budgets found')).toBeTruthy()
})
