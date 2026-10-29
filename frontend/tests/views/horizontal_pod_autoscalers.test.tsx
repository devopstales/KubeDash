import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import HorizontalPodAutoscalerView from '../../src/views/OtherResource/HorizontalPodAutoscaler'
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

const renderAt = (ui: ReactElement, path = '/other-resource/horizontal-pod-autoscaler') => {
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

// kubernetes to_dict shape: snake_case (a generated core-API model),
// spec/status intact.
const webHpa = {
  apiVersion: 'autoscaling/v1',
  kind: 'HorizontalPodAutoscaler',
  metadata: {
    name: 'web-hpa',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: {},
  },
  spec: {
    scale_target_ref: { kind: 'Deployment', name: 'web', api_version: 'apps/v1' },
    min_replicas: 2,
    max_replicas: 10,
    target_cpu_utilization_percentage: 80,
  },
  status: {
    current_replicas: 3,
    desired_replicas: 3,
    current_cpu_utilization_percentage: 50,
    conditions: [
      {
        type: 'AbleToScale',
        status: 'True',
        last_transition_time: '2026-01-02T03:04:06Z',
        reason: 'SuccessfulRescale',
        message: 'Ready to scale',
      },
    ],
  },
}

// A legacy CPU-only HPA whose controller has not yet reported
// current_cpu_utilization_percentage (4.1's UNKNOWN literal).
const noCpuHpa = {
  ...webHpa,
  metadata: { ...webHpa.metadata, name: 'no-cpu-hpa' },
  status: { ...webHpa.status, current_cpu_utilization_percentage: undefined },
}

const cells = (tr: Element | null) => Array.from(tr?.querySelectorAll('td') ?? [])

// hpa-list-renders-rows-with-data-links
test('list-renders-hpa-rows-with-data-links', async () => {
  let requestedPath = ''
  let requestedNs = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedNs = u.searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'horizontalpodautoscalers',
        cluster: 'prod',
        items: [webHpa],
      })
    }),
  )
  selectProd()
  renderAt(<HorizontalPodAutoscalerView />)

  const link = await screen.findByRole('link', { name: 'web-hpa' })
  // the list view is the sole producer of the data page's query strings.
  expect(link.getAttribute('href')).toBe(
    '/other-resource/horizontal-pod-autoscaler/data?name=web-hpa&namespace=team-a',
  )
  // the namespaced fetch EXACTLY: cluster path + the header's namespace.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/horizontalpodautoscalers')
  expect(requestedNs).toBe('team-a')
  // card title: EXACT string (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Horizontal Pod Autoscaler List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Other Resources → Horizontal Pod Autoscaler List.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns: the 4.1 list columns.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Owner',
    'Targets',
    'Min Replicas',
    'Max Replicas',
    'Replicas',
  ])
  const nameCell = link.closest('tr')
  // row: the namespace is shown (the namespaced kind).
  expect(nameCell?.textContent).toContain('team-a')
})

// hpa-list-targets-and-replica-cells
test('list-targets-and-replica-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', () =>
      HttpResponse.json({ kind: 'horizontalpodautoscalers', cluster: 'prod', items: [webHpa] }),
    ),
  )
  selectProd()
  renderAt(<HorizontalPodAutoscalerView />)

  const webLink = await screen.findByRole('link', { name: 'web-hpa' })
  expect(cells(webLink.closest('tr')).map((td) => td.textContent)).toEqual([
    'web-hpa',
    'team-a',
    'web', // Owner: scale_target_ref name, PLAIN TEXT (the 4.1 link is dropped)
    '50 / 80 %', // Targets: current / target CPU percent
    '2', // Min Replicas: min_replicas — the 4.1 header-swap is CORRECTED (NOT 10)
    '10', // Max Replicas: max_replicas (NOT 2)
    '3', // Replicas: status.current_replicas
  ])
  // Owner is plain text: no link element inside the Owner cell.
  const ownerCell = cells(webLink.closest('tr'))[2]
  expect(ownerCell.querySelector('a')).toBeNull()
})

// hpa-list-unknown-cpu-target
test('list-unknown-cpu-target', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', () =>
      HttpResponse.json({ kind: 'horizontalpodautoscalers', cluster: 'prod', items: [noCpuHpa] }),
    ),
  )
  selectProd()
  renderAt(<HorizontalPodAutoscalerView />)

  const link = await screen.findByRole('link', { name: 'no-cpu-hpa' })
  // 4.1's exact fallback for the absent legacy v1 CPU field: the UNKNOWN
  // literal (certainty rule: never guess).
  expect(cells(link.closest('tr')).map((td) => td.textContent)).toContain('UNKNOWN / 80 %')
})

// hpa-list-no-cluster-state
test('list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<HorizontalPodAutoscalerView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// hpa-list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on horizontalpodautoscalers' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<HorizontalPodAutoscalerView />)

  expect(
    await screen.findByText(/Error loading horizontal pod autoscalers: RBAC_DENIED: list on horizontalpodautoscalers/),
  ).toBeTruthy()
  // no blank table, no rows.
  expect(screen.queryAllByRole('link', { name: 'web-hpa' })).toHaveLength(0)
})

// hpa-list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/horizontalpodautoscalers', () =>
      HttpResponse.json({ kind: 'horizontalpodautoscalers', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<HorizontalPodAutoscalerView />)

  // first-class empty state, not an error.
  expect(await screen.findByText('No horizontal pod autoscalers found')).toBeTruthy()
})
