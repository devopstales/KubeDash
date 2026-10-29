import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import VerticalPodAutoscalerView from '../../src/views/OtherResource/VerticalPodAutoscaler'
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

const renderAt = (ui: ReactElement, path = '/other-resource/vertical-pod-autoscaler') => {
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

// The VPA CRD's full custom object: camelCase (the custom-object wire form).
const webVpa = {
  apiVersion: 'autoscaling.k8s.io/v1',
  kind: 'VerticalPodAutoscaler',
  metadata: {
    name: 'web-vpa',
    namespace: 'team-a',
    creationTimestamp: '2026-01-02T03:04:05Z',
    labels: { team: 'a' },
    annotations: { 'vpa.kubernetes.io/managed-by': 'kubedash' },
  },
  spec: {
    targetRef: { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' },
    updatePolicy: { updateMode: 'Auto' },
    resourcePolicy: {
      containerPolicies: [
        {
          containerName: 'app',
          controlledValues: 'RequestsLimits',
          mode: 'Auto',
          minAllowed: { memory: '128Mi' },
          maxAllowed: { memory: '1Gi' },
          controlledResources: ['cpu', 'memory'],
        },
      ],
    },
  },
  status: {
    conditions: [
      {
        type: 'RecommendationProvided',
        status: 'True',
        lastTransitionTime: '2026-01-02T03:04:06Z',
        reason: 'RecommendationAvailable',
        message: 'ok',
      },
    ],
  },
}

const vpaListResponse = (items: unknown[]) =>
  HttpResponse.json({ kind: 'verticalpodautoscalers', cluster: 'prod', items })

test('vpa-list-renders-rows-with-data-links', async () => {
  let fetchedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', ({ request }) => {
      fetchedUrl = new URL(request.url).pathname + new URL(request.url).search
      return vpaListResponse([webVpa])
    }),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  const link = await screen.findByRole('link', { name: 'web-vpa' })
  // the list view is the sole producer of the data page's query strings.
  expect(link.getAttribute('href')).toBe(
    '/other-resource/vertical-pod-autoscaler/data?name=web-vpa&namespace=team-a',
  )
  // fetch URL EXACTLY: the namespaced CRD kind with the header's namespace.
  expect(fetchedUrl).toBe('/api/v1/clusters/1/resources/verticalpodautoscalers?namespace=team-a')
  // card title EXACTLY (the e2e smoke asserts it with exact: true).
  expect(screen.getAllByText('Vertical Pod Autoscaler List', { exact: true }).length).toBeGreaterThanOrEqual(1)
  // breadcrumb: Other Resources.
  expect(screen.getByText('Other Resources')).toBeTruthy()
  // columns, in order.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Namespace',
    'Target Kind',
    'Target Name',
    'Update Mode',
    'Min Memory',
    'Max Memory',
    'Created',
  ])
  // created is rendered by formatTimestamp (no raw ISO 'T' in the row).
  const row = link.closest('tr')
  expect(row?.textContent).not.toContain('2026-01-02T03:04:05Z')
  expect(row?.textContent).toMatch(/2026/)
})

test('vpa-list-target-and-memory-cells', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([webVpa]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  await screen.findByRole('link', { name: 'web-vpa' })
  const row = screen.getByRole('link', { name: 'web-vpa' }).closest('tr')
  // Target Kind from spec.targetRef.kind; Update Mode from
  // spec.updatePolicy.updateMode; Min/Max Memory from the container policy.
  expect(row?.textContent).toContain('Deployment')
  expect(row?.textContent).toContain('Auto')
  expect(row?.textContent).toContain('128Mi')
  expect(row?.textContent).toContain('1Gi')
  // Target Name (spec.targetRef.name) is PLAIN TEXT: 4.1 linked it to a
  // workload page 5.0 does not have yet — only the VPA name is a link.
  expect(row?.querySelectorAll('a')).toHaveLength(1)
  expect(screen.getByText('web')).not.toHaveAttribute('href')
})

test('vpa-list-last-container-memory-semantics', async () => {
  // 4.1's {% set %} overwrite: the LAST container policy that defines the
  // key wins (the first 64Mi must not survive).
  const twoPolicies = {
    ...webVpa,
    metadata: { ...webVpa.metadata, name: 'two-vpa' },
    spec: {
      ...webVpa.spec,
      resourcePolicy: {
        containerPolicies: [
          { containerName: 'first', minAllowed: { memory: '64Mi' }, maxAllowed: { memory: '512Mi' } },
          { containerName: 'second', minAllowed: { memory: '256Mi' } },
        ],
      },
    },
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([twoPolicies]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  const link = await screen.findByRole('link', { name: 'two-vpa' })
  const row = link.closest('tr')
  expect(row?.textContent).toContain('256Mi')
  expect(row?.textContent).not.toContain('64Mi')
  expect(row?.textContent).toContain('512Mi')
})

test('vpa-list-missing-update-policy', async () => {
  const noPolicy = {
    ...webVpa,
    metadata: { ...webVpa.metadata, name: 'no-upd' },
    spec: {
      targetRef: { kind: 'Deployment', name: 'web', apiVersion: 'apps/v1' },
      // no updatePolicy
    },
  }
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([noPolicy]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  const link = await screen.findByRole('link', { name: 'no-upd' })
  const row = link.closest('tr')
  // 4.1's literal for the absent value: N/A (certainty rule: never guess).
  expect(row?.textContent).toContain('N/A')
})

test('vpa-list-no-cluster-state', async () => {
  const seen: string[] = []
  server.use(
    http.get('*/api/v1/clusters/:id/resources/*', ({ request }) => {
      seen.push(new URL(request.url).pathname)
      return HttpResponse.json({ items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
  renderAt(<VerticalPodAutoscalerView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

test('vpa-list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/verticalpodautoscalers', () =>
      vpaListResponse([]),
    ),
  )
  selectProd()
  renderAt(<VerticalPodAutoscalerView />)

  // Also the CRD-absent state: the page does not distinguish "no VPAs"
  // from "operator not installed" — one pinned empty-state copy.
  expect(await screen.findByText('No vertical pod autoscalers found')).toBeTruthy()
})
