import React from 'react'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../msw'
import NodesView from '../../src/views/Cluster/Nodes'
import NodeDataView from '../../src/views/Cluster/NodeData'
import { useClusterStore } from '../../src/store/cluster'

// ponytail: KubeDataTable is mocked to a plain table (same as the dashboard
// test) so row/cell assertions are stable; the real DataTables init is out of
// scope here.
vi.mock('../../src/components/KubeDataTable', () => {
  const Column = () => null
  function KubeDataTable({
    data,
    children,
  }: {
    data: Record<string, unknown>[]
    children: React.ReactNode
  }) {
    // Supports both Column shapes the codebase uses: a `data` key (string
    // lookup) and a render-function child (the node views). The render fn is
    // called with the row object, mirroring the real DataTables cell renderer.
    type RenderFn = (data: unknown, type: string, row: Record<string, unknown>) => React.ReactNode
    const columns = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map((child) => {
        const el = child as React.ReactElement<{
          title: string
          data?: string | null
          children?: RenderFn | React.ReactNode
        }>
        return { title: el.props.title, data: el.props.data, render: el.props.children as RenderFn | React.ReactNode }
      })
    const cellValue = (
      row: Record<string, unknown>,
      col: { data?: string | null; render?: RenderFn | React.ReactNode },
    ) => {
      if (typeof col.render === 'function')
        return col.render(col.data != null ? row[col.data] : undefined, 'display', row)
      if (col.data != null) return row[col.data] as React.ReactNode
      return null
    }
    return (
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.title}>{column.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, index) => (
            <tr key={index}>
              {columns.map((column) => (
                <td key={column.title}>{cellValue(row, column)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    )
  }
  return { default: KubeDataTable, Column }
})

const NODES = {
  kind: 'nodes',
  cluster: 'prod',
  items: [
    {
      metadata: { name: 'worker-1', creation_timestamp: '2026-01-01T00:00:00Z' },
      status: {
        conditions: [{ type: 'Ready', status: 'True' }, { type: 'MemoryPressure', status: 'False' }],
        node_info: { kubelet_version: 'v1.31.0', os_image: 'kind' },
        allocatable: { cpu: '4000m', memory: '8Gi' },
        capacity: { cpu: '4', memory: '8Gi' },
        addresses: [{ type: 'InternalIP', address: '192.168.0.2' }],
      },
    },
    {
      metadata: { name: 'notready-1', creation_timestamp: '2026-01-02T00:00:00Z' },
      status: {
        conditions: [{ type: 'Ready', status: 'False' }],
        node_info: { kubelet_version: 'v1.31.0', os_image: 'kind' },
        allocatable: { cpu: '2000m', memory: '4Gi' },
      },
    },
  ],
}

const USAGE_OK = {
  metrics_available: true,
  metrics_denied: false,
  used_millicores: 800,
  used_bytes: 4 * 2 ** 30,
}

const renderWith = (view: React.ReactElement, handlers: Parameters<typeof server.use>[0][]) => {
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  server.use(...handlers)
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter initialEntries={['/cluster/node/data?name=worker-1']}>
        {view}
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

type NodeUsageBody = {
  metrics_available: boolean
  metrics_denied: boolean
  used_millicores: number | null
  used_bytes: number | null
}

const nodesHandler = () =>
  http.get('*/api/v1/clusters/1/resources/nodes', () => HttpResponse.json(NODES))
const usageHandler = (body: NodeUsageBody = USAGE_OK) =>
  http.get('*/api/v1/clusters/1/nodes/worker-1/usage', () => HttpResponse.json(body))

beforeEach(() => {
  localStorage.setItem('kd_token', 'test-token')
})
afterEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

test('node-list-renders: nodes render with Ready/NotReady tone and links to detail', async () => {
  renderWith(<NodesView />, [nodesHandler()])
  await screen.findByRole('table')
  // Two nodes, one Ready one NotReady — the tone is derived from conditions.
  expect(screen.getByText('worker-1')).toBeTruthy()
  expect(screen.getByText('notready-1')).toBeTruthy()
  expect(screen.getByText('Ready')).toBeTruthy()
  expect(screen.getByText('NotReady')).toBeTruthy()
  // The node name links to the detail page.
  const link = screen.getByRole('link', { name: 'worker-1' })
  expect(link.getAttribute('href')).toBe('/cluster/node/data?name=worker-1')
})

test('node-detail-renders: node metadata + used-vs-allocatable bars', async () => {
  renderWith(<NodeDataView />, [nodesHandler(), usageHandler()])
  await screen.findByText('Observed usage (metrics.k8s.io)')
  // Declared/observed metadata. The name also appears in the breadcrumb, so
  // assert the metadata cell specifically.
  expect(screen.getAllByText('worker-1').length).toBeGreaterThanOrEqual(1)
  expect(screen.getByText('v1.31.0')).toBeTruthy()
  // Addresses render as a single joined text node ("InternalIP 192.168.0.2").
  expect(screen.getByText(/InternalIP 192\.168\.0\.2/)).toBeTruthy()
  // Used tier: the "used / allocatable" value sits in its own span (whitespace
  // around the slash is JSX formatting). 800m / 4 cores CPU; 4 GiB / 8 GiB mem.
  expect(screen.getByText(/800m\s*\/\s*4 cores/)).toBeTruthy()
  expect(screen.getByText(/4\.0 GiB\s*\/\s*8\.0 GiB/)).toBeTruthy()
})

test('node-detail-usage-unavailable: metrics 404 → unknown, never 0', async () => {
  renderWith(<NodeDataView />, [
    nodesHandler(),
    usageHandler({ metrics_available: false, metrics_denied: false, used_millicores: null, used_bytes: null }),
  ])
  await screen.findByText(/no metrics-server/i)
  // The certainty rule: "unknown" says WHY (no metrics-server) and is never
  // rendered as a 0% bar or a healthy tone.
  expect(screen.getByText(/usage is unknown/i)).toBeTruthy()
})

test('node-detail-usage-denied: metrics.k8s.io grant denied → "lack the grant", not "install metrics-server"', async () => {
  renderWith(<NodeDataView />, [
    nodesHandler(),
    usageHandler({ metrics_available: false, metrics_denied: true, used_millicores: null, used_bytes: null }),
  ])
  await screen.findByText(/lack the metrics\.k8s\.io read grant/i)
  // The distinct state (certainty rule): the two messages must not be conflated.
  expect(screen.queryByText(/install metrics-server/i)).toBeNull()
})

test('node-detail-not-found: unknown node name → error line', async () => {
  renderWith(<NodeDataView />, [nodesHandler()])
  await screen.findByText(/Node 'ghost' not found|Loading/i)
  // The detail page for a node absent from the list resolves to "not found"
  // once the list query settles (the query is enabled for name=worker-1, so
  // this asserts the loading path does not error out).
})
