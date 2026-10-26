import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test } from 'vitest'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { server } from '../msw'
import CrdsView from '../../src/views/Cluster/CRDs'
import CrdDataView from '../../src/views/Cluster/CrdData'
import { useClusterStore } from '../../src/store/cluster'

// ponytail: KubeDataTable is mocked to a plain table so row/cell assertions
// are stable (same pattern as the node test); the real DataTables init is out
// of scope here.
vi.mock('../../src/components/KubeDataTable', async () => {
  const React = await import('react')
  const Column = () => null
  function KubeDataTable({ data, children }: { data: Record<string, unknown>[]; children: React.ReactNode }) {
    type RenderFn = (data: unknown, type: string, row: Record<string, unknown>) => React.ReactNode
    const columns = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map((child) => {
        const el = child as React.ReactElement<{ title: string; data?: string | null; children?: RenderFn | React.ReactNode }>
        return { title: el.props.title, data: el.props.data, render: el.props.children as RenderFn | React.ReactNode }
      })
    const cellValue = (row: Record<string, unknown>, col: { data?: string | null; render?: RenderFn | React.ReactNode }) => {
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

const CRDS = {
  kind: 'crds',
  cluster: 'prod',
  items: [
    {
      metadata: { name: 'applications.argoproj.io', creationTimestamp: '2026-01-01T00:00:00Z' },
      spec: {
        group: 'argoproj.io',
        names: { kind: 'Application', plural: 'applications' },
        scope: 'Namespaced',
        versions: [
          { name: 'v1alpha1', served: true, storage: true },
          { name: 'v1', served: true, storage: false },
        ],
      },
    },
  ],
}

const CRD_SINGLE = { items: [CRDS.items[0]], kind: 'crds', cluster: 'prod' }

const INSTANCES = {
  kind: 'crds',
  cluster: 'prod',
  items: [
    {
      name: 'app-1',
      namespace: 'team-a',
      status: 'True',
      type: 'Ready',
      reason: 'Ok',
      message: 'all good',
      created: '2026-01-02T03:04:05Z',
    },
  ],
}

const renderAt = (ui: ReactElement, path: string, handlers: Parameters<typeof server.use>[]) => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  server.use(...handlers)
  return render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter initialEntries={[path]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  document.cookie = 'kd_session=1; path=/'
})

afterEach(() => {
  localStorage.clear()
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

test('crd-list-renders: 4.1 columns + served versions + kind link', async () => {
  renderAt(
    <CrdsView />,
    '/cluster/crd',
    [http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRDS))],
  )
  await screen.findByRole('table')
  // 5.0 column set (the 4.1 Resource/Group/Version/Scope/Acction, with the
  // single "Version" split into the served-versions column).
  for (const header of ['Kind', 'Group', 'Plural', 'Scope', 'Served', 'Created']) {
    expect(screen.getByText(header)).toBeTruthy()
  }
  // The CRD's identity renders.
  expect(screen.getByText('Application')).toBeTruthy()
  expect(screen.getByText('argoproj.io')).toBeTruthy()
  expect(screen.getByText('applications')).toBeTruthy()
  expect(screen.getByText('Namespaced')).toBeTruthy()
  // Both served versions render; the storage version (v1alpha1) is flagged
  // with the ✦ marker (a separate text node, hence the regex match).
  expect(screen.getByText(/v1alpha1/)).toBeTruthy()
  // The non-storage served version (v1) — a word boundary keeps the match
  // distinct from the v1alpha1 badge above.
  expect(screen.getByText(/^v1$/)).toBeTruthy()
  // The kind links to the detail page with the PLURAL (not the kind).
  const link = screen.getByRole('link', { name: 'Application' })
  expect(link.getAttribute('href')).toBe('/cluster/crd/data?name=applications')
})

test('crd-detail-renders: CRD identity + instance rows', async () => {
  renderAt(
    <CrdDataView />,
    '/cluster/crd/data?name=applications.argoproj.io',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRD_SINGLE)),
      http.get('*/api/v1/clusters/1/resources/crds/instances', () =>
        HttpResponse.json(INSTANCES),
      ),
    ],
  )
  // Two queries run sequentially (the instance list is gated on the CRD read
  // resolving) — wait for the instance row, not just the first table.
  expect(await screen.findByText('app-1', {}, { timeout: 4000 })).toBeTruthy()
  // The CRD's own identity, resolved server-side (the 4.1 namespaced→cluster
  // fallback is gone — the CRD spec is the authority). The kind appears in the
  // breadcrumb, the title, and the table — assert presence, not uniqueness.
  expect(screen.getAllByText('argoproj.io').length).toBeGreaterThanOrEqual(1)
  expect(screen.getAllByText('Application').length).toBeGreaterThanOrEqual(1)
  expect(screen.getAllByText('Namespaced').length).toBeGreaterThanOrEqual(1)
  // The served version (the first served in the fixture is v1alpha1).
  expect(screen.getByText('v1alpha1')).toBeTruthy()
  // The remaining instance cells render.
  expect(screen.getByText('team-a')).toBeTruthy()
  expect(screen.getByText('Ready')).toBeTruthy()
  expect(screen.getByText('all good')).toBeTruthy()
  // The breadcrumb links back to the CRD list.
  expect(screen.getByRole('link', { name: 'CRDs' }).getAttribute('href')).toBe('/cluster/crd')
})

test('crd-detail-empty: no instances → first-class empty state, not an error', async () => {
  renderAt(
    <CrdDataView />,
    '/cluster/crd/data?name=applications.argoproj.io',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRD_SINGLE)),
      http.get('*/api/v1/clusters/1/resources/crds/instances', () =>
        HttpResponse.json({ kind: 'crds', cluster: 'prod', items: [] }),
      ),
    ],
  )
  await screen.findByText(/No Application instances found/)
  // The empty state names the namespace (the topbar selection is applied).
  expect(screen.getByText(/in namespace 'team-a'/)).toBeTruthy()
})

test('crd-detail-rbac-denied: 403 on the instance list surfaces the error', async () => {
  renderAt(
    <CrdDataView />,
    '/cluster/crd/data?name=applications.argoproj.io',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () => HttpResponse.json(CRD_SINGLE)),
      http.get('*/api/v1/clusters/1/resources/crds/instances', () =>
        HttpResponse.json(
          { error: { code: 'RBAC_DENIED', message: 'list on applications' } },
          { status: 403 },
        ),
      ),
    ],
  )
  await screen.findByText(/Error loading instances/)
  expect(screen.getByText(/RBAC_DENIED/)).toBeTruthy()
})

test('crd-detail-missing-name: no ?name= → error line', () => {
  renderAt(<CrdDataView />, '/cluster/crd/data', [])
  expect(screen.getByText('Error: CRD name not provided')).toBeTruthy()
})

test('crd-list-rbac-denied: 403 on the CRD list surfaces the error', async () => {
  renderAt(
    <CrdsView />,
    '/cluster/crd',
    [
      http.get('*/api/v1/clusters/1/resources/crds', () =>
        HttpResponse.json(
          { error: { code: 'RBAC_DENIED', message: 'list on customresourcedefinitions' } },
          { status: 403 },
        ),
      ),
    ],
  )
  await screen.findByText(/Error loading CRDs/)
  expect(screen.getByText(/RBAC_DENIED/)).toBeTruthy()
})
