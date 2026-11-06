import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import GatewayClassView from '../../src/views/Network/GatewayClass'
import GatewayClassDataView from '../../src/views/Network/GatewayClassData'
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

// ADR-0040: render through ObjectRoute so the click→detail flow is the real
// one (the ref is the active pointer; the URL never carries identity).
const renderAt = (_ui: ReactElement, path = '/network/gateway-class') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/network/gateway-class"
            element={
              <ObjectRoute
                kind="gatewayclass"
                listRoute="/network/gateway-class"
                list={<GatewayClassView />}
                detail={(p) => <GatewayClassDataView name={p.name} />}
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

// FULL custom object (camelCase — the CRD seam). Cluster-scoped — no
// namespace field. ~3 days old so the Age column is a stable '3d'.
const traefikClass = {
  apiVersion: 'gateway.networking.k8s.io/v1',
  kind: 'GatewayClass',
  metadata: {
    name: 'traefik',
    creationTimestamp: new Date(Date.now() - 3 * 86400 * 1000).toISOString(),
  },
  spec: {
    controllerName: 'traefik.io/gatewayclass',
    conditions: [{ type: 'Accepted', status: 'True', reason: 'Accepted', message: 'ok' }],
  },
}

// list-renders-gateway-classes
test('list-renders-gateway-classes', async () => {
  let requestedPath = ''
  let requestedUrl = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      requestedUrl = u.href
      return HttpResponse.json({
        kind: 'gatewayclasses',
        cluster: 'prod',
        items: [traefikClass],
      })
    }),
  )
  selectProd()
  renderAt(<GatewayClassView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'traefik' })
  // fetch path is EXACTLY the cluster-scoped kind URL, no namespace substring.
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/gatewayclasses')
  expect(requestedUrl).not.toContain('namespace')

  // card title: EXACT string (the 5.0 `<Kind> List` convention).
  // Pinned on the heading specifically: the breadcrumb renders the same
  // text, and a card-title regression must not survive via the breadcrumb.
  expect(screen.getByRole('heading', { name: 'GatewayClass List' })).toBeTruthy()
  // breadcrumb: Network → GatewayClass List.
  expect(screen.getByText('Network')).toBeTruthy()
  // columns: name, controller, age.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Controller',
    'Age',
  ])
  // row: controller rendered from spec.controllerName (camelCase CRD seam).
  expect(screen.getByText('traefik.io/gatewayclass')).toBeTruthy()
  // age: human-readable (the full timestamp lives in the data view + JSON).
  const nameCell = nameButton.closest('tr')
  expect(nameCell?.textContent).not.toContain(traefikClass.metadata.creationTimestamp)
  expect(nameCell?.textContent).toMatch(/3d/)
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [traefikClass] }),
    ),
  )
  renderAt(<GatewayClassView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1).
  const nameButton = await screen.findByRole('button', { name: 'traefik' })
  await user.click(nameButton)

  // The detail renders (the active ref is kind-matched).
  expect(await screen.findByText('GatewayClass Data')).toBeTruthy()
  // The URL is clean: no query string (R1).
  expect(window.location.search).toBe('')
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
  renderAt(<GatewayClassView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on gatewayclasses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<GatewayClassView />)

  expect(
    await screen.findByText(/Error loading gateway classes: RBAC_DENIED: list on gatewayclasses/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'traefik' })).toHaveLength(0)
})

// list-crd-absent-empty-state (the VPA absence contract: CRD not installed
// is the same pinned empty state as "none exist", never an error).
test('list-crd-absent-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/gatewayclasses', () =>
      HttpResponse.json({ kind: 'gatewayclasses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<GatewayClassView />)

  expect(await screen.findByText('No gateway classes found')).toBeTruthy()
})
