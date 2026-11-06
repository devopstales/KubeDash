import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ObjectRoute from '../../src/components/ObjectRoute'
import IngressView from '../../src/views/Network/Ingress'
import IngressDataView from '../../src/views/Network/IngressData'
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
const renderAt = (_ui: ReactElement, path = '/network/ingress') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route
            path="/network/ingress"
            element={
              <ObjectRoute
                kind="ingress"
                listRoute="/network/ingress"
                list={<IngressView />}
                detail={(p) => <IngressDataView name={p.name} namespace={p.namespace ?? ''} />}
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

// kubernetes to_dict shape: snake_case. Namespaced.
const webIngress = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'Ingress',
  metadata: {
    name: 'web',
    namespace: 'team-a',
    creation_timestamp: '2026-10-26T10:00:00Z',
  },
  spec: {
    ingress_class_name: 'nginx',
    tls: [{ secret_name: 'web-tls' }],
    rules: [
      {
        host: 'web.example.com',
        http: {
          paths: [
            {
              path: '/',
              path_type: 'Prefix',
              backend: { service: { name: 'web', port: { number: 80 } } },
            },
          ],
        },
      },
      {
        host: 'www.example.com',
        http: {
          paths: [
            {
              path: '/api',
              path_type: 'Prefix',
              backend: { service: { name: 'api', port: { name: 'http' } } },
            },
          ],
        },
      },
    ],
  },
}

// no ingress_class_name, no rule host — the "—" certainty cells.
const plainIngress = {
  apiVersion: 'networking.k8s.io/v1',
  kind: 'Ingress',
  metadata: { name: 'plain', namespace: 'team-a', creation_timestamp: '2026-10-26T10:00:00Z' },
  spec: {
    rules: [
      {
        http: {
          paths: [{ path: '/', path_type: 'Prefix', backend: { service: { name: 'plain' } } }],
        },
      },
    ],
  },
}

// list-renders-ingresses
test('list-renders-ingresses', async () => {
  let requestedPath = ''
  let namespaceParam: string | null = null
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', ({ request }) => {
      const u = new URL(request.url)
      requestedPath = u.pathname
      namespaceParam = u.searchParams.get('namespace')
      return HttpResponse.json({
        kind: 'ingresses',
        cluster: 'prod',
        items: [webIngress, plainIngress],
      })
    }),
  )
  selectProd()
  renderAt(<IngressView />)

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref and navigates; the URL stays clean.
  const nameButton = await screen.findByRole('button', { name: 'web' })
  // fetch path is EXACTLY the namespaced kind URL (the selected namespace).
  expect(requestedPath).toBe('/api/v1/clusters/1/resources/ingresses')
  expect(namespaceParam).toBe('team-a')

  // card title: EXACT string (the spec's pinned title — 4.1's "Ingress
  // Resources" is not replicated). Pinned on the heading: the breadcrumb
  // renders the same text.
  expect(screen.getByRole('heading', { name: 'Ingress List' })).toBeTruthy()
  // breadcrumb: Network → Ingress List.
  expect(screen.getByText('Network')).toBeTruthy()
  // columns: name, ingressclass, hostname.
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'IngressClass',
    'Hostname',
  ])
  // row: ingress_class_name + spec.rules[].host joined ", ".
  expect(screen.getByText('nginx')).toBeTruthy()
  expect(screen.getByText('web.example.com, www.example.com')).toBeTruthy()
  // the hostless / classless row renders the "—" certainty cells.
  const plainRow = screen.getByRole('button', { name: 'plain' }).closest('tr')
  expect(plainRow?.textContent).toBe('plain——')
})

// click-name-renders-detail-with-clean-url (R1)
test('click-name-renders-detail-with-clean-url', async () => {
  const user = userEvent.setup()
  selectProd()
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [webIngress] }),
    ),
  )
  renderAt(<IngressView />)

  // Clicking the name button opens the detail via openObject; the URL
  // never carries identity (R1). The ref carries the namespace (R8).
  const nameButton = await screen.findByRole('button', { name: 'web' })
  await user.click(nameButton)

  expect(await screen.findByText('Ingress Data')).toBeTruthy()
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
  renderAt(<IngressView />)

  expect(await screen.findByText('No cluster selected.')).toBeTruthy()
  expect(seen).toHaveLength(0) // no resource fetch is made
})

// list-error-state
test('list-error-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on ingresses' } },
        { status: 403 },
      ),
    ),
  )
  selectProd()
  renderAt(<IngressView />)

  expect(
    await screen.findByText(/Error loading ingresses: RBAC_DENIED: list on ingresses/),
  ).toBeTruthy()
  // no blank table, no rows (the name cell is a button, not a link, in the
  // migrated view).
  expect(screen.queryAllByRole('button', { name: 'web' })).toHaveLength(0)
})

// list-empty-state
test('list-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/ingresses', () =>
      HttpResponse.json({ kind: 'ingresses', cluster: 'prod', items: [] }),
    ),
  )
  selectProd()
  renderAt(<IngressView />)

  expect(await screen.findByText('No ingresses found')).toBeTruthy()
})
