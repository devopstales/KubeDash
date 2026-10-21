import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ClusterRoleBindingView from '../../src/views/ClusterPermission/ClusterRoleBinding'
import { useClusterStore } from '../../src/store/cluster'

vi.mock('../../src/components/KubeDataTable', () => {
  const React = require('react') as typeof import('react')
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
          (child as React.ReactElement<{ title: string; data: string; children?: unknown }>).props,
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
                const value = row[col.data]
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

const renderView = (path = '/') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <ClusterRoleBindingView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const adminBinding = {
  metadata: { name: 'cluster-admin' },
  role_ref: { kind: 'ClusterRole', name: 'cluster-admin', api_group: 'rbac.authorization.k8s.io' },
  subjects: [
    { kind: 'User', name: 'jane' },
    { kind: 'User', name: 'bob' },
    { kind: 'Group', name: 'system:masters' },
    { kind: 'ServiceAccount', name: 'builder', namespace: 'ci' },
  ],
}

test('lists-cluster-role-bindings-without-a-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', ({ request }) => {
      requested = request.url
      return HttpResponse.json({
        kind: 'clusterrolebindings',
        cluster: 'prod',
        items: [
          adminBinding,
          {
            metadata: { name: 'view-binding' },
            role_ref: { kind: 'Role', name: 'edit' },
            subjects: [{ kind: 'Group', name: 'readers' }],
          },
        ],
      })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView('/cluster-permission/cluster-role-binding?crb_name=cluster-admin')

  expect(await screen.findByText('cluster-admin', { selector: '.selected' })).toBeTruthy()
  const url = new URL(requested)
  expect(url.pathname).toBe('/api/v1/clusters/1/resources/clusterrolebindings')
  expect(url.search).toBe('')
  expect(screen.getByText('Cluster Role Binding List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(screen.getByText('Cluster Role Bindings')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Role',
    'User',
    'Group',
    'ServiceAccount',
  ])
  expect(screen.getByRole('link', { name: 'cluster-admin' }).getAttribute('href')).toBe(
    '/cluster-permission/cluster-role/data?name=cluster-admin',
  )
  expect(screen.getByRole('link', { name: 'edit' }).getAttribute('href')).toBe(
    '/cluster-permission/role/data?name=edit',
  )
  expect(screen.getByText('jane')).toBeTruthy()
  expect(screen.getByText('bob')).toBeTruthy()
  expect(screen.getByText('system:masters')).toBeTruthy()
  expect(screen.getByText('readers')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'builder' }).getAttribute('href')).toBe(
    '/cluster-permission/service-account/data?name=builder&namespace=ci',
  )
  expect(screen.getByText('view-binding')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'cluster-admin' }).className).not.toContain('selected')
})

test('service-account-link-selects-its-namespace', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({ kind: 'clusterrolebindings', cluster: 'prod', items: [adminBinding] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  await user.click(await screen.findByRole('link', { name: 'builder' }))
  expect(useClusterStore.getState().selectedNamespace).toBe('ci')
})

test('shows-empty-state', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({ kind: 'clusterrolebindings', cluster: 'prod', items: [] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(await screen.findByText('No cluster role bindings found')).toBeTruthy()
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on clusterrolebindings' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(
    await screen.findByText(
      /Error loading cluster role bindings: RBAC_DENIED: list on clusterrolebindings/,
    ),
  ).toBeTruthy()
})

test('ignores-empty-subjects-and-unknown-role-kinds', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterrolebindings', () =>
      HttpResponse.json({
        kind: 'clusterrolebindings',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'bare' },
            role_ref: { kind: 'SomethingElse', name: 'custom' },
            subjects: null,
          },
        ],
      }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(await screen.findByText('bare')).toBeTruthy()
  expect(screen.getByText('custom')).toBeTruthy()
  expect(screen.queryByRole('link', { name: 'custom' })).toBeNull()
})
