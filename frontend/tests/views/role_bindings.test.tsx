import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import RoleBindingView from '../../src/views/ClusterPermission/RoleBinding'
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

const renderView = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <RoleBindingView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const editBinding = {
  metadata: { name: 'edit-binding', namespace: 'team-a' },
  role_ref: { kind: 'Role', name: 'edit', api_group: 'rbac.authorization.k8s.io' },
  subjects: [
    { kind: 'User', name: 'jane' },
    { kind: 'User', name: 'bob' },
    { kind: 'Group', name: 'devs' },
    { kind: 'ServiceAccount', name: 'builder', namespace: 'ci' },
  ],
}

test('lists-role-bindings-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'rolebindings',
        cluster: 'prod',
        items: [
          editBinding,
          {
            metadata: { name: 'view-binding', namespace: 'team-a' },
            role_ref: { kind: 'ClusterRole', name: 'view' },
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
  renderView()

  expect(await screen.findByText('edit-binding')).toBeTruthy()
  expect(requested).toBe('team-a')
  expect(screen.getByText('Role Bindings List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Role',
    'User',
    'Group',
    'ServiceAccount',
  ])
  expect(screen.getByRole('link', { name: 'edit' }).getAttribute('href')).toBe(
    '/cluster-permission/role/data?name=edit&namespace=team-a',
  )
  expect(screen.getByRole('link', { name: 'view' }).getAttribute('href')).toBe(
    '/cluster-permission/cluster-role/data?name=view',
  )
  expect(screen.getByText('jane')).toBeTruthy()
  expect(screen.getByText('bob')).toBeTruthy()
  expect(screen.getByText('devs')).toBeTruthy()
  expect(screen.getByText('readers')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'builder' }).getAttribute('href')).toBe(
    '/cluster-permission/service-account?selected=builder',
  )
  expect(screen.getByText('view-binding')).toBeTruthy()
})

test('service-account-link-selects-its-namespace', async () => {
  const user = userEvent.setup()
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json({ kind: 'rolebindings', cluster: 'prod', items: [editBinding] }),
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

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'rolebindings', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderView()

  expect(await screen.findByText('No role bindings found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on rolebindings' } },
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
    await screen.findByText(/Error loading role bindings: RBAC_DENIED: list on rolebindings/),
  ).toBeTruthy()
})

test('ignores-empty-subjects-and-unknown-role-kinds', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/rolebindings', () =>
      HttpResponse.json({
        kind: 'rolebindings',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'bare', namespace: 'team-a' },
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
