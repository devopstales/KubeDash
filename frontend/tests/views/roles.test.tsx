import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import RoleView from '../../src/views/ClusterPermission/Role'
import RoleDataView from '../../src/views/ClusterPermission/RoleData'
import { useClusterStore } from '../../src/store/cluster'

vi.mock('../../src/components/KubeDataTable', () => {
  const React = require('react') as typeof import('react')
  const Column = () => null
  function KubeDataTable({ data, children }: { data: Record<string, unknown>[]; children: React.ReactNode }) {
    const cols = React.Children.toArray(children)
      .filter(React.isValidElement)
      .map((child) => (child as React.ReactElement<{ title: string; data: string; children?: unknown }>).props)
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

const renderAt = (ui: ReactElement, path = '/') => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        {ui}
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

const editRole = {
  metadata: {
    name: 'edit',
    namespace: 'team-a',
    labels: { app: 'web' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"Role"}',
      owner: 'platform',
    },
  },
  rules: [
    {
      api_groups: ['', 'apps'],
      resource_names: ['web'],
      resources: ['pods', 'deployments'],
      verbs: ['get', 'list'],
    },
  ],
}

test('lists-roles-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'roles',
        cluster: 'prod',
        items: [editRole, { metadata: { name: 'view', namespace: 'team-a' }, rules: [] }],
      })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: 'team-a' })
  renderAt(<RoleView />)

  expect(await screen.findByRole('link', { name: 'edit' })).toBeTruthy()
  expect(requested).toBe('team-a')
  expect(screen.getByText('Roles List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Labels',
    'Annotations',
  ])
  expect(screen.getByRole('link', { name: 'edit' }).getAttribute('href')).toBe(
    '/cluster-permission/role/data?name=edit&namespace=team-a',
  )
  expect(screen.getByText('app: web')).toBeTruthy()
  expect(screen.getByText('owner: platform')).toBeTruthy()
  expect(screen.queryByText(/last-applied-configuration/)).toBeNull()
  expect(screen.getByRole('link', { name: 'view' })).toBeTruthy()
})

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'roles', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderAt(<RoleView />)

  expect(await screen.findByText('No roles found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', () =>
      HttpResponse.json({ error: { code: 'RBAC_DENIED', message: 'list on roles' } }, { status: 403 }),
    ),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: 'team-a' })
  renderAt(<RoleView />)

  expect(await screen.findByText(/Error loading roles: RBAC_DENIED: list on roles/)).toBeTruthy()
})

test('shows-role-rules', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/roles', () =>
      HttpResponse.json({ kind: 'roles', cluster: 'prod', items: [editRole] }),
    ),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: 'team-a' })
  renderAt(<RoleDataView />, '/cluster-permission/role/data?name=edit&namespace=team-a')

  expect(await screen.findByText('Rule List')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Roles' }).getAttribute('href')).toBe('/cluster-permission/role')
  expect(screen.getByText('edit')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'API Groups',
    'Non Resources',
    'Resources',
    'Verbs',
  ])
  expect(screen.getByText('apps')).toBeTruthy()
  expect(screen.getByText('web')).toBeTruthy()
  expect(screen.getByText('pods')).toBeTruthy()
  expect(screen.getByText('deployments')).toBeTruthy()
  expect(screen.getByText('get')).toBeTruthy()
  expect(screen.getByText('list')).toBeTruthy()
})

test('role-data-requires-a-name', async () => {
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: 'team-a' })
  renderAt(<RoleDataView />, '/cluster-permission/role/data')

  expect(await screen.findByText('Error: Role name not provided')).toBeTruthy()
})
