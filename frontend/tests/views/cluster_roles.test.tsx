import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ClusterRoleView from '../../src/views/ClusterPermission/ClusterRole'
import ClusterRoleDataView from '../../src/views/ClusterPermission/ClusterRoleData'
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

const renderAt = (ui: ReactElement, path = '/') => {
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

const editClusterRole = {
  metadata: {
    name: 'edit',
    labels: { app: 'web' },
    annotations: {
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"ClusterRole"}',
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

test('lists-cluster-roles-for-selected-cluster', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', ({ request }) => {
      requested = new URL(request.url).search
      return HttpResponse.json({
        kind: 'clusterroles',
        cluster: 'prod',
        items: [editClusterRole, { metadata: { name: 'view' }, rules: [] }],
      })
    }),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  expect(await screen.findByRole('link', { name: 'edit' })).toBeTruthy()
  expect(requested).toBe('')
  expect(screen.getByText('Cluster Role List')).toBeTruthy()
  expect(screen.getByText('Cluster Permissions')).toBeTruthy()
  expect(screen.getByText('Cluster Role')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Labels',
    'Annotations',
  ])
  expect(screen.getByRole('link', { name: 'edit' }).getAttribute('href')).toBe(
    '/cluster-permission/cluster-role/data?name=edit',
  )
  expect(screen.getByText('app: web')).toBeTruthy()
  expect(screen.getByText('owner: platform')).toBeTruthy()
  expect(screen.queryByText(/last-applied-configuration/)).toBeNull()
  expect(screen.getByRole('link', { name: 'view' })).toBeTruthy()
})

test('shows-empty-cluster-role-list', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json({ kind: 'clusterroles', cluster: 'prod', items: [] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  expect(await screen.findByText('No cluster roles found')).toBeTruthy()
})

test('shows-cluster-role-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on clusterroles' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleView />)

  expect(
    await screen.findByText(/Error loading cluster roles: RBAC_DENIED: list on clusterroles/),
  ).toBeTruthy()
})

test('shows-cluster-role-rules', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/clusterroles', () =>
      HttpResponse.json({ kind: 'clusterroles', cluster: 'prod', items: [editClusterRole] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleDataView />, '/cluster-permission/cluster-role/data?name=edit')

  expect(await screen.findByText('pods')).toBeTruthy()
  expect(screen.getByText('Rule List')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Cluster Role' }).getAttribute('href')).toBe(
    '/cluster-permission/cluster-role',
  )
  expect(screen.getByText('edit')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'API Groups',
    'Non Resources',
    'Resources',
    'Verbs',
  ])
  expect(screen.getByText('apps')).toBeTruthy()
  expect(screen.getByText('web')).toBeTruthy()
  expect(screen.getByText('deployments')).toBeTruthy()
  expect(screen.getByText('get')).toBeTruthy()
  expect(screen.getByText('list')).toBeTruthy()
})

test('cluster-role-data-requires-a-name', async () => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ClusterRoleDataView />, '/cluster-permission/cluster-role/data')

  expect(await screen.findByText('Error: Cluster role name not provided')).toBeTruthy()
})
