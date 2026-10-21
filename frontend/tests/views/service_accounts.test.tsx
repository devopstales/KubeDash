import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import type { ReactElement } from 'react'
import ServiceAccountsView from '../../src/views/ClusterPermission/ServiceAccounts'
import ServiceAccountDataView from '../../src/views/ClusterPermission/ServiceAccountData'
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

const renderView = (path = '/') => renderAt(<ServiceAccountsView />, path)

afterEach(() => {
  useClusterStore.setState({ selectedCluster: null, selectedNamespace: null })
})

test('lists-service-accounts-in-selected-namespace', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({
        kind: 'serviceaccounts',
        cluster: 'prod',
        items: [
          {
            metadata: { name: 'builder', namespace: 'team-a' },
            secrets: [{ name: 'builder-token' }],
            image_pull_secrets: [{ name: 'registry-cred' }],
          },
          {
            metadata: { name: 'default', namespace: 'team-a' },
            secrets: null,
            image_pull_secrets: null,
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

  expect(await screen.findByText('builder')).toBeTruthy()
  expect(requested).toBe('team-a')
  expect(screen.getByText('Service Accounts List')).toBeTruthy()
  expect(screen.getAllByRole('columnheader').map((th) => th.textContent)).toEqual([
    'Name',
    'Secret',
    'Pull Secret',
  ])
  expect(screen.getByRole('link', { name: 'builder' }).getAttribute('href')).toBe(
    '/cluster-permission/service-account/data?name=builder&namespace=team-a',
  )
  expect(screen.getByRole('link', { name: 'builder-token' }).getAttribute('href')).toBe(
    '/security/secret?selected=builder-token',
  )
  expect(screen.getByRole('link', { name: 'registry-cred' }).getAttribute('href')).toBe(
    '/security/secret?selected=registry-cred',
  )
  expect(screen.getByText('default')).toBeTruthy()
})

test('defaults-to-default-namespace-and-shows-empty-state', async () => {
  let requested = ''
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', ({ request }) => {
      requested = new URL(request.url).searchParams.get('namespace') ?? ''
      return HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [] })
    }),
  )
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' }, selectedNamespace: null })
  renderView()

  expect(await screen.findByText('No service accounts found')).toBeTruthy()
  expect(requested).toBe('default')
})

test('shows-rbac-error', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json(
        { error: { code: 'RBAC_DENIED', message: 'list on serviceaccounts' } },
        { status: 403 },
      ),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView()

  expect(await screen.findByText(/RBAC_DENIED: list on serviceaccounts/)).toBeTruthy()
})

const builderAccount = {
  metadata: {
    name: 'builder',
    namespace: 'team-a',
    creation_timestamp: '2026-01-02T03:04:05Z',
    labels: { app: 'ci' },
    annotations: {
      owner: 'platform',
      'kubectl.kubernetes.io/last-applied-configuration': '{"kind":"ServiceAccount"}',
    },
  },
  secrets: [{ name: 'builder-token' }, { name: 'builder-dockercfg' }],
  image_pull_secrets: [{ name: 'registry-cred' }],
}

test('highlights-the-selected-service-account', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [builderAccount] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderView('/cluster-permission/service-account?selected=builder')

  expect(await screen.findByRole('link', { name: 'builder' })).toHaveAttribute(
    'aria-current',
    'true',
  )
})

test('shows-service-account-secrets', async () => {
  server.use(
    http.get('*/api/v1/clusters/1/resources/serviceaccounts', () =>
      HttpResponse.json({ kind: 'serviceaccounts', cluster: 'prod', items: [builderAccount] }),
    ),
  )
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(
    <ServiceAccountDataView />,
    '/cluster-permission/service-account/data?name=builder&namespace=team-a',
  )

  expect(await screen.findByRole('link', { name: 'builder-token' })).toBeTruthy()
  expect(screen.getByText('Service Account Data')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Service Accounts' }).getAttribute('href')).toBe(
    '/cluster-permission/service-account',
  )
  expect(screen.getByRole('rowheader', { name: 'Name:' })).toBeTruthy()
  expect(screen.getByRole('rowheader', { name: 'Namespace:' })).toBeTruthy()
  expect(screen.getByText('team-a')).toBeTruthy()
  expect(screen.getByText('2026-01-02T03:04:05Z')).toBeTruthy()
  expect(screen.getByText('owner')).toBeTruthy()
  expect(screen.getByText('platform')).toBeTruthy()
  expect(screen.queryByText(/last-applied-configuration/)).toBeNull()
  expect(screen.getByText('app')).toBeTruthy()
  expect(screen.getByText('ci')).toBeTruthy()
  expect(screen.getByRole('rowheader', { name: 'Secret:' })).toBeTruthy()
  expect(screen.getByRole('rowheader', { name: 'Pull Secret:' })).toBeTruthy()
  expect(screen.getByRole('link', { name: 'builder-token' }).getAttribute('href')).toBe(
    '/security/secret/data?name=builder-token&namespace=team-a',
  )
  expect(screen.getByRole('link', { name: 'builder-dockercfg' }).getAttribute('href')).toBe(
    '/security/secret/data?name=builder-dockercfg&namespace=team-a',
  )
  expect(screen.getByRole('link', { name: 'registry-cred' }).getAttribute('href')).toBe(
    '/security/secret/data?name=registry-cred&namespace=team-a',
  )
})

test('service-account-data-requires-a-name', async () => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: 'team-a',
  })
  renderAt(<ServiceAccountDataView />, '/cluster-permission/service-account/data')

  expect(await screen.findByText('Error: Service account name not provided')).toBeTruthy()
})
