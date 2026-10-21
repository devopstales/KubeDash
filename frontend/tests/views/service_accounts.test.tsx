import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, expect, test, vi } from 'vitest'
import { server } from '../msw'
import ServiceAccountsView from '../../src/views/ClusterPermission/ServiceAccounts'
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
        <ServiceAccountsView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

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
