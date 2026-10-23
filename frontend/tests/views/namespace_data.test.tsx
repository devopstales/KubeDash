import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, expect, test } from 'vitest'
import { http, HttpResponse } from 'msw'
import type { ReactElement } from 'react'
import { server } from '../msw'
import NamespaceDataView from '../../src/views/Cluster/NamespaceData'
import { useClusterStore } from '../../src/store/cluster'

const ITEMS = [
  {
    metadata: {
      name: 'team-a',
      creation_timestamp: '2026-10-20T10:00:00Z',
      labels: { team: 'platform' },
      annotations: {
        'kubedash.io/repository': 'https://git.example/team-a',
        'kubedash.io/pipeline': 'javascript:alert(1)',
      },
    },
    status: { phase: 'Active' },
  },
  {
    metadata: { name: 'default', creation_timestamp: '2026-10-19T10:00:00Z' },
    status: { phase: 'Active' },
  },
]

const renderAt = (ui: ReactElement, path = '/') => {
  useClusterStore.setState({
    selectedCluster: { id: 1, name: 'prod' },
    selectedNamespace: null,
  })
  server.use(
    http.get('*/api/v1/clusters/1/resources/namespaces', () =>
      HttpResponse.json({ items: ITEMS, kind: 'namespaces', cluster: 'prod' }),
    ),
  )
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

test('shows-namespace-data-fields', async () => {
  renderAt(<NamespaceDataView />, '/cluster/namespace/data?name=team-a')
  expect(await screen.findByText('2026-10-20T10:00:00Z')).toBeTruthy()
  expect(screen.getByText('Namespace Data')).toBeTruthy()
  expect(screen.getByRole('link', { name: 'Namespaces' }).getAttribute('href')).toBe(
    '/cluster/namespace',
  )
  expect(screen.getByText('Active')).toBeTruthy()
  expect(screen.getByText('kubedash.io/repository')).toBeTruthy()
  expect(screen.getByText('https://git.example/team-a')).toBeTruthy()
  expect(screen.getByText('team')).toBeTruthy()
  expect(screen.getByText('platform')).toBeTruthy()
})

test('namespace-data-accepts-the-4.1-namespace-query', async () => {
  renderAt(<NamespaceDataView />, '/cluster/namespace/data?namespace=default')
  expect(await screen.findByText('2026-10-19T10:00:00Z')).toBeTruthy()
  expect(screen.getByText('Namespace Data')).toBeTruthy()
  expect(screen.getByText('No annotations')).toBeTruthy()
  expect(screen.getByText('No labels')).toBeTruthy()
})

test('namespace-data-reports-a-missing-name', () => {
  renderAt(<NamespaceDataView />, '/cluster/namespace/data')
  expect(screen.getByText('Error: Namespace name not provided')).toBeTruthy()
})

test('namespace-data-reports-a-missing-namespace', async () => {
  renderAt(<NamespaceDataView />, '/cluster/namespace/data?name=gone')
  expect(await screen.findByText(/Namespace 'gone' not found/)).toBeTruthy()
})
