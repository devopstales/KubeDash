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

// ADR-0040: identity arrives as a prop from ObjectRoute (the active ref),
// never from the URL — render on the CLEAN list route (no query string).
const renderAt = (ui: ReactElement, path = '/cluster/namespace') => {
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
  renderAt(<NamespaceDataView name="team-a" />)
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
  // R1: the URL never carries identity — the clean list route.
  expect(window.location.search).toBe('')
})

test('shows-the-4.1-bookmark-namespace-via-props', async () => {
  // The 4.1 `?namespace=` bookmark is dropped from the view (R7's redirect
  // covers it); the identity is the prop, rendered on the clean route.
  renderAt(<NamespaceDataView name="default" />)
  expect(await screen.findByText('2026-10-19T10:00:00Z')).toBeTruthy()
  expect(screen.getByText('Namespace Data')).toBeTruthy()
  expect(screen.getByText('No annotations')).toBeTruthy()
  expect(screen.getByText('No labels')).toBeTruthy()
  // R1: clean URL — the bookmark query no longer exists on this path.
  expect(window.location.search).toBe('')
})

test('namespace-data-reports-a-missing-name', () => {
  renderAt(<NamespaceDataView name="" />)
  expect(screen.getByText('Error: Namespace name not provided')).toBeTruthy()
})

test('namespace-data-reports-a-missing-namespace', async () => {
  renderAt(<NamespaceDataView name="gone" />)
  expect(await screen.findByText(/Namespace 'gone' not found/)).toBeTruthy()
})
