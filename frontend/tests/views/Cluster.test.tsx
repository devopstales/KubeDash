import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, test } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import ClusterView from '../../src/views/Cluster'
import { useClusterStore } from '../../src/store/cluster'

describe('ClusterView', () => {
  beforeEach(() => {
    useClusterStore.getState().setSelectedCluster({ id: 1, name: 'prod' })
    server.use(
      http.get('*/api/v1/clusters', () =>
        HttpResponse.json({
          items: [
            {
              id: 1,
              name: 'prod',
              api_server: 'https://api.prod:6443',
              context: 'prod-admin',
              status: 'ready',
              last_probe_at: '2026-10-21T10:00:00Z',
            },
          ],
        }),
      ),
      http.get('*/api/v1/clusters/1', () =>
        HttpResponse.json({
          id: 1,
          name: 'prod',
          api_server: 'https://api.prod:6443',
          context: 'prod-admin',
          status: 'ready',
          last_probe_at: '2026-10-21T10:00:00Z',
        }),
      ),
      http.get('*/api/v1/clusters/1/health', () => HttpResponse.json({ status: 'up' })),
    )
  })

  test('renders cluster details and live status instead of pods', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/clusters/1']}>
          <Routes>
            <Route path="/clusters/:id" element={<ClusterView />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('prod')).toBeTruthy()
    expect(screen.getByText('Cluster status')).toBeTruthy()
    expect(screen.getByText('https://api.prod:6443')).toBeTruthy()
    expect(screen.getByText('prod-admin')).toBeTruthy()
    expect(screen.getByText('ready')).toBeTruthy()
    expect(screen.getByText('up')).toBeTruthy()
    expect(screen.queryByText('Pods')).toBeNull()
  })
})
