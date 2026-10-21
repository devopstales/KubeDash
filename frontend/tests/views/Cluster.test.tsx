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
      http.get('*/api/v1/clusters/1/resources/pods', () =>
        HttpResponse.json({
          items: [{ metadata: { name: 'p1', namespace: 'default' }, status: { phase: 'Running' } }],
        }),
      ),
    )
  })

  test('renders the pod table for the selected cluster', async () => {
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
    expect(await screen.findByText('p1')).toBeTruthy()
    expect(screen.getByText('Running')).toBeTruthy()
  })
})
