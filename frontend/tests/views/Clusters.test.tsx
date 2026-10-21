import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { beforeAll, beforeEach, describe, expect, test } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import ClustersView from '../../src/views/Clusters'

describe('ClustersView', () => {
  beforeEach(() =>
    server.use(
      http.get('*/api/v1/clusters', () =>
        HttpResponse.json({
          items: [
            {
              id: 1,
              name: 'prod',
              api_server: 'https://prod.example',
              context: 'prod-ctx',
              status: 'up',
            },
          ],
        }),
      ),
    ),
  )

  test('lists bound clusters from the API', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter initialEntries={['/clusters']}>
          <ClustersView />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByText('prod')).toBeTruthy()
  })
})
