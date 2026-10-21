import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { http, HttpResponse } from 'msw'
import { afterEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import KubeconfigView from '../../src/views/Kubeconfig'
import { useClusterStore } from '../../src/store/cluster'

const renderView = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/settings/export']}>
        <KubeconfigView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('KubeconfigView', () => {
  afterEach(() => {
    useClusterStore.setState({ selectedCluster: null })
    vi.restoreAllMocks()
  })

  test('renders the 4.1 export page sections', async () => {
    server.use(
      http.get('*/api/v1/clusters', () =>
        HttpResponse.json([{ id: 7, name: 'prod', status: 'ok' }]),
      ),
    )
    renderView()
    expect(await screen.findByText(/the prod Kubernetes cluster/)).toBeTruthy()
    expect(screen.getByText('Welcome Dev')).toBeTruthy()
    expect(screen.getByText('Download KubeConfig')).toBeTruthy()
    for (const label of [
      'Download Kubeconfig',
      'Download Kubectl',
      'Kubectl Plugin',
      'Manual Config',
      'User kubectl',
    ]) {
      expect(screen.getByRole('link', { name: label })).toBeTruthy()
    }
    expect(screen.getByRole('heading', { name: 'Download Kubeconfig File' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Download Kubectl' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Kubectl Plugin' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Authenticate Manually' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Running kubectl' })).toBeTruthy()
    expect(screen.getByText(/Install as Kubectl$/)).toBeTruthy()
    expect(screen.getByText('Install as Kubectl plugin.')).toBeTruthy()
    expect(screen.getByText('Use the plugin.')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Download Config File' })).toBeTruthy()
  })

  test('download config file saves kubedash-kubeconfig.yaml', async () => {
    const user = userEvent.setup()
    server.use(
      http.get(
        '*/api/v1/kubeconfig',
        () =>
          new HttpResponse('apiVersion: v1\nkind: Config\n', {
            status: 200,
            headers: { 'Content-Type': 'application/yaml' },
          }),
      ),
    )
    const clicks: string[] = []
    const createObjectURL = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock')
    const originalCreateElement = document.createElement.bind(document)
    vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
      const el = originalCreateElement(tag)
      if (tag.toLowerCase() === 'a') {
        ;(el as HTMLAnchorElement).click = () => {
          clicks.push((el as HTMLAnchorElement).download)
        }
      }
      return el
    })
    renderView()
    await user.click(await screen.findByRole('button', { name: 'Download Config File' }))
    await waitFor(() => expect(clicks).toEqual(['kubedash-kubeconfig.yaml']))
    expect(createObjectURL).toHaveBeenCalled()
  })

  test('download failure shows the API message', async () => {
    const user = userEvent.setup()
    server.use(
      http.get('*/api/v1/kubeconfig', () =>
        HttpResponse.json(
          { error: { code: 'NO_BINDINGS', message: 'No cluster access yet' } },
          { status: 404 },
        ),
      ),
    )
    renderView()
    await user.click(await screen.findByRole('button', { name: 'Download Config File' }))
    expect(await screen.findByText('NO_BINDINGS: No cluster access yet')).toBeTruthy()
  })
})
