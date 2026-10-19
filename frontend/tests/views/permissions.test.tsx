import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import PermissionsView from '../../src/views/Permissions'

// ponytail: jsdom has no real downloads — spy on URL.createObjectURL + the
// anchor's click() to assert the download was TRIGGERED with the right
// filename; the Blob handed to createObjectURL carries the mock YAML.
const makeDownloadSpy = () => {
  const clicks: string[] = []
  const createObjectURL = vi
    .spyOn(URL, 'createObjectURL')
    .mockImplementation(() => `blob:mock-${clicks.length + 1}`)
  const originalCreateElement = document.createElement.bind(document)
  const createElement = vi.spyOn(document, 'createElement').mockImplementation(
    (tag: string) => {
      const el = originalCreateElement(tag)
      if (tag.toLowerCase() === 'a') {
        ;(el as HTMLAnchorElement).click = () => {
          clicks.push((el as HTMLAnchorElement).download)
        }
      }
      return el
    },
  )
  return {
    clicks,
    createObjectURL,
    cleanup: () => {
      createObjectURL.mockRestore()
      createElement.mockRestore()
    },
  }
}

const renderView = () => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/permissions']}>
        <PermissionsView />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('PermissionsView', () => {
  afterEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  test('renders the caller\u0027s bindings from the API', async () => {
    server.use(
      http.get('*/api/v1/permissions/my-access', () =>
        HttpResponse.json([
          { cluster: 'prod', namespace: 'team-a', template: 'developer', created_at: '2026-10-19T00:00:00Z' },
          { cluster: 'staging', namespace: null, template: 'viewer', created_at: '2026-10-18T00:00:00Z' },
        ]),
      ),
    )
    renderView()
    expect(await screen.findByText('prod')).toBeTruthy()
    expect(await screen.findByText('staging')).toBeTruthy()
    expect(screen.getByText('developer')).toBeTruthy()
    // namespace null renders as a placeholder, not an empty cell
    expect(screen.getAllByText('\u2014').length).toBeGreaterThanOrEqual(1)
  })

  test('user-downloads-a-kubeconfig-from-my-access', async () => {
    const user = userEvent.setup()
    server.use(
      http.get('*/api/v1/permissions/my-access', () =>
        HttpResponse.json([
          { cluster: 'prod', namespace: 'team-a', template: 'developer', created_at: '2026-10-19T00:00:00Z' },
        ]),
      ),
      http.get('*/api/v1/kubeconfig', () =>
        new HttpResponse('apiVersion: v1\nkind: Config\n', {
          status: 200,
          headers: {
            'Content-Type': 'application/yaml',
            'Content-Disposition': 'attachment; filename="kubedash-kubeconfig.yaml"',
          },
        }),
      ),
    )
    const dl = makeDownloadSpy()
    renderView()
    const button = await screen.findByRole('button', { name: /download kubeconfig/i })
    await user.click(button)
    await waitFor(() => expect(dl.clicks).toEqual(['kubedash-kubeconfig.yaml']))
    // the downloaded blob is the YAML body, not a JSON error
    const url = dl.createObjectURL.mock.results[0].value as string
    expect(url).toMatch(/^blob:mock-/)
    dl.cleanup()
  })

  test('my-access-shows-an-empty-state-for-no-bindings', async () => {
    server.use(
      http.get('*/api/v1/permissions/my-access', () => HttpResponse.json([])),
    )
    renderView()
    expect(await screen.findByText(/no cluster access yet/i)).toBeTruthy()
    expect(document.querySelector('table')).toBeNull()
    // the download button is still offered — the 404 surfaces its message
    expect(screen.getByRole('button', { name: /download kubeconfig/i })).toBeTruthy()
  })

  test('download failure surfaces the error message, no unhandled rejection', async () => {
    const user = userEvent.setup()
    server.use(
      http.get('*/api/v1/permissions/my-access', () => HttpResponse.json([])),
      http.get('*/api/v1/kubeconfig', () =>
        HttpResponse.json({ error: { code: 'NO_BINDINGS', message: 'No cluster access yet' } }, { status: 404 }),
      ),
    )
    const dl = makeDownloadSpy()
    const onerror = vi.fn()
    window.addEventListener('error', onerror)
    renderView()
    const button = await screen.findByRole('button', { name: /download kubeconfig/i })
    await user.click(button)
    expect(await screen.findByText(/no cluster access yet/i, { selector: '.text-danger' })).toBeTruthy()
    // the 404 body must NOT have been saved as a file
    expect(dl.createObjectURL).not.toHaveBeenCalled()
    dl.cleanup()
    window.removeEventListener('error', onerror)
  })
})
