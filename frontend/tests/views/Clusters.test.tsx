import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { server } from '../msw'
import { http, HttpResponse } from 'msw'
import ClustersView from '../../src/views/Clusters'

const KUBECONFIG = 'apiVersion: v1\nkind: Config\n'

const renderClusters = () =>
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter initialEntries={['/clusters']}>
        <ClustersView />
      </MemoryRouter>
    </QueryClientProvider>,
  )

const mockList = (role = 'admin', itemRole: string | null = null) =>
  server.use(
    http.get('*/api/v1/auth/me', () =>
      HttpResponse.json({
        sub: `${role}-sub`,
        email: `${role}@example.com`,
        display_name: role,
        groups: [],
        role,
        auth_source: 'oidc',
        kubeconfig_source: null,
        last_login_at: null,
      }),
    ),
    http.get('*/api/v1/clusters', () =>
      HttpResponse.json({
        items: [
          {
            id: 1,
            name: 'prod',
            api_server: 'https://prod.example',
            context: 'prod-ctx',
            status: 'up',
            role: itemRole,
          },
        ],
      }),
    ),
  )

beforeEach(() => {
  mockList()
})

afterEach(() => {
  localStorage.clear()
  vi.restoreAllMocks()
})

describe('ClustersView', () => {
  test('lists bound clusters with the 4.1 Context/URL/Action columns', async () => {
    renderClusters()
    expect(await screen.findByText('prod-ctx')).toBeTruthy()
    for (const title of ['Context', 'URL', 'Action']) {
      expect(screen.getByRole('columnheader', { name: title })).toBeTruthy()
    }
    expect(screen.getByText('https://prod.example')).toBeTruthy()
  })

  test('admin creates a cluster from the add dialog', async () => {
    const user = userEvent.setup()
    const posted = vi.fn()
    server.use(
      http.post('*/api/v1/clusters', async ({ request }) => {
        posted(await request.json())
        return HttpResponse.json({ id: 2, name: 'staging' }, { status: 201 })
      }),
    )
    renderClusters()
    expect(await screen.findByText('prod-ctx')).toBeTruthy()
    await user.click(screen.getByRole('button', { name: /add cluster/i }))
    // Explicit .focus() + paste (not click-then-paste): the click's
    // focus default-action is load-dependent in jsdom and the paste then
    // silently lands on no editable element (W042 hardening).
    const nameField = screen.getByLabelText(/^name$/i)
    nameField.focus()
    await user.paste('staging')
    const ctxField = screen.getByLabelText(/config context/i)
    ctxField.focus()
    await user.paste('staging-ctx')
    const urlField = screen.getByLabelText(/api url/i)
    urlField.focus()
    await user.paste('https://staging.example')
    const kcField = screen.getByLabelText(/kubeconfig/i)
    kcField.focus()
    await user.paste(KUBECONFIG)
    const buttons = screen.getAllByRole('button', { name: /^add cluster$/i })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() =>
      expect(posted).toHaveBeenCalledWith({
        name: 'staging',
        api_server: 'https://staging.example',
        context: 'staging-ctx',
        kubeconfig: KUBECONFIG,
      }),
    )
  })

  test('admin edits a cluster without resending the stored kubeconfig', async () => {
    const user = userEvent.setup()
    const updated = vi.fn()
    server.use(
      http.put('*/api/v1/clusters/1', async ({ request }) => {
        updated(await request.json())
        return HttpResponse.json({ id: 1, name: 'prod', status: 'up' })
      }),
    )
    renderClusters()
    await user.click(await screen.findByRole('button', { name: /edit prod/i }))
    const url = screen.getByLabelText(/api url/i)
    await user.clear(url)
    // Deterministic focus before paste (W042 hardening — same class as the
    // add-dialog flow).
    url.focus()
    await user.paste('https://prod2.example')
    const buttons = screen.getAllByRole('button', { name: /^update cluster$/i })
    await user.click(buttons[buttons.length - 1])
    await waitFor(() =>
      expect(updated).toHaveBeenCalledWith({
        name: 'prod',
        api_server: 'https://prod2.example',
        context: 'prod-ctx',
      }),
    )
  })

  test('edit-modal-kubeconfig-hint-is-associated-with-the-textarea', async () => {
    // W048: the "keep the stored kubeconfig" hint must be discoverable by
    // assistive tech (aria-describedby), not just visible text.
    const user = userEvent.setup()
    renderClusters()
    await user.click(await screen.findByRole('button', { name: /edit prod/i }))
    const kubeconfig = screen.getByLabelText(/kubeconfig/i)
    expect(kubeconfig).toHaveAttribute('aria-describedby', 'cluster-kubeconfig-hint')
    expect(screen.getByText('Leave empty to keep the stored kubeconfig.')).toBeTruthy()
  })

  test('add-dialog-disabled-submit-names-the-missing-fields', async () => {
    // W048: a disabled submit with no discoverable reason — the footer
    // names exactly the fields that are missing.
    const user = userEvent.setup()
    renderClusters()
    expect(await screen.findByText('prod-ctx')).toBeTruthy()
    await user.click(screen.getByRole('button', { name: /add cluster/i }))

    const buttons = screen.getAllByRole('button', { name: /^add cluster$/i })
    expect(buttons[buttons.length - 1]).toBeDisabled()
    expect(
      screen.getByText(
        'Required: Name, Kubernetes API URL, Kubernetes Config Context, Kubeconfig',
      ),
    ).toBeTruthy()
  })

  test('admin deletes a cluster after confirmation', async () => {
    const user = userEvent.setup()
    const deleted = vi.fn()
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    server.use(http.delete('*/api/v1/clusters/1', () => (deleted(), HttpResponse.json({}))))
    renderClusters()
    await user.click(await screen.findByRole('button', { name: /delete prod/i }))
    await waitFor(() => expect(deleted).toHaveBeenCalled())
    expect(vi.mocked(window.confirm).mock.calls[0][0]).toContain('prod')
  })

  test('non-admin sees the list without mutation controls', async () => {
    mockList('user')
    renderClusters()
    expect(await screen.findByText('prod-ctx')).toBeTruthy()
    expect(screen.queryByRole('button', { name: /add cluster/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /edit prod/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /delete prod/i })).toBeNull()
  })

  test('cluster admin sees edit and delete for their own cluster', async () => {
    // The platform role is 'user', but the binding role on the row is
    // 'admin' (the registering user's auto-binding) — the backend allows
    // the same, so the UI must show the row controls.
    mockList('user', 'admin')
    renderClusters()
    expect(await screen.findByText('prod-ctx')).toBeTruthy()
    expect(screen.getByRole('button', { name: /edit prod/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /delete prod/i })).toBeTruthy()
    // The header Add action stays platform-admin only
    expect(screen.queryByRole('button', { name: /add cluster/i })).toBeNull()
  })

  test('save failure keeps the error visible in the dialog', async () => {
    const user = userEvent.setup()
    server.use(
      http.post('*/api/v1/clusters', () =>
        HttpResponse.json(
          { error: { code: 'INVALID_KUBECONFIG', message: 'kubeconfig has no clusters' } },
          { status: 422 },
        ),
      ),
    )
    renderClusters()
    expect(await screen.findByText('prod-ctx')).toBeTruthy()
    await user.click(screen.getByRole('button', { name: /add cluster/i }))
    await user.click(screen.getByLabelText(/^name$/i))
    await user.paste('staging')
    await user.click(screen.getByLabelText(/config context/i))
    await user.paste('staging-ctx')
    await user.click(screen.getByLabelText(/api url/i))
    await user.paste('https://staging.example')
    await user.click(screen.getByLabelText(/kubeconfig/i))
    await user.paste('not a mapping: []')
    const buttons = screen.getAllByRole('button', { name: /^add cluster$/i })
    await user.click(buttons[buttons.length - 1])
    // The error renders IN the dialog (the modal stays open on failure),
    // not behind its overlay in the card body.
    expect(await screen.findByText(/kubeconfig has no clusters/)).toBeTruthy()
    expect(screen.getByText('Create Cluster')).toBeTruthy()
  })

  test('empty registry renders 4.1 empty text', async () => {
    server.use(http.get('*/api/v1/clusters', () => HttpResponse.json({ items: [] })))
    renderClusters()
    expect(await screen.findByText('No cluster configurations found')).toBeTruthy()
  })
})
