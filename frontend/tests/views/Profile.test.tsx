import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Navigate, Route, Routes } from 'react-router-dom'
import { HttpResponse, http } from 'msw'
import { beforeEach, describe, expect, it } from 'vitest'
import { server } from '../msw'
import ProfileView from '../../src/views/Profile'

const LOGIN_ENTRY = '2026-10-18T09:30:00Z'

const meHandler = (me: Record<string, unknown>) =>
  http.get('*/api/v1/auth/me', () => HttpResponse.json(me))

const renderProfile = () => {
  localStorage.setItem('kd_token', 'tok')
  localStorage.setItem('kd_refresh', 'ref')
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/profile']}>
        <Routes>
          <Route path="/profile" element={<ProfileView />} />
          <Route path="/login" element={<div>LOGIN-LANDING</div>} />
          <Route path="*" element={<Navigate to="/clusters" replace />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Profile view', () => {
  beforeEach(() => {
    server.use(
      http.get('*/api/v1/clusters', () => HttpResponse.json({ items: [] })),
      http.post('*/api/v1/auth/logout', () => HttpResponse.json({ status: 'ok' })),
    )
  })

  it('renders the identity card: name, email, groups, role + auth-source badges, last login, kubeconfig source', async () => {
    server.use(
      meHandler({
        sub: 'u1',
        email: 'dev@kubedash.local',
        display_name: 'Dev',
        groups: ['sre', 'platform'],
        role: 'admin',
        auth_source: 'oidc',
        kubeconfig_source: '/etc/kubedash/admin.kubeconfig',
        last_login_at: LOGIN_ENTRY,
      }),
    )
    renderProfile()
    expect(await screen.findByText('Dev')).toBeInTheDocument()
    expect(screen.getByText('dev@kubedash.local')).toBeInTheDocument()
    expect(screen.getByText('sre')).toBeInTheDocument()
    expect(screen.getByText('platform')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('oidc')).toBeInTheDocument()
    expect(screen.getByText('/etc/kubedash/admin.kubeconfig')).toBeInTheDocument()
    // FU-3: Intl formats in the local timezone, so assert the "Last login"
    // label is present with a non-empty formatted value (timezone-
    // independent) rather than a zone-pinned literal string.
    const lastLoginLabel = await screen.findByText('Last login')
    const lastLoginValue = lastLoginLabel.nextElementSibling
    expect(lastLoginValue).not.toBeNull()
    expect(lastLoginValue?.textContent?.length).toBeGreaterThan(0)
  })

  it('renders a non-admin me without kubeconfig source and with the local auth-source badge', async () => {
    server.use(
      meHandler({
        sub: 'u2',
        email: 'dev2@kubedash.local',
        display_name: 'Dev Two',
        groups: [],
        role: 'user',
        auth_source: 'local',
        kubeconfig_source: null,
        last_login_at: null,
      }),
    )
    renderProfile()
    expect(await screen.findByText('Dev Two')).toBeInTheDocument()
    expect(screen.getByText('user')).toBeInTheDocument()
    expect(screen.getByText('local')).toBeInTheDocument()
    expect(screen.queryByText(/kubeconfig/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/last login/i)).not.toBeInTheDocument()
  })

  it('logout POSTs /api/v1/auth/logout, clears both storage keys, and navigates to /login', async () => {
    let logoutHits = 0
    server.use(
      meHandler({
        sub: 'u3',
        email: 'dev3@kubedash.local',
        display_name: 'Dev Three',
        groups: [],
        role: 'user',
        auth_source: 'oidc',
        kubeconfig_source: null,
        last_login_at: null,
      }),
      http.post('*/api/v1/auth/logout', () => {
        logoutHits++
        return HttpResponse.json({ status: 'ok' })
      }),
    )
    const { container } = renderProfile()
    fireEvent.click(await screen.findByRole('button', { name: /log ?out/i }))
    // the logout POST is the last await before storage-clear + navigate
    await waitFor(() => expect(logoutHits).toBe(1))
    expect(localStorage.getItem('kd_token')).toBeNull()
    expect(localStorage.getItem('kd_refresh')).toBeNull()
    expect(await screen.findByText('LOGIN-LANDING')).toBeInTheDocument()
    expect(container).toHaveTextContent('LOGIN-LANDING')
  })

  it('logout still clears storage and navigates when the POST fails (revocation best-effort)', async () => {
    server.use(
      meHandler({
        sub: 'u4',
        email: 'dev4@kubedash.local',
        display_name: 'Dev Four',
        groups: [],
        role: 'user',
        auth_source: 'oidc',
        kubeconfig_source: null,
        last_login_at: null,
      }),
      http.post('*/api/v1/auth/logout', () => HttpResponse.json({}, { status: 500 })),
    )
    const { container } = renderProfile()
    fireEvent.click(await screen.findByRole('button', { name: /log ?out/i }))
    expect(await screen.findByText('LOGIN-LANDING')).toBeInTheDocument()
    expect(localStorage.getItem('kd_token')).toBeNull()
    expect(localStorage.getItem('kd_refresh')).toBeNull()
  })
})
