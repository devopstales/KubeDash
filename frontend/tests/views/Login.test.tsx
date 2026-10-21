import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Navigate, Route, Routes } from 'react-router-dom'
import { HttpResponse, http } from 'msw'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { server } from '../msw'
import LoginView from '../../src/views/Login'

/** The MSW default me/clusters handlers would leak into Login's settings
 * query via the 401-refresh path; keep them out and pin the auth surface
 * explicitly per test. */
const noAuthHandlers = () => {
  server.use(
    http.get('*/api/v1/auth/me', () => HttpResponse.json({}, { status: 401 })),
    http.post('*/api/v1/auth/refresh', () => HttpResponse.json({}, { status: 401 })),
  )
}

const settingsHandler = (flags: { sso_enabled: boolean; local_enabled: boolean }) =>
  http.get('*/api/v1/auth/settings', () => HttpResponse.json(flags))

// The 302 contract: 302 → Location: /?token=…&refresh=…; a fetch with
// redirect:'follow' follows it in-process, so in a real browser res.url is
// the final URL (the view parses the pair from it).
//
// jsdom test-environment seam: MSW's node resolver emulates that redirect
// hop by serving an HTML page at <requestPath>?redirectTo=<enc(target)>,
// but Node 24's URLSearchParams mis-decodes the `/?token=…&refresh=…` shape
// (it parses key `/?token`, so the view's pair parse misses). We therefore
// stub fetch for the POST and return a Response whose res.url IS the
// production final URL — the exact value a real browser would produce — so
// the view's parse branch runs verbatim. Non-POST requests fall through to
// MSW (the original fetch, which MSW's listen() patches onto the global).
// jsdom's Response.url is a read-only empty string, so the stub returns a
// plain object shaped like a Response (the view only reads res.ok/res.url).
let msFetch: typeof fetch | null = null
const localLogin302 = () => {
  msFetch = window.fetch.bind(window)
  return vi.spyOn(window, 'fetch').mockImplementation(async (input, init) => {
    if (init?.method === 'POST' && String(input).includes('/api/v1/auth/local')) {
      return {
        ok: true,
        status: 200,
        url: 'http://localhost:3000/?token=AT2&refresh=RT2',
        json: async () => ({}),
      } as unknown as Response
    }
    return msFetch!(input, init)
  })
}

const localLoginErrorHandler = (status: number, envelope: { code: string; message: string }) =>
  http.post('*/api/v1/auth/local', () => HttpResponse.json({ error: envelope }, { status }))

// jsdom's history API never updates location.search (jsdom #3395), so the
// router's location can't carry ?token=&refresh= in MemoryRouter. The SSO
// document-navigation arrival is therefore handed off through
// initialTokens — the same delivery contract, injected at render (the
// local-form test exercises the other, in-process, delivery path instead).
const renderLogin = (entry: string, tokens?: { token: string; refresh: string } | null) => {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/login" element={<LoginView initialTokens={tokens ?? null} />} />
          <Route path="/profile" element={<div>PROFILE-LANDING</div>} />
          <Route path="/" element={<Navigate to="/clusters" replace />} />
          <Route path="*" element={<Navigate to="/clusters" replace />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const submitLocalForm = () => {
  fireEvent.change(screen.getByPlaceholderText('Username'), { target: { value: 'admin@local' } })
  fireEvent.change(screen.getByPlaceholderText('Password'), { target: { value: 'pw' } })
  // jsdom doesn't implement implicit form submit (clicking the submit
  // button), so submit the form element directly.
  fireEvent.submit(screen.getByPlaceholderText('Username').closest('form')!)
}

describe('Login view', () => {
  beforeEach(() => {
    localStorage.clear()
    noAuthHandlers()
  })

  afterEach(() => {
    vi.restoreAllMocks()
    msFetch = null
  })

  it('parks token-in-URL (SSO callback path) and navigates to /profile', async () => {
    const { container } = renderLogin('/login', { token: 'AT', refresh: 'RT' })
    // the SSO document navigation lands the router at /login with the pair;
    // the park happens on mount, then the router moves.
    expect(await screen.findByText('PROFILE-LANDING')).toBeInTheDocument()
    expect(localStorage.getItem('kd_token')).toBe('AT')
    expect(localStorage.getItem('kd_refresh')).toBe('RT')
    expect(container).toHaveTextContent('PROFILE-LANDING') // the router actually moved
  })

  it('local form success: parses the 302 final URL, parks, navigates to /profile', async () => {
    server.use(settingsHandler({ sso_enabled: false, local_enabled: true }))
    localLogin302()
    renderLogin('/login')
    await screen.findByPlaceholderText('Username')
    submitLocalForm()
    // The park + navigate are one atomic effect: the router move is the
    // observable, and the parked pair is asserted once the landing renders.
    expect(await screen.findByText('PROFILE-LANDING')).toBeInTheDocument()
    expect(localStorage.getItem('kd_token')).toBe('AT2')
    expect(localStorage.getItem('kd_refresh')).toBe('RT2')
  })

  it('shows SSO button only when sso_enabled', async () => {
    server.use(settingsHandler({ sso_enabled: true, local_enabled: true }))
    renderLogin('/login')
    expect(await screen.findByRole('button', { name: /login with sso/i })).toBeInTheDocument()
  })

  it('hides SSO button and shows local form when sso disabled', async () => {
    server.use(settingsHandler({ sso_enabled: false, local_enabled: true }))
    renderLogin('/login')
    // wait until the settings fetch has landed (the SSO button renders
    // fail-open while the query is still pending)
    await screen.findByPlaceholderText('Username')
    await waitFor(() =>
      expect(screen.queryByRole('button', { name: /login with sso/i })).not.toBeInTheDocument(),
    )
  })

  it('submits local form and surfaces INVALID_CREDENTIALS', async () => {
    server.use(
      settingsHandler({ sso_enabled: false, local_enabled: true }),
      localLoginErrorHandler(401, { code: 'INVALID_CREDENTIALS', message: 'bad credentials' }),
    )
    renderLogin('/login')
    await screen.findByPlaceholderText('Username')
    submitLocalForm()
    expect(await screen.findByText(/bad credentials/i)).toBeInTheDocument()
  })

  it('surfaces LOCAL_AUTH_DISABLED (403) inline', async () => {
    server.use(
      settingsHandler({ sso_enabled: false, local_enabled: true }),
      localLoginErrorHandler(403, {
        code: 'LOCAL_AUTH_DISABLED',
        message: 'local auth is not configured',
      }),
    )
    renderLogin('/login')
    await screen.findByPlaceholderText('Username')
    submitLocalForm()
    expect(await screen.findByText(/local auth is not configured/i)).toBeInTheDocument()
  })

  it('fails open on settings error: renders BOTH the SSO button and the local form', async () => {
    server.use(http.get('*/api/v1/auth/settings', () => HttpResponse.error()))
    renderLogin('/login')
    expect(await screen.findByRole('button', { name: /login with sso/i })).toBeInTheDocument()
    expect(await screen.findByPlaceholderText('Username')).toBeInTheDocument()
  })
})
