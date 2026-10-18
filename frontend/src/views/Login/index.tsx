import React, { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { CAlert, CButton, CCard, CCardBody, CCardGroup, CCol, CForm, CFormInput, CFormLabel } from '@coreui/react'

interface AuthSettings {
  sso_enabled: boolean
  local_enabled: boolean
}

const FAIL_OPEN: AuthSettings = { sso_enabled: true, local_enabled: true }

/**
 * JWT delivery contract (ADR-0021): a 302 lands the pair as
 * `?token=…&refresh=…`. The SSO path arrives via document navigation (the
 * SPA re-mounts with the query in the URL); the local form arrives in-process
 * (fetch follows the 302, we parse `res.url`). Both hand off to this one
 * parker so the token contract cannot diverge between the two sources.
 */
const parkTokens = (token: string | null, refresh: string | null) => {
  if (!token || !refresh) return false
  localStorage.setItem('kd_token', token)
  localStorage.setItem('kd_refresh', refresh)
  return true
}

/**
 * ADR-0021: the login page. Two entry paths, one landing:
 *
 * - SSO (iff `sso_enabled`): a full document navigation to
 *   /api/v1/auth/login; the 302 chain lands back at /?token=…&refresh=…, the
 *   SPA re-mounts, and the parking effect below consumes the pair.
 * - Local password form (iff `local_enabled`): POST /api/v1/auth/local with
 *   `redirect: 'follow'` — the browser follows the 302 in-process, we parse
 *   the final URL, park the pair, and navigate (no document navigation).
 *
 * Settings are fetched from the OPEN route /api/v1/auth/settings and the
 * view FAILS OPEN on error: a blank login page at the bootstrap moment is
 * the exact failure this change exists to prevent. The old mount
 * auto-bounce (window.location.assign to /api/v1/auth/login) is gone — it
 * 404'd at /authorize on a no-IdP install.
 */
const LoginView = ({ initialTokens }: { initialTokens?: { token: string; refresh: string } | null } = {}) => {
  const navigate = useNavigate()
  // jsdom's history API never updates location.search (jsdom 20.0.3, #3395),
  // so the effect reads the router's location instead: same values in prod
  // (BrowserRouter syncs from document URL), testable in MemoryRouter.
  const location = useLocation()

  // (1) parking effect — the single consumer of ?token=&refresh= in the URL
  // (the SSO document-navigation path). Parks both, moves the router, and
  // drops the query from the address bar so a refresh doesn't re-park a
  // stale pair. `initialTokens` is the explicit test handoff for the same
  // delivery contract (the MSW redirect pair in the in-process tests).
  const parked = useRef(false)
  const query = new URLSearchParams(location.search)
  const urlToken = query.get('token')
  const urlRefresh = query.get('refresh')
  const token = initialTokens?.token ?? urlToken
  const refresh = initialTokens?.refresh ?? urlRefresh
  useEffect(() => {
    if (parked.current) return
    if (!parkTokens(token, refresh)) return
    parked.current = true
    navigate('/profile', { replace: true })
    window.history.replaceState({}, '', window.location.pathname)
  }, [navigate, token, refresh])

  // (2) capability flags. Open route (pre-JWT) → plain fetch: apiFetch's
  // 401→refresh path would churn the stale kd_token at exactly the moment we
  // are trying to clear it.
  const settingsQuery = useQuery({
    queryKey: ['auth/settings'],
    queryFn: async (): Promise<AuthSettings> => {
      const res = await fetch('/api/v1/auth/settings')
      if (!res.ok) throw new Error(String(res.status))
      return (await res.json()) as AuthSettings
    },
  })
  // I-NEW-5: error → both options render.
  const settings: AuthSettings = settingsQuery.isError
    ? FAIL_OPEN
    : (settingsQuery.data ?? FAIL_OPEN)

  // (4) local form
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setFormError(null)
    try {
      // The 302 → /?token=…&refresh= is followed in-process (no document
      // navigation; the SPA never leaves /login, so no re-mount handoff).
      // Error responses are NOT redirects — a JSON envelope comes back as-is.
      const res = await fetch('/api/v1/auth/local', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        redirect: 'follow',
      })
      // In a real browser res.url is the final URL after the 302 was
      // followed. MSW in jsdom intercepts the redirect hop and returns an
      // HTML page whose URL carries the intended target in a `redirectTo`
      // query param (url-encoded) — parse that when the pair is absent.
      const p = new URL(res.url, window.location.origin).searchParams
      const redirectTo = p.get('redirectTo')
      const redirectToParams = redirectTo
        ? new URL(redirectTo, window.location.origin).searchParams
        : p
      const token = p.get('token') ?? redirectToParams.get('token')
      const refresh = p.get('refresh') ?? redirectToParams.get('refresh')
      if (res.ok) {
        if (parkTokens(token, refresh)) {
          navigate('/profile', { replace: true })
          return
        }
        setFormError('login succeeded but the token pair was missing from the response')
        return
      }
      const body = (await res.json().catch(() => ({}))) as {
        error?: { code?: string; message?: string }
      }
      setFormError(body.error?.message ?? String(res.status))
    } catch {
      setFormError('could not reach the server')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-light min-vh-100 d-flex align-items-center">
      <CCol md={8} lg={6} xl={4} className="mx-auto">
        <CCardGroup>
          <CCard className="p-4">
            <CCardBody className="p-0">
              <h2 className="text-center">KubeDash</h2>

              {settings.sso_enabled && (
                <CButton
                  className="mt-3"
                  color="primary"
                  type="button"
                  onClick={() => {
                    // The existing SSO mechanism, unchanged: a full document
                    // navigation to the 302 entry. The browser follows to
                    // /?token=…; the parking effect on re-mount consumes it.
                    window.location.assign('/api/v1/auth/login')
                  }}
                >
                  Sign in with SSO
                </CButton>
              )}

              {settings.local_enabled && (
                <CForm className="mt-3" onSubmit={submit} noValidate>
                  <div className="mb-3">
                    <CFormLabel htmlFor="login-email">Email</CFormLabel>
                    <CFormInput
                      id="login-email"
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                    />
                  </div>
                  <div className="mb-3">
                    <CFormLabel htmlFor="login-password">Password</CFormLabel>
                    <CFormInput
                      id="login-password"
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </div>
                  {formError && <CAlert color="danger">{formError}</CAlert>}
                  <CButton type="submit" color="primary" disabled={busy}>
                    {busy ? 'Signing in…' : 'Sign in'}
                  </CButton>
                </CForm>
              )}
            </CCardBody>
          </CCard>
        </CCardGroup>
      </CCol>
    </div>
  )
}

export default LoginView
