import React, { useEffect, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  CAlert,
  CButton,
  CCard,
  CCardBody,
  CCol,
  CForm,
  CFormInput,
  CInputGroup,
  CInputGroupText,
  CRow,
  useColorModes,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilLockLocked, cilMoon, cilSun, cilUser } from '@coreui/icons'
import loginBg from '../../../public/img/login-bg.jpeg'

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

  // Light/dark mode: applies `data-coreui-theme` to <html> (CoreUI's dark vars
  // are already compiled into the bundle) and persists the choice so the
  // dashboard honors it too. The toggle floats top-right, matching the
  // CoreUI template's color-modes switcher.
  const { colorMode, setColorMode } = useColorModes('coreui-theme')
  const toggleTheme = () => setColorMode(colorMode === 'dark' ? 'light' : 'dark')

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
    <div className="bg-primary min-vh-100 d-flex flex-row align-items-center">
      <button
        type="button"
        className="btn btn-primary position-fixed top-0 end-0 m-2 shadow-sm"
        aria-label={colorMode === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        onClick={toggleTheme}
      >
        <CIcon icon={colorMode === 'dark' ? cilSun : cilMoon} />
      </button>
      <div className="container">
        <CRow className="justify-content-center">
          <CCol lg={8}>
            <div className="card-group d-block d-md-flex row">
              {formError && (
                <CAlert
                  className="alert-dismissible fade show"
                  color="danger"
                  dismissible
                  onClose={() => setFormError(null)}
                >
                  {formError}
                </CAlert>
              )}

              <CCard className="col-md-4 p-4 mb-0">
                <CCardBody>
                  <h1>Login</h1>
                  <p className="text-body-secondary">Sign In to your account</p>

                  {settings.sso_enabled && !settings.local_enabled && (
                    // SSO-only install: no local form, so the SSO entry is the
                    // standalone full-document navigation (the 302 entry; the
                    // parking effect on re-mount consumes /?token=…).
                    <CButton
                      className="w-100"
                      color="primary"
                      type="button"
                      onClick={() => window.location.assign('/api/v1/auth/login')}
                    >
                      Login With SSO
                    </CButton>
                  )}

                  {settings.local_enabled && (
                    <CForm className="user" onSubmit={submit} noValidate>
                      <div className="input-group mb-3">
                        <CInputGroupText>
                          <CIcon icon={cilUser} />
                        </CInputGroupText>
                        <CFormInput
                          id="login-email"
                          type="email"
                          placeholder="Username"
                          autoComplete="username"
                          required
                          value={email}
                          onChange={(e) => setEmail(e.target.value)}
                        />
                      </div>
                      <div className="input-group mb-4">
                        <CInputGroupText>
                          <CIcon icon={cilLockLocked} />
                        </CInputGroupText>
                        <CFormInput
                          id="login-password"
                          type="password"
                          placeholder="Password"
                          autoComplete="current-password"
                          required
                          value={password}
                          onChange={(e) => setPassword(e.target.value)}
                        />
                      </div>
                      <div className="row">
                        <div className="col-6">
                          <CButton
                            className="px-4"
                            color="primary"
                            type="submit"
                            disabled={busy}
                          >
                            {busy ? 'Signing in…' : 'Login'}
                          </CButton>
                        </div>
                      </div>

                      {settings.sso_enabled && (
                        <>
                          <hr />
                          <CButton
                            className="w-100"
                            color="primary"
                            type="button"
                            onClick={() => window.location.assign('/api/v1/auth/login')}
                          >
                            Login With SSO
                          </CButton>
                        </>
                      )}
                    </CForm>
                  )}
                </CCardBody>
              </CCard>

              {/* Fixed height pins the card size: the card group is a flex row
                  where both columns stretch to the tallest one. Sizing the image
                  to the tallest possible card (form + SSO) keeps the card the
                  same height whether or not the SSO button renders. */}
              <div
                className="col-lg-6 d-none d-lg-block bg-login-image"
                style={{
                  height: '403px',
                  backgroundImage: `url(${loginBg})`,
                  backgroundPosition: 'center',
                  backgroundSize: 'cover',
                }}
              />
            </div>
          </CCol>
        </CRow>
      </div>
    </div>
  )
}

export default LoginView
