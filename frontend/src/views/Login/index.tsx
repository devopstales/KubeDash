import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
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
 * ADR-0021 / ADR-0025: the login page. Two entry paths, one landing:
 *
 * - SSO (iff `sso_enabled`): a full document navigation to
 *   /api/v1/auth/login; the callback answers `302 /` with HttpOnly cookies,
 *   so the SPA re-mounts on the protected shell and never sees a token.
 * - Local password form (iff `local_enabled`): POST /api/v1/auth/local with
 *   `redirect: 'follow'` — the browser follows the 302 to `/`, processes the
 *   `Set-Cookie`, and `res.ok` is the success signal.
 *
 * No token ever touches this component: there is nothing to park, parse from
 * `res.url`, or scrub from the address bar. Settings are fetched from the
 * OPEN route /api/v1/auth/settings and the view FAILS OPEN on error: a blank
 * login page at the bootstrap moment is the exact failure this change exists
 * to prevent.
 */
const LoginView = () => {
  const navigate = useNavigate()

  // Light/dark mode: applies `data-coreui-theme` to <html> (CoreUI's dark vars
  // are already compiled into the bundle) and persists the choice so the
  // dashboard honors it too. The toggle floats top-right, matching the
  // CoreUI template's color-modes switcher.
  const { colorMode, setColorMode } = useColorModes('coreui-theme')
  const toggleTheme = () => setColorMode(colorMode === 'dark' ? 'light' : 'dark')

  // (2) capability flags. Open route (pre-JWT) → plain fetch: apiFetch's
  // 401→refresh path is for domain calls, not the login page's own probes.
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
      // The 302 to `/` is followed in-process; the browser stores the
      // HttpOnly cookies from that response (ADR-0025). `res.ok` is the
      // success signal — there is no token to parse or park.
      const res = await fetch('/api/v1/auth/local', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
        redirect: 'follow',
      })
      if (res.ok) {
        navigate('/profile', { replace: true })
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
                          <CButton className="px-4" color="primary" type="submit" disabled={busy}>
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
