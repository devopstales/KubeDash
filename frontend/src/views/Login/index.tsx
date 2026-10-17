import React, { useEffect, useRef } from 'react'
import { CButton, CCard, CCardBody, CCardGroup, CCol } from '@coreui/react'

/**
 * OIDC entry point. The backend's /api/v1/auth/callback lands the user back
 * on the SPA root with `?token=<access_jwt>&refresh=<refresh_token>` (the
 * JWT delivery contract). This view parks both in localStorage and drops
 * the query string; otherwise it bounces the browser to
 * /api/v1/auth/login to start the OIDC flow.
 */
const LoginView = () => {
  const redirected = useRef(false)

  useEffect(() => {
    if (redirected.current) return
    const params = new URLSearchParams(window.location.search)
    const token = params.get('token')
    const refresh = params.get('refresh')
    if (token && refresh) {
      localStorage.setItem('kd_token', token)
      localStorage.setItem('kd_refresh', refresh)
      window.history.replaceState({}, '', window.location.pathname)
      return
    }
    redirected.current = true
    window.location.assign('/api/v1/auth/login')
  }, [])

  return (
    <div className="bg-light min-vh-100 d-flex align-items-center">
      <CCol md={8} lg={6} xl={4} className="mx-auto">
        <CCardGroup>
          <CCard className="p-4">
            <CCardBody className="p-0">
              <h2 className="text-center">KubeDash</h2>
              <CButton className="mt-3" color="primary">
                Sign in with SSO
              </CButton>
            </CCardBody>
          </CCard>
        </CCardGroup>
      </CCol>
    </div>
  )
}

export default LoginView
