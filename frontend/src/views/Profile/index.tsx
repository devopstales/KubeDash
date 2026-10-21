import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { CButton, CCard, CCardBody, CCardHeader, CCardTitle, CCol, CRow } from '@coreui/react'
import { useCluster } from '../../hooks/useCluster'
import { apiFetch } from '../../lib/api'

/**
 * ADR-0021: the post-login landing. Identity card from the app-wide
 * useCluster() me query (grew in TICKET-16: auth_source, kubeconfig_source,
 * last_login_at) + logout: POST /api/v1/auth/logout (revokes the session
 * refresh tokens; best-effort — storage is cleared and the user is sent to
 * /login even if the POST fails), then both kd_* keys are dropped.
 */
const ProfileView = () => {
  const navigate = useNavigate()
  const { me } = useCluster()
  const [loggingOut, setLoggingOut] = useState(false)

  const logout = async () => {
    setLoggingOut(true)
    try {
      await apiFetch('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      // The client-side session is over either way: a failed revocation
      // only leaves server-side refresh tokens unexpired, not this login.
      localStorage.removeItem('kd_token')
      localStorage.removeItem('kd_refresh')
      setLoggingOut(false)
      navigate('/login', { replace: true })
    }
  }

  if (!me) {
    return <div>Loading profile…</div>
  }

  const lastLogin = me.last_login_at ? new Date(me.last_login_at) : null
  const lastLoginText =
    lastLogin && !Number.isNaN(lastLogin.getTime())
      ? new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(
          lastLogin,
        )
      : null

  return (
    <CRow>
      <CCol xs={12} lg={6}>
        <CCard>
          <CCardHeader>
            <CCardTitle>Profile</CCardTitle>
          </CCardHeader>
          <CCardBody>
            <dl className="row mb-0">
              <dt className="col-sm-4">Name</dt>
              <dd className="col-sm-8">{me.display_name ?? '—'}</dd>
              <dt className="col-sm-4">Email</dt>
              <dd className="col-sm-8">{me.email ?? '—'}</dd>
              <dt className="col-sm-4">Groups</dt>
              <dd className="col-sm-8">
                {me.groups.length > 0 ? (
                  <span className="d-inline-flex flex-wrap gap-1">
                    {me.groups.map((g) => (
                      <span key={g} className="badge bg-secondary-subtle">
                        {g}
                      </span>
                    ))}
                  </span>
                ) : (
                  '—'
                )}
              </dd>
              <dt className="col-sm-4">Role</dt>
              <dd className="col-sm-8">
                <span className="badge bg-primary-subtle">{me.role}</span>
              </dd>
              <dt className="col-sm-4">Auth source</dt>
              <dd className="col-sm-8">
                <span className="badge bg-info-subtle">{me.auth_source}</span>
              </dd>
              {me.kubeconfig_source && (
                <>
                  <dt className="col-sm-4">Admin kubeconfig source</dt>
                  <dd className="col-sm-8">{me.kubeconfig_source}</dd>
                </>
              )}
              {lastLoginText && (
                <>
                  <dt className="col-sm-4">Last login</dt>
                  <dd className="col-sm-8">{lastLoginText}</dd>
                </>
              )}
            </dl>
            <CButton
              className="mt-3"
              color="danger"
              disabled={loggingOut}
              onClick={() => {
                void logout()
              }}
            >
              {loggingOut ? 'Logging out…' : 'Log out'}
            </CButton>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  )
}

export default ProfileView
