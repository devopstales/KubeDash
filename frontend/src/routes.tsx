import React from 'react'
import { Navigate, useLocation } from 'react-router-dom'

import { useCluster } from './hooks/useCluster'

/**
 * Route guard for the SPA shell: no stored kd_token → /login.
 *
 * /auth/me is not the gate: a stale/failed `me` query doesn't mean the
 * token is dead (apiFetch refreshes transparently on 401), and gating on
 * the query would bounce logged-in users on a flaky first fetch. The
 * guard uses `useCluster()` so the bound-cluster list and identity are
 * fetched once here, app-wide, for the header switcher.
 */
export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation()
  const { me } = useCluster()
  void me

  if (!localStorage.getItem('kd_token')) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return <>{children}</>
}

/**
 * Admin gate for /admin/permissions (TICKET-07): the ROUTE redirect is the
 * real control (scenario a-non-admin-is-redirected-away-from-the-admin-view)
 * — `me` not yet fetched → render nothing (ProtectedRoute already checked
 * the token; the first /auth/me flight is in progress); `me` loaded and
 * role !== 'admin' → <Navigate to="/" />. Rendered INSIDE ProtectedRoute,
 * so useCluster() shares the same cached ['me'] query.
 */
export const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { me } = useCluster()
  if (me === null) {
    // ponytail: a spinner-free blank while the shared /auth/me flight is
    // in progress (sub-second, same cache as the header); a CSpinner
    // would need an extra import for no user-visible gain.
    return null
  }
  if (me.role !== 'admin') {
    return <Navigate to="/" replace />
  }
  return <>{children}</>
}
