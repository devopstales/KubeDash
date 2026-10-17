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
