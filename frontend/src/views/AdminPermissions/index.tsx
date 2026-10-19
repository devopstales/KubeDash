import React, { useState } from 'react'
import {
  CButton,
  CButtonGroup,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AdminUser, AuditEntry, RBACTemplate } from '../../lib/types'
import { useCluster, type ClusterItem } from '../../hooks/useCluster'
import BindModal from './components/BindModal'
import TemplateEditor from './components/TemplateEditor'

/**
 * Admin permissions (TICKET-07): Users / Templates / Audit tabs over
 * /api/v1/admin/*. Reachable at /admin/permissions, wrapped in
 * ProtectedRoute + AdminRoute (role === 'admin'; non-admins redirect to /).
 * API errors surface as text-danger messages (no toasts, no unhandled
 * rejections).
 *
 * User Detail: an INLINE panel (not a CModal) below the users table when a
 * row is clicked — ponytail: a CModal renders into a portal overlay that
 * jsdom's default queries can't see without extra setup, and the inline
 * panel carries the same information. The "per-user bindings" section shows
 * the caller's own my-access rows when the selected user IS the caller
 * (the only per-user binding listing the backend exposes); for other users
 * it shows a limitation note. The Bind form below works for any user.
 */
const AdminPermissionsView = () => {
  const { me } = useCluster()
  const callersSub = me?.sub ?? null

  const usersQuery = useQuery<AdminUser[]>({
    queryKey: ['admin', 'users'],
    queryFn: async () => {
      const r = await apiFetch<AdminUser[]>('/api/v1/admin/users')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const templatesQuery = useQuery<RBACTemplate[]>({
    queryKey: ['admin', 'templates'],
    queryFn: async () => {
      const r = await apiFetch<RBACTemplate[]>('/api/v1/admin/permissions/templates')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  // ponytail: clusters come straight from apiFetch (same queryKey as
  // useCluster's, so the TanStack cache dedupes it with the header) — the
  // modal's picker stays decoupled from the selection-store side effect.
  const clustersQuery = useQuery<ClusterItem[]>({
    queryKey: ['clusters'],
    queryFn: async () => {
      const r = await apiFetch<ClusterItem[] | { items: ClusterItem[] }>('/api/v1/clusters')
      if (r.error) throw new Error(r.error.message)
      return Array.isArray(r.data) ? r.data : (r.data?.items ?? [])
    },
  })

  // The caller's own bindings — the only per-user binding listing the
  // backend exposes (GET /permissions/my-access; there is no
  // GET /admin/users/<id>/bindings endpoint).
  const myAccessQuery = useQuery<{
    cluster: string
    namespace: string | null
    template: string | null
    created_at: string
  }[]>({
    queryKey: ['permissions', 'my-access'],
    queryFn: async () => {
      const r = await apiFetch<{
        cluster: string
        namespace: string | null
        template: string | null
        created_at: string
      }[]>('/api/v1/permissions/my-access')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  // GET /api/v1/audit is a confirmed 501 NOT_IMPLEMENTED stub on the
  // backend (base structure, backend/app/api/audit.py); the tab renders an
  // empty state until the read route lands. No new backend route (backend
  // is closed for this change).
  const auditQuery = useQuery<AuditEntry[] | null>({
    queryKey: ['admin', 'audit'],
    queryFn: async () => {
      const r = await apiFetch<AuditEntry[]>('/api/v1/audit')
      if (r.error) return null
      return r.data ?? []
    },
  })

  // ponytail: CTabs (CoreUI v5) renders the tab button + content as a flat
  // sibling list, which confuses jsdom's queryByRole('tab') and makes
  // nested content land INSIDE the button node (see unbind / audit test
  // output). A CButtonGroup + content section gives us the same UX with
  // plain DOM that the query helpers can see. The real UI trade-off is one
  // extra click (no auto-focus / keyboard arrow navigation).
  const [tab, setTab] = useState<'users' | 'templates' | 'audit'>('users')
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null)
  const [bindOpen, setBindOpen] = useState(false)

  const closeUserDetail = () => {
    setSelectedUser(null)
    setBindOpen(false)
  }

  const onBound = () => {
    usersQuery.refetch()
    myAccessQuery.refetch()
  }

  return (
    <div>
      <CButtonGroup className="mb-3" role="tablist">
        {(['users', 'templates', 'audit'] as const).map((t) => (
          <CButton
            key={t}
            color={tab === t ? 'primary' : 'secondary'}
            active={tab === t}
            onClick={() => setTab(t)}
            aria-selected={tab === t}
            role="tab"
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
          </CButton>
        ))}
      </CButtonGroup>

      {tab === 'users' && (
        <>
        {usersQuery.isLoading ? (
          <div>Loading users…</div>
        ) : usersQuery.error ? (
          <div className="text-danger">
            {usersQuery.error instanceof Error ? usersQuery.error.message : 'Failed to load users'}
          </div>
        ) : (usersQuery.data ?? []).length === 0 ? (
          <div>No users.</div>
        ) : (
          <>
            <CTable striped hover>
              <thead>
                <tr>
                  <th>Display name</th>
                  <th>Sub</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Clusters</th>
                  <th>Last login</th>
                </tr>
              </thead>
              <tbody>
                {(usersQuery.data ?? []).map((u) => (
                  <tr
                    key={u.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => {
                      setSelectedUser(u)
                      setBindOpen(false)
                    }}
                  >
                    <td>{u.display_name ?? '\u2014'}</td>
                    <td>{u.sub}</td>
                    <td>{u.email ?? '\u2014'}</td>
                    <td>{u.role}</td>
                    <td>{u.status}</td>
                    <td>{u.cluster_count}</td>
                    <td>{u.last_login_at ?? '\u2014'}</td>
                  </tr>
                ))}
              </tbody>
            </CTable>

            {selectedUser && (
              <CCard className="mt-3">
                <CCardHeader>
                  <CCardTitle>User detail</CCardTitle>
                </CCardHeader>
                <CCardBody>
                  <div className="mb-3">
                    <strong>{selectedUser.display_name ?? selectedUser.sub}</strong>
                    {' · '}
                    {selectedUser.sub}
                    {' · '}
                    <strong>Role:</strong> {selectedUser.role}
                    {' · '}
                    <strong>Status:</strong> {selectedUser.status}
                    {' · '}
                    <strong>Cluster bindings:</strong> {selectedUser.cluster_count}
                  </div>

                  {selectedUser.sub === callersSub ? (
                    myAccessQuery.isLoading ? (
                      <div>Loading bindings…</div>
                    ) : myAccessQuery.error ? (
                      <div className="text-danger">
                        {myAccessQuery.error instanceof Error
                          ? myAccessQuery.error.message
                          : 'Failed to load bindings'}
                      </div>
                    ) : (myAccessQuery.data ?? []).length === 0 ? (
                      <div>No bindings for you (the caller).</div>
                    ) : (
                      <CTable striped hover>
                        <thead>
                          <tr>
                            <th>Cluster</th>
                            <th>Namespace</th>
                            <th>Template</th>
                            <th>Created</th>
                            <th />
                          </tr>
                        </thead>
                        <tbody>
                          {(myAccessQuery.data ?? []).map((b) => (
                            <tr key={`${b.cluster}/${b.namespace ?? ''}/${b.template ?? ''}`}>
                              <td>{b.cluster}</td>
                              <td>{b.namespace ?? '\u2014'}</td>
                              <td>{b.template ?? '\u2014'}</td>
                              <td>{b.created_at}</td>
                              <td>
                                <CButton
                                  size="sm"
                                  color="danger"
                                  onClick={async (e) => {
                                    e.stopPropagation()
                                    const r = await apiFetch('/api/v1/admin/permissions/bind', {
                                      method: 'DELETE',
                                      headers: { 'Content-Type': 'application/json' },
                                      body: JSON.stringify({
                                        user: selectedUser.sub,
                                        cluster: b.cluster,
                                        namespace: b.namespace,
                                      }),
                                    })
                                    if (!r.error) {
                                      myAccessQuery.refetch()
                                      usersQuery.refetch()
                                    }
                                  }}
                                >
                                  Unbind
                                </CButton>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )
                  ) : (
                    // ponytail: no per-user binding listing endpoint exists
                    // (my-access is the caller's only); the admin list
                    // carries a cluster_count, not the rows. A clean
                    // per-user list needs a backend endpoint this ticket
                    // does not add.
                    <div>
                      Per-user binding listing is not available for other users (the
                      admin list shows only a cluster count). Bind a template below;
                      the unbind surface arrives with the per-user endpoint.
                    </div>
                  )}

                  <div className="mt-3 d-flex gap-2">
                    <CButton
                      color="primary"
                      onClick={() => setBindOpen((v) => !v)}
                    >
                      {bindOpen ? 'Close' : 'Bind'}
                    </CButton>
                    <CButton color="secondary" onClick={closeUserDetail}>
                      Close
                    </CButton>
                  </div>

                  {bindOpen && (
                    <div className="mt-3">
                      <BindModal
                        user={selectedUser.sub}
                        clusters={clustersQuery.data ?? []}
                        templates={templatesQuery.data ?? []}
                        onClose={() => setBindOpen(false)}
                        onSuccess={onBound}
                      />
                    </div>
                  )}
                </CCardBody>
              </CCard>
            )}
          </>
        )}
        </>
      )}

      {tab === 'templates' && (
        <TemplateEditor
          existingNames={(templatesQuery.data ?? []).map((t) => t.name)}
          onCreated={() => templatesQuery.refetch()}
        />
      )}

      {tab === 'audit' && (
        <>
        {auditQuery.isLoading ? (
          <div>Loading audit…</div>
        ) : auditQuery.data === null ? (
          // ponytail: the 501 body is not rendered — the read route is a
          // known stub (verified in backend/app/api/audit.py); the tab
          // carries the empty state and picks up rows when the route lands.
          <div>Audit log not available.</div>
        ) : (auditQuery.data ?? []).length === 0 ? (
          <div>No audit entries.</div>
        ) : (
          <CTable striped hover>
            <thead>
              <tr>
                <th>Action</th>
                <th>Actor</th>
                <th>Target</th>
                <th>Cluster</th>
                <th>Namespace</th>
                <th>Template</th>
                <th>At</th>
              </tr>
            </thead>
            <tbody>
              {(auditQuery.data ?? []).map((a) => (
                <tr key={a.id}>
                  <td>{a.action}</td>
                  <td>{a.actor_sub}</td>
                  <td>{a.target}</td>
                  <td>{a.cluster ?? '\u2014'}</td>
                  <td>{a.namespace ?? '\u2014'}</td>
                  <td>{a.template ?? '\u2014'}</td>
                  <td>{a.at}</td>
                </tr>
              ))}
            </tbody>
          </CTable>
        )}
        </>
      )}
    </div>
  )
}

export default AdminPermissionsView
