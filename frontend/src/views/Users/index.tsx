import React, { useState } from 'react'
import {
  CBadge,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CFormSelect,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AdminUser, GroupOut, RBACTemplate } from '../../lib/types'
import { useCluster, type ClusterItem } from '../../hooks/useCluster'
import BindModal from '../AdminPermissions/components/BindModal'

/**
 * Users (left-menu admin surface, re-homed from the AdminPermissions Users
 * tab): list every user (GET /api/v1/admin/users), inline user detail with
 * bindings + bind/unbind. Reachable at /users, wrapped in
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
const UsersView = () => {
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

  // The group list for the detail panel's "add to group" picker.
  const groupsQuery = useQuery<GroupOut[]>({
    queryKey: ['admin', 'groups'],
    queryFn: async () => {
      const r = await apiFetch<GroupOut[]>('/api/v1/admin/groups')
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

  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null)
  const [bindOpen, setBindOpen] = useState(false)
  const [pickGroup, setPickGroup] = useState('')
  const [memberError, setMemberError] = useState<string | null>(null)

  const closeUserDetail = () => {
    setSelectedUser(null)
    setBindOpen(false)
    setPickGroup('')
    setMemberError(null)
  }

  const onBound = () => {
    usersQuery.refetch()
    myAccessQuery.refetch()
  }

  const onGroupsChanged = () => {
    usersQuery.refetch()
    groupsQuery.refetch()
  }

  const assignGroup = async () => {
    if (!selectedUser || !pickGroup) return
    setMemberError(null)
    const r = await apiFetch(`/api/v1/admin/groups/${encodeURIComponent(pickGroup)}/members`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user_sub: selectedUser.sub }),
    })
    if (r.error) {
      setMemberError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setPickGroup('')
    onGroupsChanged()
  }

  const unassignGroup = async (groupName: string) => {
    if (!selectedUser) return
    setMemberError(null)
    const r = await apiFetch(
      `/api/v1/admin/groups/${encodeURIComponent(groupName)}/members/${encodeURIComponent(selectedUser.sub)}`,
      { method: 'DELETE' },
    )
    if (r.error) {
      setMemberError(`${r.error.code}: ${r.error.message}`)
      return
    }
    onGroupsChanged()
  }

  if (usersQuery.isLoading) {
    return <div>Loading users…</div>
  }

  if (usersQuery.error) {
    return (
      <div className="text-danger">
        {usersQuery.error instanceof Error ? usersQuery.error.message : 'Failed to load users'}
      </div>
    )
  }

  const users = usersQuery.data ?? []

  return (
    <div>
      {users.length === 0 ? (
        <div>No users.</div>
      ) : (
        <>
          <CTable striped hover>
            <thead>
              <tr>
                <th>Display name</th>
                <th>Sub</th>
                <th>Email</th>
                <th>Groups</th>
                <th>Role</th>
                <th>Status</th>
                <th>Clusters</th>
                <th>Last login</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr
                  key={u.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => {
                    setSelectedUser(u)
                    setBindOpen(false)
                  }}
                >
                  <td>{u.display_name ?? '—'}</td>
                  <td>{u.sub}</td>
                  <td>{u.email ?? '—'}</td>
                  <td>
                    {u.groups.length === 0 ? (
                      '—'
                    ) : (
                      u.groups.map((gn) => (
                        <CBadge color="secondary" className="me-1" key={gn}>
                          {gn}
                        </CBadge>
                      ))
                    )}
                  </td>
                  <td>{u.role}</td>
                  <td>{u.status}</td>
                  <td>{u.cluster_count}</td>
                  <td>{u.last_login_at ?? '—'}</td>
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
                            <td>{b.namespace ?? '—'}</td>
                            <td>{b.template ?? '—'}</td>
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

                <div className="mt-3">
                  <div className="mb-2">
                    <strong>Groups:</strong>{' '}
                    {selectedUser.groups.length === 0 ? (
                      <span>none</span>
                    ) : (
                      selectedUser.groups.map((gn) => (
                        <CBadge color="secondary" className="me-1" key={gn}>
                          {gn}
                          <CButton
                            color="link"
                            size="sm"
                            className="px-1"
                            aria-label={`Remove ${gn}`}
                            onClick={() => unassignGroup(gn)}
                          >
                            ×
                          </CButton>
                        </CBadge>
                      ))
                    )}
                  </div>
                  {groupsQuery.data && groupsQuery.data.length > 0 && (
                    <div className="d-flex gap-2">
                      <CFormSelect
                        value={pickGroup}
                        aria-label="Add to group"
                        onChange={(e) => setPickGroup(e.target.value)}
                        style={{ maxWidth: 220 }}
                      >
                        <option value="">Add to group…</option>
                        {groupsQuery.data
                          .filter((g) => !selectedUser.groups.includes(g.group))
                          .map((g) => (
                            <option key={g.group} value={g.group}>
                              {g.group}
                            </option>
                          ))}
                      </CFormSelect>
                      <CButton color="primary" disabled={!pickGroup} onClick={assignGroup}>
                        Add
                      </CButton>
                    </div>
                  )}
                  {memberError && <div className="text-danger mt-2">{memberError}</div>}
                </div>

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
    </div>
  )
}

export default UsersView
