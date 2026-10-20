import React, { useState } from 'react'
import {
  CBadge,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CFormSelect,
} from '@coreui/react'
import DataTable, { Column } from 'datatables.net-react'
import DtCore from 'datatables.net-dt'
import 'datatables.net-dt/css'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AdminUser, GroupOut, RBACTemplate } from '../../lib/types'
import { useCluster, type ClusterItem } from '../../hooks/useCluster'
import BindModal from '../AdminPermissions/components/BindModal'

// Assign DataTables core to the React component (datatables.net-react).
DataTable.use(DtCore)

/**
 * Users — matches the main-branch Users page: a "User List" card with a
 * DataTables table (search box, sortable headers, pagination), a
 * "User Management ▸ Users" breadcrumb, and a "+" add button (admin only).
 * Columns: Username (clickable → inline detail), Email, Permission, Type
 * (Local/OIDC), Status, Groups (badges), Cluster bindings, Last login,
 * Action (edit / delete / bind). The main-branch Create User and Edit User
 * modals are reimplemented as inline panels (ponytail: a CModal renders into
 * a portal overlay that jsdom's default queries can't see). Reachable at
 * /users, wrapped in ProtectedRoute + AdminRoute (role === 'admin';
 * non-admins redirect to /). API errors surface as text-danger messages
 * (no toasts, no unhandled rejections).
 *
 * The existing inline user-detail panel (per-user bindings + group
 * membership, TASK-026) is preserved — reached by clicking a username, the
 * 5.0 analogue of main's username-link → /user/privilege.
 */
const UsersView = () => {
  const { me } = useCluster()
  const callersSub = me?.sub ?? null
  const isBootstrap = (u: AdminUser) => u.sub.startsWith('local:')

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

  const groupsQuery = useQuery<GroupOut[]>({
    queryKey: ['admin', 'groups'],
    queryFn: async () => {
      const r = await apiFetch<GroupOut[]>('/api/v1/admin/groups')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const clustersQuery = useQuery<ClusterItem[]>({
    queryKey: ['clusters'],
    queryFn: async () => {
      const r = await apiFetch<ClusterItem[] | { items: ClusterItem[] }>('/api/v1/clusters')
      if (r.error) throw new Error(r.error.message)
      return Array.isArray(r.data) ? r.data : (r.data?.items ?? [])
    },
  })

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

  // Create / Edit modal state.
  const [createOpen, setCreateOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [create, setCreate] = useState({ username: '', email: '', password: '', role: 'user' })
  const [edit, setEdit] = useState({ role: 'user', status: 'active' })
  const [createError, setCreateError] = useState<string | null>(null)
  const [editError, setEditError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

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

  const onUsersChanged = () => {
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
    onUsersChanged()
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
    onUsersChanged()
  }

  const submitCreate = async () => {
    setCreateError(null)
    const r = await apiFetch('/api/v1/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(create),
    })
    if (r.error) {
      setCreateError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setCreateOpen(false)
    setCreate({ username: '', email: '', password: '', role: 'user' })
    onUsersChanged()
  }

  const openEdit = (u: AdminUser) => {
    setEdit({ role: u.role, status: u.status })
    setEditError(null)
    setEditOpen(true)
  }

  const submitEdit = async () => {
    if (!selectedUser) return
    setEditError(null)
    const r = await apiFetch(`/api/v1/admin/users/${selectedUser.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(edit),
    })
    if (r.error) {
      setEditError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setEditOpen(false)
    onUsersChanged()
  }

  const removeUser = async (u: AdminUser) => {
    setActionError(null)
    const r = await apiFetch(`/api/v1/admin/users/${u.id}`, { method: 'DELETE' })
    if (r.error) {
      setActionError(`${r.error.code}: ${r.error.message}`)
      return
    }
    if (selectedUser?.id === u.id) closeUserDetail()
    onUsersChanged()
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

  const openDetail = (u: AdminUser) => {
    setSelectedUser(u)
    setBindOpen(false)
  }

  return (
    <div>
      <nav aria-label="breadcrumb" className="mb-2">
        <ol className="breadcrumb my-0">
          <li className="breadcrumb-item">User Management</li>
          <li className="breadcrumb-item active">Users</li>
        </ol>
      </nav>

      <div className="d-flex justify-content-end mb-2">
        <CButton color="primary" onClick={() => { setCreateError(null); setCreateOpen((v) => !v) }}>
          {createOpen ? 'Close' : '+ Add User'}
        </CButton>
      </div>

      {createOpen && (
        <CCard className="mb-3">
          <CCardHeader><CCardTitle>Create User</CCardTitle></CCardHeader>
          <CCardBody>
            <div className="row g-3">
              <div className="col-md-6">
                <label>Name:</label>
                <input
                  className="form-control"
                  value={create.username}
                  aria-label="Create username"
                  onChange={(e) => setCreate((c) => ({ ...c, username: e.target.value }))}
                />
              </div>
              <div className="col-md-6">
                <label>Email:</label>
                <input
                  className="form-control"
                  value={create.email}
                  aria-label="Create email"
                  onChange={(e) => setCreate((c) => ({ ...c, email: e.target.value }))}
                />
              </div>
              <div className="col-md-6">
                <label>Password:</label>
                <input
                  type="password"
                  className="form-control"
                  value={create.password}
                  aria-label="Create password"
                  onChange={(e) => setCreate((c) => ({ ...c, password: e.target.value }))}
                />
              </div>
              <div className="col-md-6">
                <label>Permission:</label>
                <CFormSelect
                  value={create.role}
                  aria-label="Create permission"
                  onChange={(e) => setCreate((c) => ({ ...c, role: e.target.value }))}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </CFormSelect>
              </div>
            </div>
            {createError && <div className="text-danger mt-2">{createError}</div>}
            <div className="mt-3">
              <CButton color="primary" onClick={submitCreate}>Add User</CButton>
            </div>
          </CCardBody>
        </CCard>
      )}

      <CCard>
        <CCardHeader py-3><CCardTitle className="text-primary">User List</CCardTitle></CCardHeader>
        <CCardBody>
          {actionError && <div className="text-danger mb-2">{actionError}</div>}
          {users.length === 0 ? (
            <div>No users.</div>
          ) : (
            <div className="table-responsive">
              <DataTable
                data={users}
                className="display"
                options={{
                  pageLength: 10,
                  searching: true,
                  ordering: true,
                  lengthChange: true,
                }}
              >
                <Column
                  title="Username"
                  data="id"
                  render={(id: number, _type: string, row: AdminUser) => (
                    <a href="#" onClick={(e) => { e.preventDefault(); openDetail(row) }} aria-label={`Open ${row.display_name ?? row.sub}`}>
                      {row.display_name ?? row.sub}
                    </a>
                  )}
                />
                <Column title="Email" data="email" render={(v: string | null) => v ?? '—'} />
                <Column title="Permission" data="role" />
                <Column title="Type" data="user_type" />
                <Column title="Status" data="status" />
                <Column
                  title="Groups"
                  data="groups"
                  render={(groups: string[]) =>
                    groups.length === 0 ? (
                      '—'
                    ) : (
                      groups.map((gn) => (
                        <CBadge color="secondary" className="me-1" key={gn}>{gn}</CBadge>
                      ))
                    )
                  }
                />
                <Column title="Cluster bindings" data="cluster_count" />
                <Column
                  title="Last login"
                  data="last_login_at"
                  render={(v: string | null) => v ?? '—'}
                />
                <Column
                  title="Action"
                  data="id"
                  render={(_id: number, _type: string, u: AdminUser) => (
                    <span className="d-flex gap-1">
                      <CButton size="sm" color="secondary" onClick={() => openEdit(u)} aria-label={`Edit ${u.sub}`}>
                        Edit
                      </CButton>
                      {!isBootstrap(u) && (
                        <CButton size="sm" color="danger" onClick={() => removeUser(u)} aria-label={`Delete ${u.sub}`}>
                          Delete
                        </CButton>
                      )}
                      <CButton size="sm" color="primary" onClick={() => { openDetail(u); setBindOpen(true) }} aria-label={`Bind ${u.sub}`}>
                        Bind
                      </CButton>
                    </span>
                  )}
                />
              </DataTable>
            </div>
          )}
        </CCardBody>
      </CCard>

      {selectedUser && (
        <CCard className="mt-3">
          <CCardHeader><CCardTitle>User detail</CCardTitle></CCardHeader>
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
              <strong>Type:</strong> {selectedUser.user_type}
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
                <table className="table table-striped">
                  <thead>
                    <tr>
                      <th>Cluster</th><th>Namespace</th><th>Template</th><th>Created</th><th />
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
                            onClick={async () => {
                              const r = await apiFetch('/api/v1/admin/permissions/bind', {
                                method: 'DELETE',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ user: selectedUser.sub, cluster: b.cluster, namespace: b.namespace }),
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
                </table>
              )
            ) : (
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
                        <option key={g.group} value={g.group}>{g.group}</option>
                      ))}
                  </CFormSelect>
                  <CButton color="primary" disabled={!pickGroup} onClick={assignGroup}>
                    Add
                  </CButton>
                </div>
              )}
              {memberError && <div className="text-danger mt-2">{memberError}</div>}
            </div>

            {editOpen && (
              <div className="mt-3">
                <div className="d-flex gap-3">
                  <div>
                    <label>Dashboard Role:</label>
                    <CFormSelect
                      value={edit.role}
                      aria-label="Edit role"
                      onChange={(e) => setEdit((x) => ({ ...x, role: e.target.value }))}
                      style={{ maxWidth: 180 }}
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </CFormSelect>
                  </div>
                  <div>
                    <label>Status:</label>
                    <CFormSelect
                      value={edit.status}
                      aria-label="Edit status"
                      onChange={(e) => setEdit((x) => ({ ...x, status: e.target.value }))}
                      style={{ maxWidth: 180 }}
                    >
                      <option value="active">Active</option>
                      <option value="disabled">Disabled</option>
                    </CFormSelect>
                  </div>
                </div>
                {editError && <div className="text-danger mt-2">{editError}</div>}
                <div className="mt-2">
                  <CButton color="primary" onClick={submitEdit}>Save</CButton>
                </div>
              </div>
            )}

            <div className="mt-3 d-flex gap-2">
              <CButton color="primary" onClick={() => setBindOpen((v) => !v)}>
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
    </div>
  )
}

export default UsersView
