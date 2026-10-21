import React, { useState } from 'react'
import { Link, Navigate, useLocation, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CForm,
  CFormInput,
  CFormLabel,
  CFormSelect,
  CModal,
  CModalBody,
  CModalFooter,
  CModalHeader,
  CModalTitle,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilBadge, cilPencil, cilTrash, cilUserPlus } from '@coreui/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AdminUser } from '../../lib/types'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { useCluster } from '../../hooks/useCluster'
import TemplatesPage from './Templates'
import AuditPage from './Audit'

const SPECIAL = /[ `!@#$%^ˇ&*()_+\-=[\]{};':"\\|,.<>/?~]/

/** 4.1 Create User meter: all five criteria must pass before Add User enables. */
const passwordCriteria = (password: string) => ({
  length: password.length >= 6 && password.length <= 15,
  capital: /[A-Z]/.test(password),
  small: /[a-z]/.test(password),
  number: /[0-9]/.test(password),
  special: SPECIAL.test(password),
})

const CRITERIA: { key: keyof ReturnType<typeof passwordCriteria>; label: string }[] = [
  { key: 'length', label: '6-15 characters' },
  { key: 'capital', label: 'Uppercase letter (A-Z)' },
  { key: 'small', label: 'Lowercase letter (a-z)' },
  { key: 'number', label: 'Number (0-9)' },
  { key: 'special', label: 'Special character' },
]

const typeLabel = (source: string | undefined) => {
  if (source === 'oidc') return 'OpenID'
  if (source === 'local') return 'Local'
  return '\u2014'
}

const roleLabel = (role: string) => {
  if (role === 'admin') return 'Admin'
  if (role === 'user') return 'User'
  return role
}

const displayName = (user: AdminUser) => user.display_name || user.sub

/**
 * 4.1 User List (`users/user.html.j2`): header breadcrumb and Create User,
 * CoreUI card, and icon actions (edit, delete, privilege edit). The
 * bootstrap admin row has no actions.
 * `?tab=templates` and `?tab=audit` are separate pages, not a tab strip.
 */
const UserList = () => {
  const queryClient = useQueryClient()
  const { me } = useCluster()
  const usersQuery = useQuery<AdminUser[]>({
    queryKey: ['admin', 'users'],
    queryFn: async () => {
      const r = await apiFetch<AdminUser[]>('/api/v1/admin/users')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const [editing, setEditing] = useState<AdminUser | null>(null)
  const [role, setRole] = useState('user')
  const [saveError, setSaveError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const [creating, setCreating] = useState(false)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [createRole, setCreateRole] = useState('user')
  const [passwordUnlocked, setPasswordUnlocked] = useState(false)
  const [createError, setCreateError] = useState<string | null>(null)
  const [rowError, setRowError] = useState<string | null>(null)

  const criteria = passwordCriteria(password)
  const passwordStrong = CRITERIA.every((item) => criteria[item.key])

  const reload = () => {
    queryClient.invalidateQueries({ queryKey: ['admin', 'users'] })
  }

  const closeCreate = () => {
    setCreating(false)
    setUsername('')
    setEmail('')
    setPassword('')
    setCreateRole('user')
    setPasswordUnlocked(false)
    setCreateError(null)
  }

  const openEdit = (user: AdminUser) => {
    setEditing(user)
    setRole(user.role)
    setSaveError(null)
  }

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editing) return
    setBusy(true)
    setSaveError(null)
    const r = await apiFetch(`/api/v1/admin/users/${editing.id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role }),
    })
    setBusy(false)
    if (r.error) {
      setSaveError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setEditing(null)
    reload()
  }

  const createUser = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!passwordStrong) return
    setBusy(true)
    setCreateError(null)
    const r = await apiFetch('/api/v1/admin/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        email,
        password,
        role: createRole,
        type: 'Local',
      }),
    })
    setBusy(false)
    if (r.error) {
      setCreateError(`${r.error.code}: ${r.error.message}`)
      return
    }
    closeCreate()
    reload()
  }

  const removeUser = async (user: AdminUser) => {
    setRowError(null)
    const r = await apiFetch(`/api/v1/admin/users/${user.id}`, { method: 'DELETE' })
    if (r.error) {
      setRowError(`${r.error.code}: ${r.error.message}`)
      return
    }
    reload()
  }

  const users = usersQuery.data ?? []
  const mutable = (user: AdminUser) => !user.sub.startsWith('local:')
  const privilegeTo = (sub: string, page = '/user/privilege') =>
    me?.sub === sub ? page : `${page}?user=${encodeURIComponent(sub)}`

  return (
    <>
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>User Management</CBreadcrumbItem>
          <CBreadcrumbItem active>Users</CBreadcrumbItem>
        </CBreadcrumb>
        <CButton
          color="link"
          className="header-toggler ms-auto"
          type="button"
          aria-label="Create User"
          title="Create User"
          onClick={() => setCreating(true)}
        >
          <CIcon icon={cilUserPlus} size="lg" />
        </CButton>
      </TopMenu>

      <CCard className="shadow mb-4 mx-4">
        <CCardHeader className="py-3">
          <h6 className="m-0 fw-bold text-primary">User List</h6>
        </CCardHeader>
        <CCardBody>
          {usersQuery.isLoading ? (
            <div>Loading users…</div>
          ) : usersQuery.error ? (
            <div className="text-danger">
              {usersQuery.error instanceof Error
                ? usersQuery.error.message
                : 'Failed to load users'}
            </div>
          ) : users.length === 0 ? (
            <div className="text-center text-muted">No users found</div>
          ) : (
            <KubeDataTable data={users}>
              <Column title="Username" data="display_name">
                {(name: string | null, _type: string, row: AdminUser) => {
                  const label = name || row.sub
                  if (!mutable(row) && me?.sub !== row.sub) return label
                  return <Link to={privilegeTo(row.sub)}>{label}</Link>
                }}
              </Column>
              <Column title="Email" data="email">
                {(value: string | null) => value ?? '\u2014'}
              </Column>
              <Column title="Permission" data="role">
                {(value: string) => roleLabel(value)}
              </Column>
              <Column title="Type" data="auth_source">
                {(source: string | undefined) => typeLabel(source)}
              </Column>
              <Column title="Action" data={null}>
                {(_data: unknown, _type: string, row: AdminUser) =>
                  mutable(row) ? (
                    <div className="d-flex flex-row gap-1">
                      <CButton
                        color="success"
                        size="sm"
                        type="button"
                        aria-label={`Edit ${displayName(row)}`}
                        title="Edit"
                        onClick={() => openEdit(row)}
                      >
                        <CIcon icon={cilPencil} />
                      </CButton>
                      <CButton
                        color="danger"
                        size="sm"
                        type="button"
                        aria-label={`Delete ${displayName(row)}`}
                        title="Delete"
                        onClick={() => removeUser(row)}
                      >
                        <CIcon icon={cilTrash} />
                      </CButton>
                      <Link
                        to={privilegeTo(row.sub, '/user/privilege/edit')}
                        className="btn btn-secondary btn-sm"
                        aria-label={`Edit privileges ${displayName(row)}`}
                        title="Edit privileges"
                      >
                        <CIcon icon={cilBadge} />
                      </Link>
                    </div>
                  ) : null
                }
              </Column>
            </KubeDataTable>
          )}
          {rowError && <div className="text-danger mt-3">{rowError}</div>}
        </CCardBody>
      </CCard>

      {creating && (
        <CModal visible alignment="center" onClose={closeCreate} aria-labelledby="modaladdLabel">
          <CModalHeader>
            <CModalTitle id="modaladdLabel">Create User</CModalTitle>
          </CModalHeader>
          <CForm onSubmit={createUser}>
            <CModalBody>
              <div className="mb-3">
                <CFormLabel>Name:</CFormLabel>
                <CFormInput
                  value={username}
                  placeholder="Type your username"
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="mb-3">
                <CFormLabel>Email:</CFormLabel>
                <CFormInput
                  type="text"
                  value={email}
                  placeholder="Type your email"
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="PassEntry">Password:</CFormLabel>
                <CFormInput
                  type="password"
                  id="PassEntry"
                  value={password}
                  placeholder="Type your password"
                  readOnly={!passwordUnlocked}
                  onClick={() => setPasswordUnlocked(true)}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <div id="password-strength-status" className="small mt-1">
                  {passwordStrong
                    ? 'Password is strong — you can add the user.'
                    : password.length > 0
                      ? 'Password not strong enough yet.'
                      : ''}
                </div>
                <ul id="passwordCriterion" className="ps-3 mb-0 small">
                  {CRITERIA.map((item) => (
                    <li
                      key={item.key}
                      className={criteria[item.key] ? 'text-success' : 'text-danger'}
                    >
                      {item.label}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="add-role">Permission:</CFormLabel>
                <CFormSelect
                  id="add-role"
                  aria-label="Select role"
                  value={createRole}
                  onChange={(e) => setCreateRole(e.target.value)}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </CFormSelect>
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="add-user-type">Type:</CFormLabel>
                <CFormSelect id="add-user-type" aria-label="Select type" value="Local">
                  <option value="Local">Local</option>
                </CFormSelect>
              </div>
              {createError && <div className="text-danger">{createError}</div>}
            </CModalBody>
            <CModalFooter>
              <CButton type="button" color="secondary" onClick={closeCreate}>
                Close
              </CButton>
              <CButton
                type="submit"
                color="primary"
                id="btnAddUser"
                disabled={!passwordStrong || busy}
              >
                {busy ? 'Saving…' : 'Add User'}
              </CButton>
            </CModalFooter>
          </CForm>
        </CModal>
      )}

      {editing && (
        <CModal
          visible
          alignment="center"
          onClose={() => setEditing(null)}
          aria-labelledby="modaleditLabel"
        >
          <CModalHeader>
            <CModalTitle id="modaleditLabel">Update Information</CModalTitle>
          </CModalHeader>
          <CForm onSubmit={save}>
            <CModalBody>
              <div className="mb-3">
                <CFormLabel htmlFor="edit-username-display">Name:</CFormLabel>
                <CFormInput id="edit-username-display" value={displayName(editing)} readOnly />
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="edit-role">Dashboard Role:</CFormLabel>
                <CFormSelect
                  id="edit-role"
                  aria-label="Select role"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </CFormSelect>
              </div>
              <div className="mb-3">
                <CFormLabel htmlFor="edit-type">Type:</CFormLabel>
                <CFormSelect
                  id="edit-type"
                  aria-label="Select type"
                  value={typeLabel(editing.auth_source)}
                  disabled
                >
                  <option value={typeLabel(editing.auth_source)}>
                    {typeLabel(editing.auth_source)}
                  </option>
                </CFormSelect>
              </div>
              {saveError && <div className="text-danger">{saveError}</div>}
            </CModalBody>
            <CModalFooter>
              <CButton type="button" color="secondary" onClick={() => setEditing(null)}>
                Close
              </CButton>
              <CButton type="submit" color="primary" disabled={busy}>
                {busy ? 'Saving…' : 'Save changes'}
              </CButton>
            </CModalFooter>
          </CForm>
        </CModal>
      )}
    </>
  )
}

const AdminPermissionsView = () => {
  const [params] = useSearchParams()
  const { pathname } = useLocation()
  const tab = params.get('tab')
  if (tab === 'templates') return <TemplatesPage />
  if (tab === 'audit') return <AuditPage />
  if (pathname !== '/user/list') return <Navigate to="/user/list" replace />
  return <UserList />
}

export default AdminPermissionsView
