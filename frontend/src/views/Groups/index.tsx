import React, { useState } from 'react'
import { Link } from 'react-router-dom'
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
  CModal,
  CModalBody,
  CModalFooter,
  CModalHeader,
  CModalTitle,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilPlus, cilSync, cilUserPlus } from '@coreui/icons'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { GroupRow } from '../../lib/groupTypes'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

/**
 * 4.1 Groups list (`users/group.html.j2`) at `/user/group`: the groups
 * table (Name / Created / Action) with a row link to the group's
 * privileges page and an action button to the privilege editor. Add Group
 * and Sync (materialize memberships from OIDC claims) in the header.
 */
const GroupsList = () => {
  const queryClient = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [syncMsg, setSyncMsg] = useState<string | null>(null)

  const groupsQuery = useQuery<GroupRow[]>({
    queryKey: ['admin', 'groups'],
    queryFn: async () => {
      const r = await apiFetch<GroupRow[]>('/api/v1/admin/groups')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const reload = () => {
    queryClient.invalidateQueries({ queryKey: ['admin', 'groups'] })
  }

  const createGroup = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const r = await apiFetch('/api/v1/admin/groups', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name }),
    })
    setBusy(false)
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setCreating(false)
    setName('')
    reload()
  }

  const sync = async () => {
    setSyncMsg(null)
    setBusy(true)
    const r = await apiFetch<{ created_members: number }>('/api/v1/admin/groups/sync', {
      method: 'POST',
    })
    setBusy(false)
    if (r.error) {
      setSyncMsg(`Sync failed: ${r.error.code}: ${r.error.message}`)
      return
    }
    setSyncMsg(`Synced — ${r.data?.created_members ?? 0} new member(s)`)
    reload()
  }

  const groups = groupsQuery.data ?? []

  return (
    <>
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>User Management</CBreadcrumbItem>
          <CBreadcrumbItem active>Groups</CBreadcrumbItem>
        </CBreadcrumb>
        <CButton
          color="link"
          className="header-toggler ms-auto"
          type="button"
          aria-label="Add Group"
          title="Add Group"
          onClick={() => setCreating(true)}
        >
          <CIcon icon={cilPlus} size="lg" />
        </CButton>
      </TopMenu>

      <CCard className="shadow mb-4 mx-4">
        <CCardHeader className="py-3 d-flex flex-row align-items-center">
          <h6 className="m-0 fw-bold text-primary">Groups List</h6>
          <CButton
            color="secondary"
            size="sm"
            className="ms-auto"
            type="button"
            onClick={sync}
            disabled={busy}
          >
            <CIcon icon={cilSync} className="me-1" />
            Sync from SSO
          </CButton>
        </CCardHeader>
        <CCardBody>
          {groupsQuery.isLoading ? (
            <div>Loading groups…</div>
          ) : groupsQuery.error ? (
            <div className="text-danger">
              {groupsQuery.error instanceof Error ? groupsQuery.error.message : 'Failed to load groups'}
            </div>
          ) : groups.length === 0 ? (
            <div className="text-center text-muted">
              No groups found — log an SSO user in or sync from SSO.
            </div>
          ) : (
            <KubeDataTable data={groups}>
              <Column title="Name" data="display_name">
                {(_name: string, _type: string, row: GroupRow) => (
                  <Link to={`/user/group/privilege?group=${encodeURIComponent(row.name)}`}>
                    {row.display_name}
                  </Link>
                )}
              </Column>
              <Column title="Source" data="source">
                {(value: string) => (value === 'oidc' ? 'SSO' : 'Manual')}
              </Column>
              <Column title="Members" data="member_count">
                {(count: number) => String(count)}
              </Column>
              <Column title="Created" data="created_at">
                {(value: string | null) =>
                  value ? new Date(value).toLocaleString() : '\u2014'
                }
              </Column>
              <Column title="Action" data={null}>
                {(_data: unknown, _type: string, row: GroupRow) => (
                  <Link
                    to={`/user/group/privilege/edit?group=${encodeURIComponent(row.name)}`}
                    className="btn btn-secondary btn-sm"
                    aria-label={`Edit privileges ${row.display_name}`}
                    title="Edit privileges"
                  >
                    <CIcon icon={cilUserPlus} />
                  </Link>
                )}
              </Column>
            </KubeDataTable>
          )}
          {syncMsg && (
            <div className={syncMsg.startsWith('Sync failed') ? 'text-danger mt-3' : 'text-success mt-3'}>
              {syncMsg}
            </div>
          )}
        </CCardBody>
      </CCard>

      {creating && (
        <CModal visible alignment="center" onClose={() => setCreating(false)} aria-labelledby="modalgroupLabel">
          <CModalHeader>
            <CModalTitle id="modalgroupLabel">Add Group</CModalTitle>
          </CModalHeader>
          <CForm onSubmit={createGroup}>
            <CModalBody>
              <div className="mb-3">
                <CFormLabel>Name:</CFormLabel>
                <CFormInput
                  value={name}
                  placeholder="Type the group name"
                  onChange={(e) => setName(e.target.value)}
                />
                <div className="small text-muted mt-1">
                  Created as a manual group — SSO users never join it automatically.
                </div>
              </div>
              {error && <div className="text-danger">{error}</div>}
            </CModalBody>
            <CModalFooter>
              <CButton type="button" color="secondary" onClick={() => setCreating(false)}>
                Close
              </CButton>
              <CButton type="submit" color="primary" disabled={busy || !name.trim()}>
                {busy ? 'Saving…' : 'Add Group'}
              </CButton>
            </CModalFooter>
          </CForm>
        </CModal>
      )}
    </>
  )
}

export default GroupsList
