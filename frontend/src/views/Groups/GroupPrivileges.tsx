import React, { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { GroupDetail, GroupBinding } from '../../lib/groupTypes'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

/**
 * 4.1 Group privileges page (`users/group-privilege.html.j2`) at
 * `/user/group/privilege?group=<name>`: two sections — Members (4.1 tab)
 * and RoleBindings — the group's template bindings on the header-selected
 * cluster, with an Unbind action. The bind form lives at
 * `/user/group/privilege/edit`.
 */
const GroupPrivilegesView = () => {
  const [params] = useSearchParams()
  const group = params.get('group') ?? ''
  const selected = useClusterStore((s) => s.selectedCluster)
  const [error, setError] = useState<string | null>(null)

  const detailQuery = useQuery<GroupDetail | null>({
    queryKey: ['admin', 'groups', group],
    queryFn: async () => {
      const r = await apiFetch<GroupDetail>(`/api/v1/admin/groups/${encodeURIComponent(group)}`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data
    },
    enabled: !!group,
  })

  const bindingsQuery = useQuery<GroupBinding[]>({
    queryKey: ['admin', 'groups', group, 'privileges'],
    queryFn: async () => {
      const r = await apiFetch<GroupBinding[]>(
        `/api/v1/admin/groups/${encodeURIComponent(group)}/privileges`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
    enabled: !!group,
  })

  const bindings = (bindingsQuery.data ?? []).filter(
    (b) => !selected || b.cluster === selected.name,
  )

  const unbind = async (b: GroupBinding) => {
    const r = await apiFetch(`/api/v1/admin/groups/${encodeURIComponent(group)}/privileges`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cluster: b.cluster, namespace: b.namespace, template: b.template }),
    })
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    bindingsQuery.refetch()
  }

  const detail = detailQuery.data
  const members = detail?.members ?? []

  return (
    <CCard>
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>User Management</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/user/group">Groups</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{group || 'Loading…'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="d-flex flex-row align-items-center">
          <h6 className="m-0 fw-bold text-primary">Group Data — {group || '…'}</h6>
          <CButton
            color="primary"
            size="sm"
            className="ms-auto"
            type="button"
            disabled={!group}
            onClick={() =>
              (window.location.href = `/user/group/privilege/edit?group=${encodeURIComponent(group)}`)
            }
          >
            Edit privileges
          </CButton>
        </CCardTitle>
      </CCardHeader>

      <CCardBody>
        <h6 className="fw-bold text-primary mb-2">Members</h6>
        {detailQuery.isLoading ? (
          <div>Loading members…</div>
        ) : detailQuery.error ? (
          <div className="text-danger">
            {detailQuery.error instanceof Error
              ? detailQuery.error.message
              : 'Failed to load group'}
          </div>
        ) : members.length === 0 ? (
          <div className="text-muted">No members found</div>
        ) : (
          <KubeDataTable data={members}>
            <Column title="Username" data="display_name">
              {(name: string | null, _t: string, row: { sub: string }) => name || row.sub}
            </Column>
            <Column title="Email" data="email">
              {(value: string | null) => value ?? '\u2014'}
            </Column>
            <Column title="Type" data="auth_source">
              {(value: string) =>
                value === 'oidc' ? 'OpenID' : value === 'local' ? 'Local' : value
              }
            </Column>
          </KubeDataTable>
        )}

        <h6 className="fw-bold text-primary mt-4 mb-2">RoleBindings</h6>
        {bindingsQuery.isLoading ? (
          <div>Loading role bindings…</div>
        ) : bindingsQuery.error ? (
          <div className="text-danger">
            {bindingsQuery.error instanceof Error
              ? bindingsQuery.error.message
              : 'Failed to load role bindings'}
          </div>
        ) : bindings.length === 0 ? (
          <div className="text-muted">
            No role bindings found on {selected?.name ?? 'this cluster'}
          </div>
        ) : (
          <KubeDataTable data={bindings}>
            <Column title="Namespace" data="namespace">
              {(value: string | null) => value ?? '(cluster)'}
            </Column>
            <Column title="Type" data={null}>
              {(_data: unknown, _type: string, row: GroupBinding) =>
                row.namespace ? 'RoleBinding' : 'ClusterRoleBinding'
              }
            </Column>
            <Column title="Template" data="template">
              {(value: string | null) => value ?? '\u2014'}
            </Column>
            <Column title="Action" data={null}>
              {(_data: unknown, _type: string, row: GroupBinding) => (
                <CButton color="danger" size="sm" type="button" onClick={() => unbind(row)}>
                  Unbind
                </CButton>
              )}
            </Column>
          </KubeDataTable>
        )}
        {error && <div className="text-danger mt-3">{error}</div>}
      </CCardBody>
    </CCard>
  )
}

export default GroupPrivilegesView
