import React, { useState } from 'react'
import { Link, useLocation, useSearchParams } from 'react-router-dom'
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
import type { MyAccessBinding } from '../../lib/types'
import { useCluster } from '../../hooks/useCluster'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

/**
 * 4.1 Privileges page at `/user/privilege`: the user's bindings on the
 * header-selected cluster with an Unbind action. `?user=` selects someone
 * else; with no query the page is the caller. The bind form lives at
 * `/user/privilege/edit`.
 */
const PrivilegesView = () => {
  const [params] = useSearchParams()
  const { search } = useLocation()
  const { me } = useCluster()
  const user = params.get('user') ?? me?.sub ?? ''
  const selected = useClusterStore((s) => s.selectedCluster)

  const bindingsQuery = useQuery<MyAccessBinding[]>({
    queryKey: ['permissions', 'my-access'],
    queryFn: async () => {
      const r = await apiFetch<MyAccessBinding[]>('/api/v1/permissions/my-access')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
    enabled: me?.sub === user,
  })

  const bindings = (bindingsQuery.data ?? []).filter((b) => !selected || b.cluster === selected.name)
  const [error, setError] = useState<string | null>(null)

  const unbind = async (b: MyAccessBinding) => {
    const r = await apiFetch('/api/v1/admin/permissions/bind', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, cluster: b.cluster, namespace: b.namespace }),
    })
    if (r.error) {
      setError(`${r.error.code}: ${r.error.message}`)
      return
    }
    bindingsQuery.refetch()
  }

  return (
    <CCard>
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>User Management</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/user/list">Users</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem>Privileges</CBreadcrumbItem>
          <CBreadcrumbItem active>{user}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="d-flex align-items-center">
        <CCardTitle className="mb-0">Privileges — {user}</CCardTitle>
        <Link to={`/user/privilege/edit${search}`} className="btn btn-primary btn-sm ms-auto">
          Edit privileges
        </Link>
      </CCardHeader>
      <CCardBody>
        <div className="mb-3">
          <strong>Cluster:</strong> {selected?.name ?? 'none selected'}
        </div>

        {me?.sub !== user ? (
          <div className="mb-3">
            Bindings for other users are not listed (the API returns only the caller&apos;s access).
            Use Edit privileges to bind a template.
          </div>
        ) : bindingsQuery.isLoading ? (
          <div>Loading bindings…</div>
        ) : bindingsQuery.error ? (
          <div className="text-danger">
            {bindingsQuery.error instanceof Error ? bindingsQuery.error.message : 'Failed to load bindings'}
          </div>
        ) : bindings.length === 0 ? (
          <div className="mb-3">No bindings on this cluster.</div>
        ) : (
          <KubeDataTable data={bindings}>
            <Column title="Cluster" data="cluster" />
            <Column title="Namespace" data="namespace">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="Template" data="template">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="Action" data={null}>
              {(_data: unknown, _type: string, row: MyAccessBinding) => (
                <CButton size="sm" color="danger" onClick={() => unbind(row)}>
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

export default PrivilegesView
