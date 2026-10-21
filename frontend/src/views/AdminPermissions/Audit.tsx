import React from 'react'
import { CCard, CCardBody, CCardHeader, CCardTitle } from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { AuditEntry } from '../../lib/types'
import KubeDataTable, { Column } from '../../components/KubeDataTable'

/**
 * Settings → Audit Log (`/admin/permissions?tab=audit`). Its own page, not
 * a tab on the User List. GET /api/v1/audit is still a 501 stub; the page
 * shows an empty state until that route returns rows.
 */
const AuditPage = () => {
  const auditQuery = useQuery<AuditEntry[] | null>({
    queryKey: ['admin', 'audit'],
    queryFn: async () => {
      const r = await apiFetch<AuditEntry[]>('/api/v1/audit')
      if (r.error) return null
      return r.data ?? []
    },
  })

  return (
    <CCard>
      <CCardHeader>
        <CCardTitle>Audit</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {auditQuery.isLoading ? (
          <div>Loading audit…</div>
        ) : !auditQuery.data ? (
          <div>Audit log not available.</div>
        ) : auditQuery.data.length === 0 ? (
          <div>No audit entries.</div>
        ) : (
          <KubeDataTable data={auditQuery.data}>
            <Column title="Action" data="action" />
            <Column title="Actor" data="actor_sub" />
            <Column title="Target" data="target" />
            <Column title="Cluster" data="cluster">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="Namespace" data="namespace">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="Template" data="template">
              {(v: string | null) => v ?? '\u2014'}
            </Column>
            <Column title="At" data="at" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default AuditPage
