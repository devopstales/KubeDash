import React, { useState } from 'react'
import { CButton, CCard, CCardBody, CCardHeader, CCardTitle, CCol, CRow } from '@coreui/react'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, downloadFile } from '../../lib/api'
import type { MyAccessBinding } from '../../lib/types'

/**
 * My Access (TICKET-06, all users): the caller's bindings from
 * GET /api/v1/permissions/my-access + a Download kubeconfig button
 * (GET /api/v1/kubeconfig, ADR-0011). Empty state when unbound; download
 * failures surface the API error message inline.
 */
const PermissionsView = () => {
  const [downloadError, setDownloadError] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)

  const { data, isLoading, error } = useQuery<MyAccessBinding[]>({
    queryKey: ['permissions', 'my-access'],
    queryFn: async () => {
      const r = await apiFetch<MyAccessBinding[]>('/api/v1/permissions/my-access')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  const bindings = data ?? []

  const onDownload = async () => {
    setDownloading(true)
    setDownloadError(null)
    try {
      const r = await downloadFile('/api/v1/kubeconfig', 'kubedash-kubeconfig.yaml')
      if (!r.ok) setDownloadError(`${r.error?.code ?? 'UNKNOWN'}: ${r.error?.message ?? ''}`)
    } catch {
      setDownloadError('Download failed')
    } finally {
      setDownloading(false)
    }
  }

  return (
    <CRow>
      <CCol xs={12}>
        <CCard>
          <CCardHeader>
            <CCardTitle>My access</CCardTitle>
          </CCardHeader>
          <CCardBody>
            {isLoading ? (
              <div>Loading your access…</div>
            ) : error ? (
              // Task 6 review carry-forward: a failed my-access fetch (e.g.
              // 500) must not leave the user staring at "Loading…" forever.
              <div className="text-danger">
                {error instanceof Error ? error.message : 'Failed to load your access'}
              </div>
            ) : bindings.length === 0 ? (
              <div>No cluster access yet.</div>
            ) : (
              <KubeDataTable data={bindings}>
                <Column title="Cluster" data="cluster" />
                <Column title="Namespace" data="namespace">
                  {(namespace: string | null) => namespace ?? '\u2014'}
                </Column>
                <Column title="Template" data="template">
                  {(template: string | null) => template ?? '\u2014'}
                </Column>
                <Column title="Created" data="created_at" />
              </KubeDataTable>
            )}
            <div className="mt-3">
              <CButton onClick={onDownload} disabled={downloading}>
                {downloading ? 'Downloading…' : 'Download kubeconfig'}
              </CButton>
              {downloadError && <div className="text-danger mt-2">{downloadError}</div>}
            </div>
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  )
}

export default PermissionsView
