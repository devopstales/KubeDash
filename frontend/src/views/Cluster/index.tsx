import React, { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CCol,
  CRow,
  CTable,
} from '@coreui/react'
import { useClusterStore } from '../../store/cluster'
import { useCluster } from '../../hooks/useCluster'
import { apiFetch } from '../../lib/api'
import type { Cluster, Health } from '../../lib/types'

/**
 * Cluster Details shows registry metadata and the live API health probe.
 * Pods belong to Interface → Workloads → Pods, not this status page.
 */
const ClusterView = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const { clusters } = useCluster()

  const paramId = id ? Number(id) : null
  // Cross-reference the URL param against the bound clusters. A stale
  // param from a prior session redirects to the current selection.
  const isStale =
    paramId != null &&
    clusters.length > 0 &&
    !clusters.some((c) => c.id === paramId)

  useEffect(() => {
    if (isStale && selectedCluster) {
      navigate(`/clusters/${selectedCluster.id}`, { replace: true })
    }
  }, [isStale, selectedCluster, navigate])

  const clusterId = isStale ? selectedCluster?.id : paramId ?? selectedCluster?.id

  const clusterQuery = useQuery<Cluster>({
    queryKey: ['cluster', clusterId],
    enabled: clusterId != null && !Number.isNaN(clusterId),
    queryFn: async () => {
      const r = await apiFetch<Cluster>(`/api/v1/clusters/${clusterId}`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      if (!r.data) throw new Error('Cluster details are unavailable')
      return r.data
    },
  })

  const healthQuery = useQuery<Health>({
    queryKey: ['cluster', clusterId, 'health'],
    enabled: clusterId != null && !Number.isNaN(clusterId),
    queryFn: async () => {
      const r = await apiFetch<Health>(`/api/v1/clusters/${clusterId}/health`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      if (!r.data) throw new Error('Cluster health is unavailable')
      return r.data
    },
  })

  if (clusterId == null || Number.isNaN(clusterId)) {
    return <div>Select a cluster to see its status.</div>
  }

  return (
    <CRow>
      <CCol xs={12}>
        <CCard>
          <CCardHeader>
            <CCardTitle>Cluster status</CCardTitle>
          </CCardHeader>
          <CCardBody>
            {clusterQuery.isLoading ? (
              <div>Loading cluster status…</div>
            ) : clusterQuery.error ? (
              <div className="text-danger">{clusterQuery.error.message}</div>
            ) : (
              <CTable bordered>
                <tbody>
                  <tr>
                    <th scope="row">Name</th>
                    <td>{clusterQuery.data?.name}</td>
                  </tr>
                  <tr>
                    <th scope="row">API server</th>
                    <td>{clusterQuery.data?.api_server ?? '\u2014'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Context</th>
                    <td>{clusterQuery.data?.context ?? '\u2014'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Registry status</th>
                    <td>{clusterQuery.data?.status ?? 'unknown'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Live API status</th>
                    <td>
                      {healthQuery.isLoading
                        ? 'Checking…'
                        : healthQuery.error
                          ? healthQuery.error.message
                          : healthQuery.data?.status ?? 'unknown'}
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Last probe</th>
                    <td>{clusterQuery.data?.last_probe_at ?? '\u2014'}</td>
                  </tr>
                </tbody>
              </CTable>
            )}
          </CCardBody>
        </CCard>
      </CCol>
    </CRow>
  )
}

export default ClusterView
