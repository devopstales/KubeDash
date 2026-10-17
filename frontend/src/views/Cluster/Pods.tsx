import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { faCircle } from '@fortawesome/free-solid-svg-icons'
import { apiFetch } from '../../lib/api'
import type { Pod, ResourceList } from '../../lib/types'

const PHASE_COLOR: Record<string, string> = {
  Running: '#198754',
  Succeeded: '#0d6efd',
  Failed: '#dc3545',
  Pending: '#ffc107',
  Unknown: '#6c757d',
}

/**
 * Pod table for a bound cluster: TanStack Query against
 * GET /api/v1/clusters/<id>/resources/pods (R4). The 403 RBAC envelope
 * (via apiFetch) renders as a message row instead of a crash.
 */
const Pods = ({ clusterId }: { clusterId: number }) => {
  const { data, error, isLoading } = useQuery({
    queryKey: ['pods', clusterId, 'all'],
    queryFn: async () => {
      const r = await apiFetch<ResourceList>(`/api/v1/clusters/${clusterId}/resources/pods`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data?.items ?? []
    },
  })

  return (
    <CCard>
      <CCardHeader>
        <CCardTitle>Pods</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {isLoading ? (
          <div>Loading pods…</div>
        ) : error ? (
          <div className="text-danger">{error.message}</div>
        ) : (
          <CTable striped>
            <thead>
              <tr>
                <th>Name</th>
                <th>Namespace</th>
                <th>Phase</th>
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((pod: Pod, i: number) => {
                const phase = pod.status?.phase ?? 'Unknown'
                return (
                  <tr key={pod.metadata?.name ?? i}>
                    <td>{pod.metadata?.name ?? ''}</td>
                    <td>{pod.metadata?.namespace ?? ''}</td>
                    <td>
                      <FontAwesomeIcon
                        icon={faCircle}
                        style={{ color: PHASE_COLOR[phase] ?? '#6c757d', marginRight: '0.5rem' }}
                      />
                      <span>{phase}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </CTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default Pods
