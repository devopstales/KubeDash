/**
 * HA Status (spec 2026-11-10-ha-status-page): the pgEdge active-active
 * database + the KubeDash leader election, read from
 * `GET /api/v1/admin/ha-status` and polled every 5 s (SSE push is a v2).
 *
 * Two failure domains, two card sections + one card per node: a sick
 * cluster renders its reasons (the API degrades per-node, it never 500s
 * on the thing it is there to diagnose); an API error (403/500) is the
 * "status unavailable" banner.
 */
import { useQuery } from '@tanstack/react-query'
import {
  CAlert,
  CCardBody,
  CCard,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import { apiFetch } from '../../lib/api'
import { ClusterStatusCard } from './ClusterStatusCard'
import type { HaReport, HaStatusLevel } from './types'

const BANNER_COLOR: Record<HaStatusLevel, 'success' | 'warning' | 'danger'> = {
  healthy: 'success',
  degraded: 'warning',
  down: 'danger',
}

/** Heartbeat older than the backend's stale threshold (10 s, ha_status.py). */
const HEARTBEAT_STALE_S = 10

export const ClusterStatusView = () => {
  const query = useQuery<HaReport>({
    queryKey: ['admin', 'ha-status'],
    queryFn: async () => {
      const r = await apiFetch<HaReport>('/api/v1/admin/ha-status')
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      if (!r.data) throw new Error('HA report missing')
      return r.data
    },
    refetchInterval: 5000,
  })

  const report = query.data

  if (query.isLoading) {
    return <div className="text-center text-muted py-5">Loading cluster status…</div>
  }
  if (query.error || !report) {
    return (
      <CAlert color="danger">
        Cluster status unavailable
        {query.error instanceof Error ? `: ${query.error.message}` : ''}
      </CAlert>
    )
  }

  return (
    <>
      <CAlert color={BANNER_COLOR[report.status]}>
        <span className="fw-bold">HA {report.status}</span>
        {report.reasons.length > 0 ? (
          <span> — {report.reasons.join(', ')}</span>
        ) : null}
        <span className="text-muted ms-2">
          (database: {report.database.status}, election: {report.election.status})
        </span>
      </CAlert>

      {report.nodes.map((node) => (
        <ClusterStatusCard key={node.name} node={node} />
      ))}

      <CCard className="shadow mb-4">
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">
            Leader Election
          </CCardTitle>
        </CCardHeader>
        <CCardBody>
          <CTable small className="align-middle mb-0">
            <tbody>
              <tr>
                <td className="text-muted">Leader</td>
                <td className="fw-bold">{report.leader.replica_id}</td>
              </tr>
              <tr>
                <td className="text-muted">Fence (election count)</td>
                <td>{report.leader.fence}</td>
              </tr>
              {report.leader.acquired_at ? (
                <tr>
                  <td className="text-muted">Acquired</td>
                  <td>{report.leader.acquired_at}</td>
                </tr>
              ) : null}
              <tr>
                <td className="text-muted">Heartbeat age</td>
                <td
                  className={
                    report.leader.heartbeat_age_s > HEARTBEAT_STALE_S
                      ? 'text-danger'
                      : undefined
                  }
                >
                  {report.leader.heartbeat_age_s.toFixed(1)} s
                </td>
              </tr>
              <tr>
                <td className="text-muted">Lock</td>
                <td>{report.leader.lock_verdict}</td>
              </tr>
              {report.leader.candidates !== null ? (
                <tr>
                  <td className="text-muted">Candidates</td>
                  <td>
                    1 leader of {report.leader.candidates} candidate
                    {report.leader.candidates === 1 ? '' : 's'}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </CTable>
        </CCardBody>
      </CCard>

      <CCard className="shadow mb-4">
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Task Queue</CCardTitle>
        </CCardHeader>
        <CCardBody>
          <CTable small className="align-middle mb-0">
            <tbody>
              <tr>
                <td className="text-muted">Pending</td>
                <td>{report.queue.pending}</td>
              </tr>
              <tr>
                <td className="text-muted">Processing</td>
                <td>{report.queue.processing}</td>
              </tr>
              <tr>
                <td className="text-muted">Done</td>
                <td>{report.queue.done}</td>
              </tr>
              {report.queue.oldest_pending_at ? (
                <tr>
                  <td className="text-muted">Oldest pending</td>
                  <td>{report.queue.oldest_pending_at}</td>
                </tr>
              ) : null}
            </tbody>
          </CTable>
        </CCardBody>
      </CCard>
    </>
  )
}

export default ClusterStatusView
