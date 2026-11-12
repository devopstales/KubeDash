/**
 * HA Status (spec 2026-11-10-ha-status-page): the pgEdge active-active
 * database + the KubeDash leader election, read from
 * `GET /api/v1/admin/ha-status` and polled every 5 s (SSE push is a v2).
 *
 * Two failure domains, two card sections + one card per node: a sick
 * cluster renders its reasons (the API degrades per-node, it never 500s
 * on the thing it is there to diagnose); an API error (403/500) is the
 * "status unavailable" banner.
 *
 * No page-level HA banner: the cards sit two-up and each section shows
 * its own state (node chips, the election badge + reasons).
 */
import { useQuery } from '@tanstack/react-query'
import { CBadge, CAlert, CCardBody, CCard, CCardHeader, CCardTitle, CTable } from '@coreui/react'
import { apiFetch } from '../../lib/api'
import { ClusterStatusCard } from './ClusterStatusCard'
import type { HaReport, HaStatusLevel } from './types'

const STATUS_COLOR: Record<HaStatusLevel, 'success' | 'warning' | 'danger'> = {
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
    <div className="ha-status-grid">
      {report.nodes.map((node) => (
        <ClusterStatusCard key={node.name} node={node} />
      ))}

      <div>
        <CCard className="shadow mb-4 h-100">
          <CCardHeader className="py-3 d-flex align-items-center justify-content-between">
            <CCardTitle className="m-0 fw-bold text-primary fs-6">Leader Election</CCardTitle>
            <CBadge color={STATUS_COLOR[report.election.status]}>{report.election.status}</CBadge>
          </CCardHeader>
          <CCardBody>
            <CTable small className="align-middle mb-0">
              <tbody>
                {/* Rows follow the Kubernetes Lease object (coordination.k8s.io):
                    holderIdentity / acquireTime / renewTime /
                    leaseDurationSeconds / leaseTransitions. */}
                <tr>
                  <td className="text-muted">Holder</td>
                  <td className="fw-bold">{report.leader.replica_id}</td>
                </tr>
                <tr>
                  <td className="text-muted">Acquire time</td>
                  <td>{report.leader.acquired_at ?? '—'}</td>
                </tr>
                <tr>
                  <td className="text-muted">Renew time</td>
                  <td>{report.leader.renew_at ?? '—'}</td>
                </tr>
                <tr>
                  <td className="text-muted">Lease duration</td>
                  <td>{report.leader.lease_duration_s} s</td>
                </tr>
                <tr>
                  <td className="text-muted">Transitions (fence)</td>
                  <td>{report.leader.fence}</td>
                </tr>
                <tr>
                  <td className="text-muted">Heartbeat age</td>
                  <td
                    className={
                      report.leader.heartbeat_age_s > HEARTBEAT_STALE_S ? 'text-danger' : undefined
                    }
                  >
                    {report.leader.heartbeat_age_s.toFixed(1)} s
                  </td>
                </tr>
                <tr>
                  <td className="text-muted">Lock</td>
                  <td>{report.leader.lock_verdict}</td>
                </tr>
                <tr>
                  <td className="text-muted">KubeDash replicas</td>
                  <td>
                    {report.leader.candidates === null ? (
                      <span className="text-muted">unknown</span>
                    ) : (
                      <>
                        {report.leader.candidates}{' '}
                        <span className="text-muted">(1 leader of {report.leader.candidates})</span>
                      </>
                    )}
                  </td>
                </tr>
              </tbody>
            </CTable>
            {report.election.reasons.length > 0 ? (
              <div className="small text-warning mt-3">{report.election.reasons.join(', ')}</div>
            ) : null}
          </CCardBody>
        </CCard>
      </div>

      <div>
        <CCard className="shadow mb-4 h-100">
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
      </div>
    </div>
  )
}

export default ClusterStatusView
