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
 * A page-level HA banner (acceptance R5: "the page shows a healthy
 * banner" / "a down banner listing node_unreachable:n2") leads the grid
 * with the overall status + every reason; the cards still carry the
 * per-section detail.
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
  // No report yet: an initial-load failure is the "unavailable" banner.
  // A LATER (refetch) failure with a report in hand renders the grid below
  // plus a stale-data banner — a transient 500 must not hide the last good
  // report (W049f).
  if (!report) {
    return (
      <CAlert color="danger">
        Cluster status unavailable
        {query.error instanceof Error ? `: ${query.error.message}` : ''}
      </CAlert>
    )
  }

  return (
    <>
      {query.error ? (
        <CAlert color="warning" className="mb-4" role="alert">
          Refresh failed — showing the last good report from {report.probed_at}.
        </CAlert>
      ) : null}
      {/* Acceptance R5: the page-level banner — overall status + all reasons.
          role=status: a polite live region, so screen readers hear a 5 s
          in-place update (a node going down, a leader change). */}
      <CAlert color={STATUS_COLOR[report.status]} role="status" className="mb-4">
        <span className="fw-bold">HA {report.status}</span>
        {report.reasons.length > 0 ? <span> — {report.reasons.join(', ')}</span> : null}
      </CAlert>
      {report.warnings.length > 0 ? (
        <div className="small text-warning mb-2">{report.warnings.join(' · ')}</div>
      ) : null}
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
                  <th scope="row" className="text-muted">Holder</th>
                  <td className="fw-bold">{report.leader.replica_id}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Acquire time</th>
                  <td>{report.leader.acquired_at ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Renew time</th>
                  <td>{report.leader.renew_at ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Lease duration</th>
                  <td>{report.leader.lease_duration_s} s</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Transitions (fence)</th>
                  <td>{report.leader.fence}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Heartbeat age</th>
                  <td
                    className={
                      report.leader.heartbeat_age_s > HEARTBEAT_STALE_S ? 'text-danger' : undefined
                    }
                  >
                    {report.leader.heartbeat_age_s.toFixed(1)} s
                    {/* Not color-only: the stale state gets a text marker
                        too (W048). */}
                    {report.leader.heartbeat_age_s > HEARTBEAT_STALE_S ? (
                      <span> (stale)</span>
                    ) : null}
                  </td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Lock</th>
                  <td>{report.leader.lock_verdict}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">KubeDash replicas</th>
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
                  <th scope="row" className="text-muted">Pending</th>
                  <td>{report.queue.pending}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Processing</th>
                  <td>{report.queue.processing}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Done</th>
                  <td>{report.queue.done}</td>
                </tr>
                <tr>
                  <th scope="row" className="text-muted">Failed</th>
                  <td>{report.queue.failed}</td>
                </tr>
                {report.queue.oldest_pending_at ? (
                  <tr>
                    <th scope="row" className="text-muted">Oldest pending</th>
                    <td>{report.queue.oldest_pending_at}</td>
                  </tr>
                ) : null}
              </tbody>
            </CTable>
          </CCardBody>
        </CCard>
      </div>
      </div>
    </>
  )
}

export default ClusterStatusView
