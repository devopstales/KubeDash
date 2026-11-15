/**
 * One cluster member's probe result (spec 2026-11-10-ha-status-page R4).
 * A sick node is a card with a reason, never an empty or errored page —
 * the probe degrades to `reachable: false` on the server.
 */
import { CBadge, CCardBody, CCard, CCardHeader, CCardTitle, CTable } from '@coreui/react'
import type { HaNode } from './types'

const formatLag = (node: HaNode): string => {
  if (node.lag_bytes <= 0) return '—'
  const kiB = node.lag_bytes / 1024
  const size = kiB >= 1024 ? `${(kiB / 1024).toFixed(1)} MiB` : `${kiB.toFixed(1)} KiB`
  return `${size} (${node.lag_interval_s.toFixed(1)} s)`
}

export const ClusterStatusCard = ({ node }: { node: HaNode }) => (
  <CCard className="shadow mb-4 h-100">
    <CCardHeader className="py-3 d-flex align-items-center justify-content-between">
      <CCardTitle className="m-0 fw-bold text-primary fs-6">
        {node.name}
        {node.dsn ? <span className="text-muted fw-normal ms-2">{node.dsn}</span> : null}
      </CCardTitle>
      <CBadge color={node.reachable ? 'success' : 'danger'}>
        {node.reachable ? 'reachable' : 'unreachable'}
      </CBadge>
    </CCardHeader>
    <CCardBody>
      {node.reachable ? (
        <CTable small className="align-middle mb-0">
          <tbody>
            <tr>
              <th scope="row" className="text-muted">Replication</th>
              <td>
                {node.sub_statuses.length === 0 ? (
                  <span className="text-muted">no local subscriptions</span>
                ) : (
                  node.sub_statuses.map((s) => (
                    <CBadge
                      key={s.name}
                      color={s.status === 'replicating' ? 'success' : 'danger'}
                      className="me-1"
                    >
                      {s.name}: {s.status}
                    </CBadge>
                  ))
                )}
              </td>
            </tr>
            <tr>
              <th scope="row" className="text-muted">Lag</th>
              <td>{formatLag(node)}</td>
            </tr>
            <tr>
              <th scope="row" className="text-muted">Apply workers</th>
              <td>
                {node.apply_workers}
                {node.workers_streaming ? <span className="text-success"> (streaming)</span> : null}
              </td>
            </tr>
            <tr>
              <th scope="row" className="text-muted">Conflicts</th>
              {/* Not color-only: a non-zero conflict count gets a text
                  marker too (W048). */}
              <td className={node.conflicts > 0 ? 'text-danger' : undefined}>
                {node.conflicts}
                {node.conflicts > 0 ? <span> (non-zero)</span> : null}
              </td>
            </tr>
            <tr>
              <th scope="row" className="text-muted">Exceptions</th>
              <td className={node.exceptions_pending > 0 ? 'text-warning' : undefined}>
                {node.exceptions_pending}
                {node.exceptions_pending > 0 ? <span> (pending)</span> : null}
              </td>
            </tr>
            <tr>
              <th scope="row" className="text-muted">Leader lock</th>
              <td>
                {node.lock_held_locally ? (
                  <CBadge color="info">
                    held here (pid {node.lock_holder_pid},{' '}
                    {node.lock_holder_state ?? 'state unknown'})
                  </CBadge>
                ) : (
                  <span className="text-muted">not held here</span>
                )}
              </td>
            </tr>
          </tbody>
        </CTable>
      ) : (
        <div className="text-danger">Unreachable — {node.probe_error ?? 'probe failed'}</div>
      )}
    </CCardBody>
  </CCard>
)

export default ClusterStatusCard
