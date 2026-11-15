/**
 * The HA report types — a mirror of the backend's `HaStatusOut`
 * (`backend/app/schemas/ha_status.py`, spec 2026-11-10-ha-status-page).
 * Kept by hand (the API is a plain JSON envelope, no codegen).
 */

export type HaStatusLevel = 'healthy' | 'degraded' | 'down'

export interface SubStatus {
  name: string
  status: string
}

export interface HaNode {
  name: string
  reachable: boolean
  probe_error: string | null
  /** Receive-direction subscriptions visible on this node. */
  sub_statuses: SubStatus[]
  lag_bytes: number
  lag_interval_s: number
  apply_workers: number
  workers_streaming: boolean
  conflicts: number
  exceptions_pending: number
  lock_held_locally: boolean
  lock_holder_pid: number | null
  lock_holder_state: string | null
  elapsed_ms: number
  /** host:port only — the backend never sends the full DSN (credentials). */
  dsn: string
}

export interface Leader {
  /** Kubernetes Lease ``holderIdentity``. */
  replica_id: string
  /** Kubernetes Lease ``leaseTransitions`` (every acquire bumps the fence). */
  fence: number
  heartbeat_age_s: number
  /** "held on n1 (pid 7899, idle)" / "not seen on any reachable node" / ... */
  lock_verdict: string
  token: string | null
  /** Kubernetes Lease ``acquireTime``. */
  acquired_at: string | null
  /** Kubernetes Lease ``renewTime`` — the last lease heartbeat. */
  renew_at: string | null
  /** Kubernetes Lease ``leaseDurationSeconds`` — the stale threshold. */
  lease_duration_s: number
  /** The KubeDash Deployment's spec.replicas; null when unknown (F14). */
  candidates: number | null
}

export interface Queue {
  pending: number
  processing: number
  done: number
  /** Dead letters (pgqueue.fail() after MAX_ATTEMPTS); 0 when none. */
  failed: number
  oldest_pending_at: string | null
}

export interface HaSection {
  status: HaStatusLevel
  reasons: string[]
}

export interface HaReport {
  probed_at: string
  spock_version: string
  nodes: HaNode[]
  leader: Leader
  queue: Queue
  status: HaStatusLevel
  reasons: string[]
  database: HaSection
  election: HaSection
  /** Config warnings (e.g. a typo'd node_dsn_overrides name) — [] when none. */
  warnings: string[]
}
