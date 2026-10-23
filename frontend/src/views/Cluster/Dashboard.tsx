import React from 'react'
import {
  CBadge,
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import CIcon from '@coreui/icons-react'
import { cilBell } from '@coreui/icons'
import ConcentricDonut from '../../components/ConcentricDonut'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { apiFetch } from '../../lib/api'
import type { ClusterEvent, MetricsSummary } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

// One hue per resource (Option C, findings.md rev 6): CPU = blue (CoreUI
// primary), Memory = amber (CoreUI warning). The overcommit math lives in
// ConcentricDonut (single source) — the view only passes the raw sums.
const HUE_CPU: [number, number, number] = [22, 92, 255]
const HUE_MEMORY: [number, number, number] = [249, 177, 21]

// The donut's ring legend (operator ask: the three rings were opaque).
// Rendered inside each resource card so the explanation sits next to the
// chart it explains. Declared (requests/limits, pod specs) vs observed
// (used, metrics.k8s.io) are labeled distinctly — the certainty rule.
const DonutLegend = ({
  hue,
  ...rest
}: { hue: [number, number, number] } & Record<string, unknown>) => {
  const [r, g, b] = hue
  const swatch = (alpha: number) => (
    <span
      className="d-inline-block"
      style={{
        width: 10,
        height: 10,
        borderRadius: '50%',
        background: `rgba(${r}, ${g}, ${b}, ${alpha})`,
      }}
    />
  )
  return (
    <div className="d-flex flex-column gap-1 mb-2" style={{ fontSize: '.72rem' }} {...rest}>
      <span className="d-inline-flex align-items-center gap-2 text-muted">
        {swatch(1)} Used (observed · metrics.k8s.io)
      </span>
      <span className="d-inline-flex align-items-center gap-2 text-muted">
        {swatch(0.65)} Requests (declared · pod specs)
      </span>
      <span className="d-inline-flex align-items-center gap-2 text-muted">
        {swatch(0.35)} Limits (declared · pod specs)
      </span>
      <span className="text-muted">
        Inner ring = used · outer = limits · full circle = 100% of capacity
      </span>
    </div>
  )
}

type EventRow = {
  type: string
  reason: string
  object: string
  namespace: string
  message: string
  count: string
  last: string
}

const toEventRow = (event: ClusterEvent): EventRow => {
  const obj = event.involved_object ?? {}
  return {
    type: event.type ?? '',
    reason: event.reason ?? '',
    object: obj.kind ? `${obj.kind} ${obj.name}`.trim() : (obj.name ?? ''),
    namespace: obj.namespace ?? '',
    message: event.message ?? '',
    count: event.count == null ? '—' : String(event.count),
    last: event.last_timestamp ?? '—',
  }
}

const DashboardView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const enabled = cluster != null

  const summary = useQuery<MetricsSummary>({
    queryKey: ['cluster-metrics-summary', cluster?.id],
    enabled,
    queryFn: async () => {
      const r = await apiFetch<MetricsSummary>(`/api/v1/clusters/${cluster!.id}/metrics/summary`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data!
    },
  })

  const events = useQuery<ClusterEvent[]>({
    queryKey: ['cluster-events', cluster?.id],
    enabled,
    queryFn: async () => {
      const r = await apiFetch<ClusterEvent[]>(`/api/v1/clusters/${cluster!.id}/events`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? []
    },
  })

  // Version skew (AGENTS.md): a 404 from either endpoint (new frontend on an
  // old backend) is the EXPECTED state, not an error — the values render
  // unknown, never a red error. With retry:false a 404 throws into the query
  // error state, so a 404 is mapped out of `error` before it can be rendered.
  // apiFetch envelopes HTTP errors as `Error("<code>: <message>")` where
  // code is the backend's error code ('NOT_FOUND' for 404) — match on the
  // code prefix, not the message text.
  const is404 = (error: unknown) => error instanceof Error && /^NOT_FOUND: /.test(error.message)
  const metrics = !is404(summary.error) ? summary.data : null
  const eventRows = !is404(events.error) ? (events.data ?? []).map(toEventRow) : []

  const eventsFailed = events.error && !is404(events.error)

  return (
    <>
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Dashboard</CBreadcrumbItem>
            <CBreadcrumbItem active>Cluster Metrics</CBreadcrumbItem>
          </CBreadcrumb>
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">
            Cluster Dashboard{cluster ? ` — ${cluster.name}` : ''}
          </CCardTitle>
        </CCardHeader>
        <CCardBody>
          {!cluster ? (
            <div>No cluster selected.</div>
          ) : summary.isLoading || events.isLoading ? (
            <div>Loading cluster metrics...</div>
          ) : (
            <>
              {/* Certainty rule (AGENTS.md): "unknown" must say WHY — and say
                  the RIGHT why. Two distinct states (OWASP A05/A10):
                  - metrics_denied: the caller lacks the metrics.k8s.io read
                    grant. Do NOT suggest installing metrics-server; the fix
                    is an RBAC grant, not a component.
                  - !metrics_available (and not denied): the Metrics API is
                    genuinely absent on this cluster — the install advice
                    applies. */}
              {metrics && metrics.metrics_denied ? (
                <CBadge
                  color="warning"
                  className="mb-3 d-inline-flex align-items-center gap-2 px-3 py-2"
                >
                  <CIcon icon={cilBell} customClassName="nav-icon" />
                  Usage (used) is hidden — your account lacks the metrics.k8s.io read grant on this
                  cluster. An admin can grant it to see live CPU/memory usage; requests and limits
                  below are declared pod specs and are always available.
                </CBadge>
              ) : metrics && !metrics.metrics_available ? (
                <CBadge
                  color="warning"
                  className="mb-3 d-inline-flex align-items-center gap-2 px-3 py-2"
                >
                  <CIcon icon={cilBell} customClassName="nav-icon" />
                  Usage (used) is unknown — this cluster has no metrics-server (metrics.k8s.io
                  unreachable). Install metrics-server to see live CPU/memory usage; requests and
                  limits below are declared pod specs and are always available.
                </CBadge>
              ) : null}
              {/* Row 1: allocation donuts — one card per donut. The ring
                  legend lives INSIDE each card (operator ask): the donut
                  encodes three values on three concentric rings, declared
                  (requests/limits, pod specs) vs observed (used,
                  metrics.k8s.io) — the certainty rule made visible. */}
              <div className="row g-4 mb-4">
                <div className="col-12 col-md-4">
                  <CCard>
                    <CCardHeader>
                      <CCardTitle className="m-0 fs-6 fw-bold">CPU</CCardTitle>
                    </CCardHeader>
                    <CCardBody>
                      <DonutLegend hue={HUE_CPU} data-testid="donut-legend-cpu" />
                      <ConcentricDonut
                        used={metrics?.cpu.used_millicores ?? null}
                        requests={metrics?.cpu.requests_millicores ?? 0}
                        limits={metrics?.cpu.limits_millicores ?? 0}
                        capacity={metrics?.cpu.capacity_millicores ?? 0}
                        hue={HUE_CPU}
                        label="CPU"
                        ariaLabel="CPU used, requests, limits concentric donut"
                      />
                    </CCardBody>
                  </CCard>
                </div>
                <div className="col-12 col-md-4">
                  <CCard>
                    <CCardHeader>
                      <CCardTitle className="m-0 fs-6 fw-bold">Memory</CCardTitle>
                    </CCardHeader>
                    <CCardBody>
                      <DonutLegend hue={HUE_MEMORY} data-testid="donut-legend-mem" />
                      <ConcentricDonut
                        used={metrics?.memory.used_bytes ?? null}
                        requests={metrics?.memory.requests_bytes ?? 0}
                        limits={metrics?.memory.limits_bytes ?? 0}
                        capacity={metrics?.memory.capacity_bytes ?? 0}
                        hue={HUE_MEMORY}
                        label="Memory"
                        ariaLabel="Memory used, requests, limits concentric donut"
                      />
                    </CCardBody>
                  </CCard>
                </div>
                <div className="col-12 col-md-4">
                  <CCard>
                    <CCardHeader>
                      <CCardTitle className="m-0 fs-6 fw-bold">Pods</CCardTitle>
                    </CCardHeader>
                    <CCardBody>
                      {/* The pods counts come from the same summary as the
                          used values: summary 404 (version skew) → unknown. */}
                      {metrics ? (
                        <div className="d-flex flex-column gap-2 py-4">
                          <div className="d-flex justify-content-between">
                            <span className="text-muted">Capacity</span>
                            <span>{metrics.pods.capacity}</span>
                          </div>
                          <div className="d-flex justify-content-between">
                            <span className="text-muted">Running</span>
                            <span>{metrics.pods.running}</span>
                          </div>
                          <div className="d-flex justify-content-between">
                            <span className="text-muted">Pending</span>
                            <span>{metrics.pods.pending}</span>
                          </div>
                          <div className="d-flex justify-content-between">
                            <span className="text-muted">Completed</span>
                            <span>{metrics.pods.completed}</span>
                          </div>
                        </div>
                      ) : (
                        <div className="text-muted py-4">unknown</div>
                      )}
                    </CCardBody>
                  </CCard>
                </div>
              </div>

              {/* Row 2: cluster events (the endpoint's newest-first order, as-is). */}
              <CCard>
                <CCardHeader>
                  <CCardTitle className="m-0 fs-6 fw-bold">Events</CCardTitle>
                </CCardHeader>
                <CCardBody>
                  {eventsFailed ? (
                    <div className="text-danger">Error loading events: {events.error!.message}</div>
                  ) : eventRows.length === 0 ? (
                    <div className="text-center text-muted">No events found</div>
                  ) : (
                    <KubeDataTable data={eventRows}>
                      <Column title="Type" data="type">
                        {(type: string) => (
                          <CBadge color={type === 'Warning' ? 'warning' : 'success'}>{type}</CBadge>
                        )}
                      </Column>
                      <Column title="Reason" data="reason" />
                      <Column title="Object" data="object" />
                      <Column title="Namespace" data="namespace" />
                      <Column title="Message" data="message" />
                      <Column title="Count" data="count" />
                      <Column title="Last seen" data="last" />
                    </KubeDataTable>
                  )}
                </CCardBody>
              </CCard>
            </>
          )}
          {summary.error && !is404(summary.error) ? (
            <div className="text-danger mt-3">Error loading metrics: {summary.error.message}</div>
          ) : null}
        </CCardBody>
      </CCard>
    </>
  )
}

export default DashboardView
