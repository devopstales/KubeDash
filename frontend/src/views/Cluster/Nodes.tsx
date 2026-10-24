import React from 'react'
import { Link } from 'react-router-dom'
import {
  CBadge,
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CProgress,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { apiFetch } from '../../lib/api'
import type { K8sNode, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

// ponytail: KubeDataTable cell renderers receive row[data] (DataTables
// dataGet), so rows must be FLAT objects whose keys match the Column data
// attrs — the toRow pattern the Roles/Namespaces views use.
type Conditions = NonNullable<K8sNode['status']>['conditions']

const readyTone = (conditions: Conditions): 'success' | 'danger' => {
  const ready = conditions?.find((c) => c.type === 'Ready')
  return ready?.status === 'True' ? 'success' : 'danger'
}

// 4.1 derives Role from the node-role.kubernetes.io/<role> label; a node with
// no role label is a Worker (4.1's default).
const nodeRole = (labels: Record<string, string> | null | undefined): string => {
  if (!labels) return 'Worker'
  for (const [key, value] of Object.entries(labels)) {
    if (key.startsWith('node-role.kubernetes.io/')) {
      const role = key.split('/')[1]
      if (role) return role.charAt(0).toUpperCase() + role.slice(1)
    }
  }
  return 'Worker'
}

const nodeIp = (node: K8sNode): string => {
  const addresses = node.status?.addresses ?? []
  const order = ['InternalIP', 'ExternalIP', 'Hostname']
  for (const type of order) {
    const a = addresses.find((x) => x.type === type)
    if (a?.address) return a.address
  }
  return '\u2014'
}

type NodeRow = {
  name: string
  status: string
  tone: 'success' | 'danger'
  role: string
  version: string
  ip: string
  os: string
  cpu_pct: number | null
  mem_pct: number | null
}

const toRow = (node: K8sNode, cpuPct: number | null, memPct: number | null): NodeRow => ({
  name: node.metadata?.name ?? '',
  status: node.status?.conditions?.find((c) => c.type === 'Ready')?.status === 'True' ? 'Ready' : 'NotReady',
  tone: readyTone(node.status?.conditions),
  role: nodeRole(node.metadata?.labels),
  version: node.status?.node_info?.kubelet_version ?? '\u2014',
  ip: nodeIp(node),
  os: node.status?.node_info?.os_image ?? '\u2014',
  cpu_pct: cpuPct,
  mem_pct: memPct,
})

// ponytail: used/capacity as an integer percentage, or null when either term
// is unknown (certainty rule: never 0 for an unknown source).
const pct = (used: number | null, capacity: number | null): number | null =>
  used !== null && capacity !== null && capacity > 0
    ? Math.min(100, Math.round((used / capacity) * 100))
    : null

// Per-node usage cell: a THIN 4px bar (matching the tile style) with the %
// to its right. The prototype's table cells are plain "38%" text; we keep the
// bar because it's the "progress" the node view is built around, but match the
// prototype's thin bar + muted % tone.
const UsageCell = ({ value }: { value: number | null }) => {
  if (value === null) {
    return <span className="text-muted">unknown</span>
  }
  const color = value > 90 ? 'danger' : value > 75 ? 'warning' : 'success'
  return (
    <div className="d-flex align-items-center gap-2" style={{ minWidth: '6rem' }}>
      {/* className→outer .progress, progressBarClassName→inner bar. Do NOT
          pass a `style` prop here: CProgress __rest-spreads it onto the bar
          and overwrites the width (the empty-bar bug, commit 8ca17a2a). */}
      <CProgress
        value={value}
        color={color}
        height={4}
        className="flex-grow-1"
        progressBarClassName="progress-bar"
      />
      <span className="text-muted" style={{ fontSize: '.75rem', minWidth: '2.2rem', textAlign: 'right' }}>
        {value}%
      </span>
    </div>
  )
}

const fmtBytes = (n: number | null): string => {
  if (n === null) return 'unknown'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`
}
const fmtCpu = (m: number | null): string => {
  if (m === null) return 'unknown'
  return m >= 1000 ? `${(m / 1000).toFixed(m % 1000 === 0 ? 0 : 2)} cores` : `${m}m`
}

// Cluster metric tile (dashboard-1-41.html reference). The big number is the
// stat value (fs-5→1.75rem scale, `%` as a small muted suffix), over a THIN
// 4px bar (the prototype's `progress height:4px`). Certainty rule: value
// null → the word "unknown", never 0 or a healthy tone. Storage has no source
// → unknown with a "no storage metrics source" note.
const Tile = ({
  label,
  value,
  suffix,
  sub,
  pctValue,
}: {
  label: string
  value: string
  suffix?: string
  sub?: string
  pctValue: number | null
}) => {
  const unknown = pctValue === null && value === 'unknown'
  return (
    <CCard className="border-0 h-100">
      <CCardBody className="py-3">
        <div className="text-muted text-uppercase" style={{ fontSize: '.7rem', letterSpacing: '.04em' }}>
          {label}
        </div>
        <div className="fw-semibold" style={{ fontSize: '1.5rem', lineHeight: 1.2, margin: '.25rem 0' }}>
          {unknown ? (
            <span className="text-muted" style={{ fontSize: '1.15rem' }}>
              unknown
            </span>
          ) : (
            <>
              {value}
              {suffix ? (
                <span className="text-muted" style={{ fontSize: '.95rem' }}>
                  {suffix}
                </span>
              ) : null}
            </>
          )}
        </div>
        <CProgress
          value={pctValue ?? 0}
          color={pctValue === null ? 'secondary' : pctValue > 90 ? 'danger' : pctValue > 75 ? 'warning' : 'success'}
          height={4}
        />
        {sub ? (
          <div className="text-muted" style={{ fontSize: '.7rem', marginTop: '.4rem' }}>
            {sub}
          </div>
        ) : null}
      </CCardBody>
    </CCard>
  )
}

const NodesView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const nodesQuery = useQuery<ResourceList<K8sNode>>({
    queryKey: ['nodes', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sNode>>(
        `/api/v1/clusters/${cluster!.id}/resources/nodes`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? { items: [] }
    },
  })

  // The per-node used tier (blueprint Task 3). A 404 (version skew: old
  // backend) or error degrades to "no metrics" — the view still renders the
  // declared columns, used shows unknown (never a red error).
  const metricsQuery = useQuery<{
    cluster: string
    metrics_available: boolean
    source: string
    items: Array<{
      name: string
      cpu_used_millicores: number | null
      cpu_capacity_millicores: number | null
      memory_used_bytes: number | null
      memory_capacity_bytes: number | null
    }>
  }>({
    queryKey: ['node-metrics', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<{
        cluster: string
        metrics_available: boolean
        source: string
        items: Array<{
          name: string
          cpu_used_millicores: number | null
          cpu_capacity_millicores: number | null
          memory_used_bytes: number | null
          memory_capacity_bytes: number | null
        }>
      }>(`/api/v1/clusters/${cluster!.id}/metrics/nodes`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? { cluster: '', metrics_available: false, source: 'metrics.k8s.io', items: [] }
    },
  })

  const metricsByNode = new Map(
    (metricsQuery.data?.items ?? []).map((item) => [item.name, item]),
  )

  const rows = (nodesQuery.data?.items ?? []).map((node) => {
    const m = metricsByNode.get(node.metadata?.name ?? '')
    return toRow(
      node,
      m ? pct(m.cpu_used_millicores, m.cpu_capacity_millicores) : null,
      m ? pct(m.memory_used_bytes, m.memory_capacity_bytes) : null,
    )
  })

  // Cluster rollup for the four tiles (blueprint Task 4): sum usage / sum
  // capacity across nodes. Any term that can't be read (metrics unavailable,
  // a node with no capacity) makes the tile "unknown" — never 0 (certainty
  // rule). Pods = Ready/Total from the node list (always readable). Storage
  // has no source → always unknown.
  const items = metricsQuery.data?.items ?? []
  const metricsAvailable = metricsQuery.data?.metrics_available ?? false
  const hasUsed = items.length > 0 && items.every((i) => i.cpu_used_millicores !== null && i.memory_used_bytes !== null)
  const hasCap = items.length > 0 && items.every((i) => i.cpu_capacity_millicores !== null && i.memory_capacity_bytes !== null)
  const cpuUsed = hasUsed ? items.reduce((s, i) => s + (i.cpu_used_millicores ?? 0), 0) : null
  const cpuCap = hasCap ? items.reduce((s, i) => s + (i.cpu_capacity_millicores ?? 0), 0) : null
  const memUsed = hasUsed ? items.reduce((s, i) => s + (i.memory_used_bytes ?? 0), 0) : null
  const memCap = hasCap ? items.reduce((s, i) => s + (i.memory_capacity_bytes ?? 0), 0) : null
  const cpuPct = pct(cpuUsed, cpuCap)
  const memPct = pct(memUsed, memCap)
  const readyCount = rows.filter((r) => r.status === 'Ready').length
  const totalPods = rows.length

  const statusCell = (tone: NodeRow['tone'], status: string) => (
    <CBadge color={tone}>{status}</CBadge>
  )
  const nameCell = (name: string) => (
    <Link to={`/cluster/node/data?name=${encodeURIComponent(name)}`}>{name}</Link>
  )

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster</CBreadcrumbItem>
          <CBreadcrumbItem active>Nodes</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Cluster Metrics</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : nodesQuery.isLoading ? (
          <div>Loading nodes...</div>
        ) : nodesQuery.error ? (
          <div className="text-danger">Error loading nodes: {nodesQuery.error.message}</div>
        ) : (
          <>
            {/* Cluster metric tiles (blueprint Task 4): CPU/Memory usage,
                Pods (Ready/Total), Storage (no source → unknown). The
                certainty rule: an unreadable rollup is "unknown", never 0. */}
            <div className="row row-cols-2 row-cols-lg-4 g-3 mb-4">
              <div className="col">
                <Tile
                  label="CPU usage"
                  value={cpuPct === null ? 'unknown' : `${cpuPct}`}
                  suffix={cpuPct === null ? undefined : '%'}
                  sub={cpuUsed !== null || cpuCap !== null ? `${fmtCpu(cpuUsed)} / ${fmtCpu(cpuCap)}` : 'no metrics source'}
                  pctValue={cpuPct}
                />
              </div>
              <div className="col">
                <Tile
                  label="Memory usage"
                  value={memPct === null ? 'unknown' : `${memPct}`}
                  suffix={memPct === null ? undefined : '%'}
                  sub={memUsed !== null || memCap !== null ? `${fmtBytes(memUsed)} / ${fmtBytes(memCap)}` : 'no metrics source'}
                  pctValue={memPct}
                />
              </div>
              <div className="col">
                <Tile
                  label="Pods"
                  value={`${readyCount}/${totalPods}`}
                  sub="ready / total nodes"
                  pctValue={totalPods > 0 ? Math.round((readyCount / totalPods) * 100) : 0}
                />
              </div>
              <div className="col">
                <Tile
                  label="Storage"
                  value="unknown"
                  sub="no storage metrics source"
                  pctValue={null}
                />
              </div>
            </div>
            {rows.length === 0 ? (
              <div className="text-center text-muted">No nodes found</div>
            ) : (
              <KubeDataTable data={rows}>
                <Column title="State" data="status">
                  {(status: string, _type: string, row: NodeRow) => statusCell(row.tone, status)}
                </Column>
                <Column title="Name" data="name">
                  {(name: string) => nameCell(name)}
                </Column>
                <Column title="Role" data="role" />
                <Column title="Version" data="version" />
                <Column title="IP" data="ip" />
                <Column title="OS" data="os" />
                <Column title="CPU Usage" data="cpu_pct">
                  {(v: number | null) => <UsageCell value={v} />}
                </Column>
                <Column title="Memory Usage" data="mem_pct">
                  {(v: number | null) => <UsageCell value={v} />}
                </Column>
              </KubeDataTable>
            )}
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default NodesView
export { readyTone }
