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

const UsageCell = ({ value }: { value: number | null }) => {
  if (value === null) {
    return <span className="text-muted">unknown</span>
  }
  const color = value > 90 ? 'danger' : value > 75 ? 'warning' : 'success'
  return (
    <div style={{ minWidth: '6rem' }}>
      <CProgress value={value} color={color} style={{ height: '8px' }} />
      <div className="text-end" style={{ fontSize: '.7rem' }}>
        {value}%
      </div>
    </div>
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
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Node List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : nodesQuery.isLoading ? (
          <div>Loading nodes...</div>
        ) : nodesQuery.error ? (
          <div className="text-danger">Error loading nodes: {nodesQuery.error.message}</div>
        ) : rows.length === 0 ? (
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
      </CCardBody>
    </CCard>
  )
}

export default NodesView
export { readyTone }
