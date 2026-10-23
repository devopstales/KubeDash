import React from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CBadge,
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CProgress,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { K8sNode, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// ponytail: parse a K8s quantity the way the backend does (CPU in millicores,
// memory in bytes). The Metrics API reports used.cpu in NANOcores ("270808684n")
// — the n-suffix must be checked before m (a bare float("…n") raises).
const parseCpu = (qty: string | null | undefined): number | null => {
  if (!qty) return null
  if (qty.endsWith('n')) return Math.trunc(Number(qty.slice(0, -1)) / 1e6)
  if (qty.endsWith('m')) return Number(qty.slice(0, -1))
  return Number(qty) * 1000
}
const parseBytes = (qty: string | null | undefined): number | null => {
  if (!qty) return null
  const suffixes: [string, number][] = [
    ['Ki', 2 ** 10],
    ['Mi', 2 ** 20],
    ['Gi', 2 ** 30],
    ['Ti', 2 ** 40],
    ['Pi', 2 ** 50],
    ['Ei', 2 ** 60],
    ['K', 1e3],
    ['M', 1e6],
    ['G', 1e9],
    ['T', 1e12],
    ['P', 1e15],
    ['E', 1e18],
  ]
  for (const [s, mult] of suffixes) {
    if (qty.endsWith(s)) return Number(qty.slice(0, -s.length)) * mult
  }
  return Number(qty)
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

const PROBE_CONDITIONS = ['Ready', 'MemoryPressure', 'DiskPressure', 'PIDPressure']

// ponytail: taints render as "key=value:effect" badges (4.1's format).
const taintsOf = (node: K8sNode): string[] =>
  (node.spec?.taints ?? []).map((t) =>
    t.effect ? `${t.key ?? ''}=${t.value ?? ''}:${t.effect}` : `${t.key ?? ''}=${t.value ?? ''}`,
  )

// Certainty rule: used is a READ value. null → "unknown", never 0. The bar
// shows the used/allocatable fraction; an unknown used renders an empty bar
// (not a 0% bar, which would imply a healthy zero).
const UsedBar = ({ label, used, capacity, fmt }: {
  label: string
  used: number | null
  capacity: number | null
  fmt: (n: number | null) => string
}) => {
  const pct = used !== null && capacity !== null && capacity > 0 ? Math.min(100, (used / capacity) * 100) : null
  return (
    <div style={{ marginBottom: '.75rem' }}>
      <div className="d-flex justify-content-between" style={{ fontSize: '.8rem' }}>
        <span className="text-muted">{label}</span>
        <span>
          {fmt(used)} / {capacity !== null ? fmt(capacity) : 'unknown'}
        </span>
      </div>
      <CProgress
        value={pct ?? 0}
        color={pct === null ? 'secondary' : pct > 90 ? 'danger' : pct > 75 ? 'warning' : 'success'}
        style={{ height: '8px' }}
      />
    </div>
  )
}

const NodeDataView = () => {
  const [params] = useSearchParams()
  const name = params.get('name') || ''
  const cluster = useClusterStore((s) => s.selectedCluster)

  const list = useQuery<ResourceList<K8sNode>>({
    queryKey: ['nodes', cluster?.id],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sNode>>(
        `/api/v1/clusters/${cluster!.id}/resources/nodes`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? { items: [] }
    },
  })

  const node = (list.data?.items ?? []).find((n) => n.metadata?.name === name)

  const usage = useQuery<{
    metrics_available: boolean
    metrics_denied: boolean
    used_millicores: number | null
    used_bytes: number | null
  }>({
    queryKey: ['node-usage', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<{
        metrics_available: boolean
        metrics_denied: boolean
        used_millicores: number | null
        used_bytes: number | null
      }>(`/api/v1/clusters/${cluster!.id}/nodes/${encodeURIComponent(name)}/usage`)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? { metrics_available: false, metrics_denied: false, used_millicores: null, used_bytes: null }
    },
  })

  const status = node?.status
  const allocCpu = parseCpu(status?.allocatable?.cpu)
  const allocMem = parseBytes(status?.allocatable?.memory)
  const capCpu = parseCpu(status?.capacity?.cpu)
  const capMem = parseBytes(status?.capacity?.memory)
  const u = usage.data

  const conditions = (status?.conditions ?? []).map(
    (c) => [`${c.type ?? ''}`, `${c.status ?? ''}`, `${(c as { reason?: string }).reason ?? ''}`, `${(c as { message?: string }).message ?? ''}`] as [string, string, string, string],
  )
  const taints = node ? taintsOf(node) : []
  const info: [string, string][] = [
    ['Kubelet version', status?.node_info?.kubelet_version ?? ''],
    ['Container runtime', status?.node_info?.container_runtime_version ?? ''],
    ['OS image', status?.node_info?.os_image ?? ''],
    ['Kernel version', status?.node_info?.kernel_version ?? ''],
  ].filter(([, v]) => v) as [string, string][]
  const addresses = (status?.addresses ?? [])
    .map((a) => [`${a.type}`, `${a.address}`] as [string, string])
  const labels = Object.entries(node?.metadata?.labels ?? {})

  const readyToneBadge = () => {
    const ready = status?.conditions?.find((c) => c.type === 'Ready')
    const pressureOn = (status?.conditions ?? []).some(
      (c) => c.type && c.type !== 'Ready' && c.status === 'True',
    )
    const tone = ready?.status === 'True' ? (pressureOn ? 'warning' : 'success') : 'danger'
    return <CBadge color={tone}>{ready?.status === 'True' ? 'Ready' : 'NotReady'}</CBadge>
  }

  // Used-vs-allocatable: the observed (used) tier degrades to unknown when the
  // Metrics API is absent or the node is unscraped (certainty rule). The bar
  // compares used against ALLOCATABLE (the schedulable ceiling), not capacity
  // (which includes system-reserved headroom).
  const usageCard = () => {
    if (!u) return null
    return (
      <CCard className="shadow mb-4">
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">
            Observed usage (metrics.k8s.io)
          </CCardTitle>
        </CCardHeader>
        <CCardBody>
          {u.metrics_denied ? (
            <div className="text-warning">
              Usage is unknown — you lack the metrics.k8s.io read grant (RBAC
              denied). An admin can grant <code>get</code> on
              <code> nodes</code> in the <code>metrics.k8s.io</code> group.
            </div>
          ) : !u.metrics_available ? (
            <div className="text-warning">
              Usage is unknown — this cluster has no metrics-server
              (metrics.k8s.io unreachable). Install metrics-server to see live
              CPU/memory usage.
            </div>
          ) : (
            <>
              <UsedBar label="CPU used / allocatable" used={u.used_millicores} capacity={allocCpu} fmt={fmtCpu} />
              <UsedBar label="Memory used / allocatable" used={u.used_bytes} capacity={allocMem} fmt={fmtBytes} />
            </>
          )}
        </CCardBody>
      </CCard>
    )
  }

  const detailTable = (
    <CTable bordered>
      <tbody>
        <tr>
          <th scope="row">Status:</th>
          <td>{readyToneBadge()}</td>
        </tr>
        <tr>
          <th scope="row">Name:</th>
          <td>{node?.metadata?.name ?? ''}</td>
        </tr>
        <tr>
          <th scope="row">Created:</th>
          <td>{node?.metadata?.creation_timestamp ?? ''}</td>
        </tr>
        <tr>
          <th scope="row">Unschedulable:</th>
          <td>{node?.spec?.unschedulable ? 'Yes' : 'No'}</td>
        </tr>
        <tr>
          <th scope="row">Allocatable:</th>
          <td>
            CPU {fmtCpu(allocCpu)} · Memory {fmtBytes(allocMem)}
            {capCpu !== null ? ` · Capacity CPU ${fmtCpu(capCpu)}` : ''}
            {capMem !== null ? ` · Capacity Mem ${fmtBytes(capMem)}` : ''}
          </td>
        </tr>
        <tr>
          <th scope="row">Taints:</th>
          <td>
            {taints.length ? (
              taints.map((t) => (
                <CBadge key={t} color="secondary" className="me-1">
                  {t}
                </CBadge>
              ))
            ) : (
              'No taints'
            )}
          </td>
        </tr>
        <tr>
          <th scope="row">Conditions:</th>
          <td>
            {conditions.length ? (
              <CTable bordered small className="mb-0">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Reason</th>
                    <th>Message</th>
                  </tr>
                </thead>
                <tbody>
                  {conditions.map(([type, st, reason, message], i) => (
                    <tr key={i}>
                      <td>{type}</td>
                      <td>{st}</td>
                      <td>{reason}</td>
                      <td className="text-break">{message}</td>
                    </tr>
                  ))}
                </tbody>
              </CTable>
            ) : (
              'No conditions'
            )}
          </td>
        </tr>
        <tr>
          <th scope="row">Info:</th>
          <td>
            {info.length ? (
              <CTable bordered small className="mb-0">
                <tbody>
                  {info.map(([k, v]) => (
                    <tr key={k}>
                      <td>{k}</td>
                      <td>{v}</td>
                    </tr>
                  ))}
                </tbody>
              </CTable>
            ) : (
              'No node info'
            )}
          </td>
        </tr>
        <tr>
          <th scope="row">Addresses:</th>
          <td>{addresses.map(([k, v]) => `${k} ${v}`).join(' · ') || 'None'}</td>
        </tr>
        <tr>
          <th scope="row">Labels:</th>
          <td>{labels.length ? labels.map(([k, v]) => `${k}=${v}`).join(' · ') : 'No labels'}</td>
        </tr>
      </tbody>
    </CTable>
  )

  return (
    <>
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Cluster</CBreadcrumbItem>
            <CBreadcrumbItem>
              <Link to="/cluster/node">Nodes</Link>
            </CBreadcrumbItem>
            <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
          </CBreadcrumb>
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Node Data</CCardTitle>
        </CCardHeader>
        <CCardBody>
          {!name ? (
            <div className="text-danger">Error: Node name not provided</div>
          ) : !cluster ? (
            <div>No cluster selected.</div>
          ) : list.isLoading ? (
            <div>Loading node data...</div>
          ) : list.error ? (
            <div className="text-danger">Error loading node: {list.error.message}</div>
          ) : !node ? (
            <div className="text-danger">Error: Node '{name}' not found</div>
          ) : (
            detailTable
          )}
        </CCardBody>
      </CCard>
      {name && cluster && usageCard()}
    </>
  )
}

export default NodeDataView
