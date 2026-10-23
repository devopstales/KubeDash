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
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'
import { apiFetch } from '../../lib/api'
import type { K8sNode, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

// ponytail: KubeDataTable's cell renderers receive row[data] (the real
// DataTables dataGet), so the rows must be FLAT objects whose keys match the
// Column data attrs — the same toRow pattern the Roles/Namespaces views use.
// Passing raw nested K8sNode objects made dataGet request "name" on a node
// that has no top-level name → the "unknown parameter" warning.
type Conditions = NonNullable<K8sNode['status']>['conditions']

const readyTone = (conditions: Conditions): 'success' | 'warning' | 'danger' => {
  if (!conditions?.length) return 'danger'
  const ready = conditions.find((c) => c.type === 'Ready')
  const pressureOn = conditions.some(
    (c) => c.type && c.type !== 'Ready' && c.status === 'True',
  )
  if (ready?.status !== 'True') return 'danger'
  return pressureOn ? 'warning' : 'success'
}

type NodeRow = {
  name: string
  status: string
  tone: 'success' | 'warning' | 'danger'
  os: string
  kubelet: string
  created: string
}

const toRow = (node: K8sNode): NodeRow => {
  const conditions = node.status?.conditions ?? []
  const ready = conditions.find((c) => c.type === 'Ready')
  return {
    name: node.metadata?.name ?? '',
    status: ready?.status === 'True' ? 'Ready' : 'NotReady',
    tone: readyTone(conditions),
    os: node.status?.node_info?.os_image ?? '\u2014',
    kubelet: node.status?.node_info?.kubelet_version ?? '\u2014',
    created: node.metadata?.creation_timestamp ?? '\u2014',
  }
}

const NodesView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<ResourceList<K8sNode>>({
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

  const rows = (query.data?.items ?? []).map(toRow)

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
        ) : query.isLoading ? (
          <div>Loading nodes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading nodes: {query.error.message}</div>
        ) : rows.length === 0 ? (
          <div className="text-center text-muted">No nodes found</div>
        ) : (
          <KubeDataTable data={rows}>
            <Column title="Status" data="status">
              {(status: string, _type: string, row: NodeRow) => statusCell(row.tone, status)}
            </Column>
            <Column title="Node" data="name">
              {(name: string) => nameCell(name)}
            </Column>
            <Column title="OS Image" data="os" />
            <Column title="Kubelet" data="kubelet" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default NodesView
export { readyTone }
