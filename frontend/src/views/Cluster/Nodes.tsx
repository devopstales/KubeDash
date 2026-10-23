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

// ponytail: node condition status is the literal "True"/"False"/"Unknown".
// Ready True with no pressure condition ON is the only healthy tone.
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

  const nodes = query.data?.items ?? []

  const statusCell = (node: K8sNode) => {
    const tone = readyTone(node.status?.conditions ?? [])
    const ready = node.status?.conditions?.find((c) => c.type === 'Ready')
    return <CBadge color={tone}>{ready?.status === 'True' ? 'Ready' : 'NotReady'}</CBadge>
  }
  const nameCell = (node: K8sNode) => (
    <Link to={`/cluster/node/data?name=${encodeURIComponent(node.metadata?.name ?? '')}`}>
      {node.metadata?.name ?? ''}
    </Link>
  )
  const osCell = (node: K8sNode) => node.status?.node_info?.os_image ?? '\u2014'
  const kubeletCell = (node: K8sNode) => node.status?.node_info?.kubelet_version ?? '\u2014'
  const createdCell = (node: K8sNode) => node.metadata?.creation_timestamp ?? '\u2014'

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
        ) : nodes.length === 0 ? (
          <div className="text-center text-muted">No nodes found</div>
        ) : (
          <KubeDataTable data={nodes}>
            <Column title="Status" data="status">
              {(node: K8sNode) => statusCell(node)}
            </Column>
            <Column title="Node" data="name">
              {(node: K8sNode) => nameCell(node)}
            </Column>
            <Column title="OS Image" data="os">
              {(node: K8sNode) => osCell(node)}
            </Column>
            <Column title="Kubelet" data="kubelet">
              {(node: K8sNode) => kubeletCell(node)}
            </Column>
            <Column title="Created" data="created">
              {(node: K8sNode) => createdCell(node)}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default NodesView
export { readyTone }
