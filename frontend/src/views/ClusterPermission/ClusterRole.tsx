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
import { apiFetch } from '../../lib/api'
import type { K8sClusterRole, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

/** 4.1 drops this annotation from the Cluster Role list (`cluster-role.html.j2`). */
const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'

type ClusterRoleRow = {
  name: string
  labels: Record<string, string>
  annotations: Record<string, string>
}

const toRow = (role: K8sClusterRole): ClusterRoleRow => ({
  name: role.metadata?.name ?? '',
  labels: role.metadata?.labels ?? {},
  annotations: role.metadata?.annotations ?? {},
})

const badges = (entries: [string, string][]) => {
  if (entries.length === 0) return ' '
  return (
    <>
      {entries.map(([key, value], i) => (
        <span key={key}>
          {i > 0 ? <br /> : null}
          <CBadge color="secondary">
            {key}: {value}
          </CBadge>
        </span>
      ))}
    </>
  )
}

/**
 * 4.1 `cluster-permission/cluster-role.html.j2`: ClusterRoles on the
 * header-selected cluster. The name opens the rule list. Labels and
 * annotations render as secondary badges; the last-applied annotation
 * is omitted. ClusterRoles are cluster-scoped, so the selected namespace
 * is not sent.
 */
const ClusterRoleView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<ClusterRoleRow[]>({
    queryKey: ['clusterroles', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sClusterRole>>(
        `/api/v1/clusters/${cluster!.id}/resources/clusterroles`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  const nameLink = (name: string) =>
    name ? (
      <Link to={`/cluster-permission/cluster-role/data?name=${encodeURIComponent(name)}`}>
        {name}
      </Link>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster Permissions</CBreadcrumbItem>
          <CBreadcrumbItem active>Cluster Role</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Cluster Role List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading cluster roles...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading cluster roles: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No cluster roles found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {nameLink}
            </Column>
            <Column title="Labels" data="labels">
              {(labels: Record<string, string>) => badges(Object.entries(labels ?? {}))}
            </Column>
            <Column title="Annotations" data="annotations">
              {(annotations: Record<string, string>) =>
                badges(Object.entries(annotations ?? {}).filter(([key]) => key !== LAST_APPLIED))
              }
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ClusterRoleView
