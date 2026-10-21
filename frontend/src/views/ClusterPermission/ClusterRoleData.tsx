import React from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import type { K8sClusterRole, PolicyRule, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

type RuleRow = {
  apiGroups: string[]
  resourceNames: string[]
  resources: string[]
  verbs: string[]
}

const toRule = (rule: PolicyRule): RuleRow => ({
  apiGroups: rule.api_groups ?? [],
  resourceNames: rule.resource_names ?? [],
  resources: rule.resources ?? [],
  verbs: rule.verbs ?? [],
})

/** 4.1 `formatArrayValue`: drop blank entries, one value per line. */
const lines = (value: string[] | undefined) => {
  const items = (value ?? []).filter((item) => item && item.length > 0)
  if (items.length === 0) return ' '
  return (
    <>
      {items.map((item, i) => (
        <span key={`${item}-${i}`}>
          {i > 0 ? <br /> : null}
          {item}
        </span>
      ))}
    </>
  )
}

/**
 * 4.1 `cluster-permission/cluster-role-data.html.j2`: the rules of one
 * ClusterRole. The "Non Resources" column shows resource names, matching
 * that page.
 */
const ClusterRoleDataView = () => {
  const [params] = useSearchParams()
  const name = params.get('name') ?? ''
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<RuleRow[]>({
    queryKey: ['clusterroles', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sClusterRole>>(
        `/api/v1/clusters/${cluster!.id}/resources/clusterroles`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const role = (r.data?.items ?? []).find((item) => item.metadata?.name === name)
      if (!role) throw new Error(`Cluster role '${name}' not found`)
      return (role.rules ?? []).map(toRule)
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster Permissions</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/cluster-permission/cluster-role">Cluster Role</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Rule List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: Cluster role name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading rules...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading cluster role: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No rules found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="API Groups" data="apiGroups">
              {lines}
            </Column>
            <Column title="Non Resources" data="resourceNames">
              {lines}
            </Column>
            <Column title="Resources" data="resources">
              {lines}
            </Column>
            <Column title="Verbs" data="verbs">
              {lines}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ClusterRoleDataView
