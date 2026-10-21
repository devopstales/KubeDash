import React from 'react'
import { Link } from 'react-router-dom'
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
import type { ResourceList, ServiceAccount } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

type ServiceAccountRow = { name: string; secret: string; pullSecret: string }

const toRow = (sa: ServiceAccount): ServiceAccountRow => ({
  name: sa.metadata?.name ?? '',
  secret: sa.secrets?.[0]?.name ?? '',
  pullSecret: sa.image_pull_secrets?.[0]?.name ?? '',
})

const secretLink = (name: string) =>
  name ? <Link to={`/security/secret?selected=${encodeURIComponent(name)}`}>{name}</Link> : null

/**
 * 4.1 `cluster-permission/service-account.html.j2`: the service accounts in
 * the header-selected cluster and namespace, with their first token secret
 * and first image pull secret linked to the Secrets page.
 */
const ServiceAccountsView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'

  const query = useQuery<ServiceAccountRow[]>({
    queryKey: ['serviceaccounts', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ServiceAccount>>(
        `/api/v1/clusters/${cluster!.id}/resources/serviceaccounts?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Cluster Permissions</CBreadcrumbItem>
          <CBreadcrumbItem active>Service Accounts</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Service Accounts List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading service accounts…</div>
        ) : query.error ? (
          <div className="text-danger">Error loading service accounts: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No service accounts found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name" />
            <Column title="Secret" data="secret">
              {secretLink}
            </Column>
            <Column title="Pull Secret" data="pullSecret">
              {secretLink}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ServiceAccountsView
