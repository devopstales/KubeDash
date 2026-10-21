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
import type { K8sSecret, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

type SecretRow = { name: string; type: string }

const toRow = (secret: K8sSecret): SecretRow => ({
  name: secret.metadata?.name ?? '',
  type: secret.type || 'N/A',
})

/**
 * 4.1 `security/secret.html.j2`: Secrets in the header-selected namespace.
 * The name opens the secret data page; `?selected=<name>` (the Service
 * Accounts links) bolds that secret's name.
 */
const SecretView = () => {
  const [params] = useSearchParams()
  const selected = params.get('selected')
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'

  const query = useQuery<SecretRow[]>({
    queryKey: ['secrets', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sSecret>>(
        `/api/v1/clusters/${cluster!.id}/resources/secrets?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  const nameLink = (name: string) =>
    name ? (
      <Link
        to={`/security/secret/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`}
        className={name === selected ? 'fw-bold' : undefined}
        aria-current={name === selected ? 'true' : undefined}
      >
        {name}
      </Link>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Security</CBreadcrumbItem>
          <CBreadcrumbItem active>Secrets</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Secret List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading secrets...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading secrets: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No secrets found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {nameLink}
            </Column>
            <Column title="Type" data="type" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default SecretView
