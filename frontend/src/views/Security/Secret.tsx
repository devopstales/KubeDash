import React from 'react'
import { useNavigate } from 'react-router-dom'
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
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { K8sSecret, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import ShareObjectButton from '../../components/ShareObjectButton'
import TopMenu from '../../components/TopMenu'

// The kind is namespaced (unlike the cluster-scoped priorityclass template);
// this route is the ADR-0040 secret object kind (TICKET-03).
const KIND = 'secret'
const LIST_ROUTE = '/security/secret'

type SecretRow = { name: string; type: string }

const toRow = (secret: K8sSecret): SecretRow => ({
  name: secret.metadata?.name ?? '',
  type: secret.type || 'N/A',
})

/**
 * 4.1 `security/secret.html.j2`: Secrets in the header-selected namespace.
 * A name opens the secret data page via openObject (ADR-0040): the URL never
 * carries object identity (R1). The previously-opened secret's name is
 * bolded from the active ref (getActiveRef), not a `?selected=` param (R9).
 */
const SecretView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

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

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref to sessionStorage and navigates to the clean list route; the URL
  // never carries object identity (R1). Namespaced: the namespace is carried
  // in the ref, not the URL. The bold is driven by the active ref (R9).
  const nameCell = (name: string) =>
    name ? (
      <>
        <button
          type="button"
          className={
            'btn btn-link btn-sm p-0 text-primary text-decoration-underline' +
            (name === selected ? ' fw-bold' : '')
          }
          aria-current={name === selected ? 'true' : undefined}
          onClick={() => openObject(KIND, name, namespace, LIST_ROUTE, navigate)}
        >
          {name}
        </button>{' '}
        <ShareObjectButton kind={KIND} name={name} namespace={namespace} listRoute={LIST_ROUTE} />
      </>
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
              {nameCell}
            </Column>
            <Column title="Type" data="type" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default SecretView
