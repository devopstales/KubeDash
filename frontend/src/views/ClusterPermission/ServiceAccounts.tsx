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
import type { ResourceList, ServiceAccount } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040 TICKET-04: the registry kind for service accounts (namespaced);
// the list route is where a name's click lands the user (clean URL, R1).
const KIND = 'serviceaccount'
const LIST_ROUTE = '/cluster-permission/service-account'
// The cross-kind target of the secret cells (R9: the ?selected= producer
// is deleted; the click resolves on the secret view's own route).
const SECRET_ROUTE = '/security/secret'

type ServiceAccountRow = { name: string; secret: string; pullSecret: string }

const toRow = (sa: ServiceAccount): ServiceAccountRow => ({
  name: sa.metadata?.name ?? '',
  secret: sa.secrets?.[0]?.name ?? '',
  pullSecret: sa.image_pull_secrets?.[0]?.name ?? '',
})

/**
 * 4.1 `cluster-permission/service-account.html.j2`: the service accounts in
 * the header-selected cluster and namespace, with their first token secret
 * and first image pull secret linked to the Secrets page. A name opens the
 * Service Account data page via openObject (ADR-0040): the URL never
 * carries object identity (R1). The previously-opened account's name is
 * bolded from the active ref (getActiveRef), not a `?selected=` param (R9).
 */
const ServiceAccountsView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

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
        </button>
      </>
    ) : null

  // Cross-kind link: a token/pull secret name opens the SECRET kind's detail
  // (openObject with the target kind; the click lands on the secret list
  // route, whose ObjectRoute renders the secret detail).
  const secretCell = (name: string) =>
    name ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject('secret', name, namespace, SECRET_ROUTE, navigate)}
      >
        {name}
      </button>
    ) : null

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
            <Column title="Name" data="name">
              {nameCell}
            </Column>
            <Column title="Secret" data="secret">
              {secretCell}
            </Column>
            <Column title="Pull Secret" data="pullSecret">
              {secretCell}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ServiceAccountsView
