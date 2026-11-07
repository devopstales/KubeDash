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
import type { ResourceList, ServiceItem } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (core v1, the API resource name) and the ONE
// clean list route this page renders (2026-10-28-service-views). The name
// button writes the ref + navigates here; the ObjectRoute at the route
// renders the ref-matched ServiceData (the URL never carries identity, R1).
const KIND = 'service'
const LIST_ROUTE = '/network/service'

type ServiceRow = { name: string; type: string; clusterIp: string; externalIp: string }

// 4.1's External IP: status.load_balancer.ingress[0].ip for a LoadBalancer,
// else "—". The 4.1 deep index 500s on a pending LoadBalancer with no
// ingress yet — 5.0 renders "—" for absent ingress/ip (certainty rule:
// never crash the row).
const externalIp = (item: ServiceItem): string => {
  if (item.spec?.type !== 'LoadBalancer') return '—'
  const ingress = item.status?.load_balancer?.ingress?.[0]
  return ingress?.ip ?? '—'
}

const toRow = (item: ServiceItem): ServiceRow => ({
  name: item.metadata?.name ?? '',
  // "—" when absent (certainty rule: never guess).
  type: item.spec?.type ?? '—',
  clusterIp: item.spec?.cluster_ip ?? '—',
  externalIp: externalIp(item),
})

/**
 * 4.1 `network/service.html.j2`: Services in the header-selected namespace
 * (columns Name / Type / Cluster IP / External IP — 4.1's card title stays
 * EXACTLY "Service List", the e2e-smoke contract). ADR-0022 placement: the
 * Network group (the 4.1 `network/` template, ported 1:1 with the 5.0
 * deltas). ADR-0040: the name cell is a button (not a Link) — openObject
 * writes the ref to sessionStorage and navigates to the clean list route;
 * the URL never carries object identity (R1). Namespaced: the namespace
 * rides the ref, not the URL (R8). The bold is driven by the active ref (R9).
 */
const ServiceView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<ServiceRow[]>({
    queryKey: ['services', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ServiceItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/services?namespace=${encodeURIComponent(namespace)}`,
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

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem active>Service List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Service List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading services...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading services: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No services found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(typeof name === 'string' ? name : '')}
            </Column>
            <Column title="Type" data="type" />
            <Column title="Cluster IP" data="clusterIp" />
            <Column title="External IP" data="externalIp" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ServiceView
