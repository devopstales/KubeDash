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
import { formatAge } from '../../lib/format'
import { openObject } from '../../lib/objectRef'
import type { GatewayClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders. GatewayClass is a cluster-scoped CRD
// (gateway.networking.k8s.io v1): the list URL and the openObject ref carry
// NO namespace. The CRD's OWN served version + scope is the backend's
// authority (the VPA seam); CRD-absent (Gateway API not installed) is a
// first-class empty state, not an error.
const KIND = 'gatewayclass'
const LIST_ROUTE = '/network/gateway-class'

type GatewayClassRow = {
  name: string
  controller: string
  age: string
}

const toRow = (item: GatewayClassItem): GatewayClassRow => ({
  name: item.metadata?.name ?? '',
  // FULL custom object — camelCase (the CRD seam, unlike the core API kinds).
  // "—" when absent (certainty rule: never guess).
  controller: item.spec?.controllerName ?? '—',
  // The 5.0 cluster-scoped CRD list convention: human-readable Age (the full
  // creationTimestamp is in the data view + the JSON block).
  age: formatAge(item.metadata?.creationTimestamp),
})

/**
 * NEW (4.1 had no Gateway API): cluster-scoped GatewayClasses (Name /
 * Controller / Age) on the VPA CRD seam. The card title is EXACTLY
 * "GatewayClass List" (the 5.0 `<Kind> List` convention). ADR-0040: the name
 * cell is a button (not a Link) — openObject writes the ref and navigates
 * to the clean route; the URL never carries object identity (R1).
 */
const GatewayClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<GatewayClassRow[]>({
    queryKey: ['gatewayclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<GatewayClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/gatewayclasses`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  const nameCell = (name: string) =>
    name ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject(KIND, name, undefined, LIST_ROUTE, navigate)}
      >
        {name}
      </button>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem active>GatewayClass List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">GatewayClass List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading gateway classes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading gateway classes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          // CRD-absent (Gateway API not installed) and "none exist" render
          // the same pinned copy (the VPA absence contract).
          <div className="text-center text-muted">No gateway classes found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="Controller" data="controller" />
            <Column title="Age" data="age" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default GatewayClassView
