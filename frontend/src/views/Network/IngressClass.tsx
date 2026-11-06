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
import { formatTimestamp } from '../../lib/format'
import { openObject } from '../../lib/objectRef'
import type { IngressClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders. IngressClass is cluster-scoped (networking.k8s.io
// v1): the list URL and the openObject ref carry NO namespace.
const KIND = 'ingressclass'
const LIST_ROUTE = '/network/ingress-class'

type IngressClassRow = {
  name: string
  controller: string
  created: string
}

const toRow = (item: IngressClassItem): IngressClassRow => ({
  name: item.metadata?.name ?? '',
  // "—" when absent (certainty rule: never guess).
  controller: item.spec?.controller ?? '—',
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

/**
 * 4.1 `network/ingress-class.html.j2` parity: cluster-scoped IngressClasses
 * (Name / Controller / Created). The card title is EXACTLY "IngressClass
 * List": 4.1's title verbatim (the e2e smoke contract). ADR-0040: the name
 * cell is a button (not a Link) — openObject writes the ref and navigates
 * to the clean route; the URL never carries object identity (R1).
 */
const IngressClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<IngressClassRow[]>({
    queryKey: ['ingressclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IngressClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ingressclasses`,
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
          <CBreadcrumbItem active>IngressClass List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">IngressClass List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading ingress classes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading ingress classes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No ingress classes found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="Controller" data="controller" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default IngressClassView
