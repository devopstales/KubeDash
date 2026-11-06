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
import { openObject } from '../../lib/objectRef'
import type { IngressItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders. Ingress is namespaced (networking.k8s.io v1):
// the selected namespace rides the list URL AND the openObject ref (R8) —
// the Pvc pattern (namespace ?? 'default').
const KIND = 'ingress'
const LIST_ROUTE = '/network/ingress'

type IngressRow = {
  name: string
  ingressClass: string
  hostname: string
}

const toRow = (item: IngressItem): IngressRow => {
  // 4.1 `network/ingress.html.j2` parity: Name / IngressClass / Hostname.
  const hosts = (item.spec?.rules ?? []).map((r) => r.host).filter((h): h is string => Boolean(h))
  return {
    name: item.metadata?.name ?? '',
    // "—" when absent (certainty rule: never guess).
    ingressClass: item.spec?.ingress_class_name ?? '—',
    // spec.rules[].host joined ", " — "—" when no rule carries a host.
    hostname: hosts.length > 0 ? hosts.join(', ') : '—',
  }
}

/**
 * 4.1 `network/ingress.html.j2` parity: one namespace's Ingresses
 * (Name / IngressClass / Hostname). The card title is EXACTLY "Ingress
 * List" (the spec's pinned title — 4.1's "Ingress Resources" is NOT
 * replicated). ADR-0040: the name cell is a button (not a Link) —
 * openObject writes the ref (name + namespace) and navigates to the clean
 * route; the URL never carries object identity (R1).
 */
const IngressView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()

  const query = useQuery<IngressRow[]>({
    queryKey: ['ingresses', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IngressItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ingresses?namespace=${encodeURIComponent(namespace)}`,
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
        onClick={() => openObject(KIND, name, namespace, LIST_ROUTE, navigate)}
      >
        {name}
      </button>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem active>Ingress List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Ingress List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading ingresses...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading ingresses: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No ingresses found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="IngressClass" data="ingressClass" />
            <Column title="Hostname" data="hostname" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default IngressView
