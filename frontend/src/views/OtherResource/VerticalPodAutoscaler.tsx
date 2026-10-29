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
import { formatTimestamp } from '../../lib/format'
import type { ResourceList, VerticalPodAutoscalerItem } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

type VpaRow = {
  name: string
  namespace: string
  targetKind: string
  targetName: string
  updateMode: string
  minMemory: string
  maxMemory: string
  created: string
}

// 4.1's Min/Max Memory take the LAST container in
// spec.resourcePolicy.containerPolicies that defines the key (the Jinja
// `{% set mem_min = ... %}` overwrite). "N/A" is 4.1's literal for the
// absent value (certainty rule: never guess, never crash the row).
const containerMem = (item: VerticalPodAutoscalerItem, key: 'minAllowed' | 'maxAllowed'): string => {
  let value = 'N/A'
  for (const cp of item.spec?.resourcePolicy?.containerPolicies ?? []) {
    const v = cp?.[key]?.memory
    if (v != null) value = String(v)
  }
  return value
}

const toRow = (item: VerticalPodAutoscalerItem, namespace: string): VpaRow => ({
  name: item.metadata?.name ?? '',
  namespace: item.metadata?.namespace ?? namespace,
  targetKind: item.spec?.targetRef?.kind ?? 'N/A',
  // 4.1 linked Target Name to /workload/<kind-lower>s; 5.0 has no
  // workload-page destination yet, so it is plain text (the full
  // targetRef is in the data page's JSON block).
  targetName: item.spec?.targetRef?.name ?? 'N/A',
  updateMode: item.spec?.updatePolicy?.updateMode ?? 'N/A',
  minMemory: containerMem(item, 'minAllowed'),
  maxMemory: containerMem(item, 'maxAllowed'),
  created: formatTimestamp(item.metadata?.creationTimestamp),
})

const nameLink = (row: VpaRow) =>
  row.name ? (
    <Link
      to={`/other-resource/vertical-pod-autoscaler/data?name=${encodeURIComponent(row.name)}&namespace=${encodeURIComponent(
        row.namespace,
      )}`}
    >
      {row.name}
    </Link>
  ) : null

/**
 * 4.1 `other-resources/vpa.html.j2` port: VerticalPodAutoscalers in the
 * header-selected namespace. The kind is a NAMESPACED CRD
 * (verticalpodautoscalers.autoscaling.k8s.io) read as a FULL custom object
 * (spec + status intact, camelCase — the Cilium precedent; the CRD's own
 * served version is the authority, CRD-absent degrades to the empty state
 * below). A name opens the data page with `?name=&namespace=` query params
 * (the 4.1 hidden-form POST is dropped); this view is the sole producer of
 * those query strings (the row's OWN namespace — an all-namespaces list
 * would carry mixed namespaces). The card title is EXACTLY "Vertical Pod
 * Autoscaler List": the e2e smoke asserts that string with exact: true.
 * Placement under Other Resources is a ratified deviation (ADR-0022).
 */
const VerticalPodAutoscalerView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'

  const query = useQuery<VpaRow[]>({
    queryKey: ['verticalpodautoscalers', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<VerticalPodAutoscalerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/verticalpodautoscalers?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem active>Vertical Pod Autoscaler List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Vertical Pod Autoscaler List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading vertical pod autoscalers...</div>
        ) : query.error ? (
          <div className="text-danger">
            Error loading vertical pod autoscalers: {query.error.message}
          </div>
        ) : (query.data ?? []).length === 0 ? (
          // Also the CRD-absent state (operator not installed): the API
          // returns [] in both cases and the page does not distinguish.
          <div className="text-center text-muted">No vertical pod autoscalers found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: VpaRow) => nameLink(row)}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Target Kind" data="targetKind" />
            <Column title="Target Name" data="targetName" />
            <Column title="Update Mode" data="updateMode" />
            <Column title="Min Memory" data="minMemory" />
            <Column title="Max Memory" data="maxMemory" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default VerticalPodAutoscalerView
