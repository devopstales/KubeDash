import React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CBadge,
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import { apiFetch } from '../../lib/api'
import { formatTimestamp } from '../../lib/format'
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { PvcItem, PvcUsage, PvcUsageResponse, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders.
const KIND = 'pvc'
const LIST_ROUTE = '/storage/pvc'

type PvcRow = {
  name: string
  namespace: string
  phase: string
  storageClass: string
  volume: string
  capacity: string
  created: string
}

const toRow = (item: PvcItem, namespace: string): PvcRow => ({
  name: item.metadata?.name ?? '',
  // the row's OWN namespace: the name link must follow the row, not the
  // store (the openObject ref carries it, R8).
  namespace: item.metadata?.namespace ?? namespace,
  phase: item.status?.phase ?? '',
  // 4.1's deep-index KeyError is fixed: an unbound claim has no volume
  // and no capacity — render "—" (certainty rule: never guess).
  storageClass: item.spec?.storage_class_name ?? '—',
  volume: item.spec?.volume_name ?? '—',
  capacity: item.status?.capacity?.storage ?? '—',
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

// 4.1's three-tier Status badge: Bound → success, Terminating → danger,
// everything else non-empty → warning, "—" when absent (certainty rule).
const statusCell = (phase: string) => {
  if (phase === 'Bound') return <CBadge color="success">Bound</CBadge>
  if (phase === 'Terminating') return <CBadge color="danger">Terminating</CBadge>
  if (phase) return <CBadge color="warning">{phase}</CBadge>
  return '—'
}

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). Namespaced: the namespace is carried
// in the ref, not the URL. The bold is driven by the active ref (R9).
const nameCell = (row: PvcRow, selected: string | null, navigate: (p: string) => void) =>
  row.name ? (
    <>
      <button
        type="button"
        className={
          'btn btn-link btn-sm p-0 text-primary text-decoration-underline' +
          (row.name === selected ? ' fw-bold' : '')
        }
        aria-current={row.name === selected ? 'true' : undefined}
        onClick={() => openObject(KIND, row.name, row.namespace, LIST_ROUTE, navigate)}
      >
        {row.name}
      </button>
    </>
  ) : null

/**
 * 4.1 `storage/pvc.html.j2` parity: PersistentVolumeClaims in the
 * header-selected namespace (the ResourceQuota pattern — the namespace
 * comes from the selected-namespace store, `?? 'default'`). A name opens
 * the PVC data page via openObject (ADR-0040): the URL never carries
 * object identity (R1). The card title is EXACTLY "Persistent Volume
 * Claim List": 4.1's title verbatim (the e2e smoke contract). The Usage
 * column is a SECOND parallel fetch on /metrics/pvcs (4.1 computed
 * k8sPVCMetric in the list route and joined in the template; 5.0 exposes
 * it as its own query-only metrics tier, ratified 2026-10-28): joined by
 * PVC name, one decimal + " %"; a PVC absent from the items, a
 * metrics_available/metrics_denied flag, or a failed usage fetch all
 * degrade the column to "—" — the list never fails on the observed tier
 * (ADR-0003 two-tier, client-side).
 */
const PvcView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<PvcRow[]>({
    queryKey: ['pvcs', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PvcItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/persistentvolumeclaims?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  // The Usage column's second fetch: KUBELET stats/summary (not
  // metrics.k8s.io). It is an independent query — its error/loading state
  // NEVER surfaces as a list error (the observed tier degrades, ADR-0003).
  const usageQuery = useQuery<PvcUsageResponse>({
    queryKey: ['pvc-usage', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<PvcUsageResponse>(
        `/api/v1/clusters/${cluster!.id}/metrics/pvcs?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data as PvcUsageResponse
    },
  })

  // The observed tier degrades to unknown, never to a row error (ADR-0003
  // two-tier, client-side): a failed/absent/denied/unavailable usage
  // response means every Usage cell renders "—".
  const usageByPvc = useMemo(() => {
    const map = new Map<string, PvcUsage>()
    if (usageQuery.data?.metrics_available && !usageQuery.data.metrics_denied) {
      for (const u of usageQuery.data.items) map.set(u.name, u)
    }
    return map
  }, [usageQuery.data])

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem active>Persistent Volume Claim List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Persistent Volume Claim List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading persistent volume claims...</div>
        ) : query.error ? (
          <div className="text-danger">
            Error loading persistent volume claims: {query.error.message}
          </div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No persistent volume claims found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Status" data="phase">
              {(phase: string) => statusCell(phase)}
            </Column>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as PvcRow, selected, navigate)}
            </Column>
            <Column title="StorageClass" data="storageClass" />
            <Column title="Volume" data="volume" />
            <Column title="Capacity" data="capacity" />
            <Column title="Usage" data="name">
              {(name: unknown) => {
                const u = usageByPvc.get(String(name))
                return u ? `${u.percentage_used} %` : '—'
              }}
            </Column>
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PvcView
