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
import { apiFetch } from '../../lib/api'
import { openObject } from '../../lib/objectRef'
import type { PersistentVolumeItem, PvcUsage, PvcUsageResponse, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// The kind is cluster-scoped: the PV object ref (the Name cell) carries no
// namespace. The list URL DOES carry ?namespace= — but as a CLAIM filter,
// not a scope (4.1's k8sPersistentVolumeListGet filtered the cluster list
// to the selected namespace via claim_ref): a bound PV shows only for its
// claim's namespace, a free PV (no claim_ref) always shows.
const KIND = 'persistentvolume'
const LIST_ROUTE = '/storage/pv'

type PvRow = {
  name: string
  status: string
  storageClass: string
  volumeClaim: string
  volumeClaimNamespace: string
  capacity: string
}

// The table row = the base row + the observed-tier join. The join lives in
// the ROW, not in a render closure: datatables.net-react binds Column
// render fns only at table initialisation and re-renders cells only when
// the data prop changes, so a closure over usageQuery.data would go stale
// when the usage fetch resolves after the list (cell stuck at "—" until a
// remount). A freshly joined array per render changes the data prop (the
// wrapper's redraw), and the render fn stays a pure function of the row.
type PvTableRow = PvRow & { usage: string | null }

const toRow = (item: PersistentVolumeItem): PvRow => {
  const deleting = Boolean(item.metadata?.deletion_timestamp)
  const phase = item.status?.phase ?? ''
  return {
    name: item.metadata?.name ?? '',
    // 4.1: a deletion timestamp overrides the displayed status.
    status: deleting ? 'Terminating' : phase,
    storageClass: item.spec?.storage_class_name ?? '',
    volumeClaim: item.spec?.claim_ref?.name ?? '',
    volumeClaimNamespace: item.spec?.claim_ref?.namespace ?? '',
    capacity: item.spec?.capacity?.storage ?? '',
  }
}

// 4.1's pv.html.j2 Status badge: Bound → success, Terminating → danger,
// everything else non-empty → warning, "—" when absent (certainty rule).
const statusCell = (phase: string) => {
  if (phase === 'Bound') return <CBadge color="success">Bound</CBadge>
  if (phase === 'Terminating') return <CBadge color="danger">Terminating</CBadge>
  if (phase) return <CBadge color="warning">{phase}</CBadge>
  return '—'
}

/**
 * 4.1 `storage` nav leaf "PV": cluster-scoped Persistent Volumes (the kind
 * has no namespace: the object ref carries none). The list is 4.1's
 * claim-namespace-filtered view (the header-selected namespace; free PVs
 * always appear). A name opens the PV data page (Task 4). The card title
 * is EXACTLY "Persistent Volume List": the e2e smoke (ui-smoke.spec.ts)
 * asserts that string with exact: true. The StorageClass/VolumeClaim cells
 * are ADR-0040 object refs (cross-kind opens; the claim ref carries the
 * claim's own namespace, R8). The Usage column is a 5.0 addition (4.1's PV
 * view had no usage): the PVC list's observed tier — a second parallel
 * fetch on /metrics/pvcs joined by claim name (the claim-ns filter means
 * every bound PV shown is bound in the selected namespace); free PVs and
 * every ADR-0003 degrade render "—". Placement under Storage is a
 * ratified deviation (ADR-0022, 4.1's own template lived in storage/);
 * 4.1's hidden-form + session navigation is the ratified deviation
 * (briefing.md).
 */
const PvView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()

  const query = useQuery<PvRow[]>({
    queryKey: ['persistentvolumes', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PersistentVolumeItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/persistentvolumes?namespace=${encodeURIComponent(
          namespace,
        )}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  // The Usage column's second fetch: the SAME observed tier as the PVC
  // list — KUBELET stats/summary via /metrics/pvcs (not metrics.k8s.io).
  // The list's claim-namespace filter means every bound PV shown here is
  // bound to a claim IN the selected namespace, so the PVC usage map
  // answers the join (by claim name). Same query key as PvcView: the
  // cache is shared, so navigating pvc → pv reuses the scan. Its
  // error/loading state NEVER surfaces as a list error (ADR-0003).
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
  // response means every Usage cell renders "—". The usage is joined into
  // the rows on every render (the Nodes.tsx pattern); the fresh array per
  // render is what changes the data prop and triggers the wrapper's
  // redraw (see PvTableRow).
  const usageByPvc = new Map<string, PvcUsage>(
    usageQuery.data?.metrics_available && !usageQuery.data.metrics_denied
      ? usageQuery.data.items.map((u) => [u.name, u])
      : [],
  )
  const rows: PvTableRow[] = (query.data ?? []).map((row) => {
    const u = row.volumeClaim ? usageByPvc.get(row.volumeClaim) : undefined
    return { ...row, usage: u ? `${u.percentage_used} %` : null }
  })

  // ADR-0040: the cells are buttons (not Links) — openObject writes the
  // ref to sessionStorage and navigates to the target list route; the URL
  // never carries object identity (R1). The Name cell is cluster-scoped
  // (no namespace); the cross-kind cells open on the target kind's route.
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

  const storageClassCell = (name: string) =>
    name ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() =>
          openObject('storageclass', name, undefined, '/storage/storage-class', navigate)
        }
      >
        {name}
      </button>
    ) : (
      '—'
    )

  const volumeClaimCell = (row: PvRow) =>
    row.volumeClaim ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() =>
          openObject(
            // The target route's registry kind (App.tsx: ObjectRoute
            // kind="pvc") — ObjectRoute matches ref.kind === kind verbatim.
            'pvc',
            row.volumeClaim,
            row.volumeClaimNamespace,
            '/storage/pvc',
            navigate,
          )
        }
      >
        {row.volumeClaim}
      </button>
    ) : (
      '—'
    )

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem active>Persistent Volume List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Persistent Volume List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading persistent volumes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading persistent volumes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No persistent volumes found</div>
        ) : (
          <KubeDataTable data={rows}>
            <Column title="Status" data="status">
              {(status: unknown) => statusCell(status as string)}
            </Column>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="StorageClass" data="storageClass">
              {(sc: unknown) => storageClassCell(sc as string)}
            </Column>
            {/* data={null}: the render fn gets the whole row (the
                datatables.net-react contract) — the claim link must carry
                the claim's OWN namespace, not a single column. */}
            <Column title="VolumeClaim" data={null}>
              {(row: unknown) => volumeClaimCell(row as PvRow)}
            </Column>
            <Column title="Capacity" data="capacity">
              {(capacity: unknown) => (capacity ? (capacity as string) : '—')}
            </Column>
            {/* The join is in the row (PvTableRow.usage): only bound PVs
                have a claim to join, so free PVs carry usage: null and
                render "—", same as the absent-tier. */}
            <Column title="Usage" data="usage">
              {(usage: unknown) => (usage ? usage as string : '—')}
            </Column>
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PvView
