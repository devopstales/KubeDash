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
import { apiFetch } from '../../lib/api'
import { openObject } from '../../lib/objectRef'
import type { PersistentVolumeItem, ResourceList } from '../../lib/types'
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
 * claim's own namespace, R8). Placement under Storage is a ratified
 * deviation (ADR-0022, 4.1's own template lived in storage/); 4.1's
 * hidden-form + session navigation is the ratified deviation (briefing.md).
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
            'persistentvolumeclaim',
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
          <KubeDataTable data={query.data ?? []}>
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
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PvView
