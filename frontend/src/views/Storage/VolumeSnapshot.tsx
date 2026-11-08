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
import { formatTimestamp } from '../../lib/format'
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { VolumeSnapshotItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders.
const KIND = 'volumesnapshot'
const LIST_ROUTE = '/storage/volumesnapshot'

type SnapshotRow = {
  name: string
  namespace: string
  usable: string
  snapshotClass: string
  volumeClaim: string
  restoreSize: string
  created: string
}

// The Usable cell is the 4.1 status.readyToUse success/danger badge pair:
// true → "Ready" (success), false → "Not Ready" (danger), absent → "—".
// SnapshotClass / VolumeClaim / Restore Size deep-index the raw custom
// object — 4.1's `spec.source.persistentVolumeClaimName` and
// `spec.volumeSnapshotClassName` KeyError'd (500) on a SourceMode-less
// snapshot; 5.0 renders "—" for absent keys (certainty rule: never guess,
// never crash a row).
const toRow = (item: VolumeSnapshotItem, namespace: string): SnapshotRow => ({
  name: item.metadata?.name ?? '',
  // The list read is namespaced, but the row's own namespace wins when
  // present (the openObject ref must follow the row, not the store).
  namespace: item.metadata?.namespace ?? namespace,
  usable:
    item.status?.readyToUse === undefined
      ? '—'
      : item.status.readyToUse
        ? 'Ready'
        : 'Not Ready',
  snapshotClass: item.spec?.volumeSnapshotClassName ?? '—',
  volumeClaim: item.spec?.source?.persistentVolumeClaimName ?? '—',
  restoreSize: item.status?.restoreSize ?? '—',
  created: formatTimestamp(item.metadata?.creationTimestamp),
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). Namespaced: the namespace is carried
// in the ref, not the URL. The bold is driven by the active ref (R9).
const nameCell = (row: SnapshotRow, selected: string | null, navigate: (p: string) => void) =>
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

// The Usable cell: the 4.1 readyToUse badge (true → success, false →
// danger, absent → plain "—").
const usableCell = (usable: string) =>
  usable === 'Ready' ? (
    <CBadge color="success">Ready</CBadge>
  ) : usable === 'Not Ready' ? (
    <CBadge color="danger">Not Ready</CBadge>
  ) : (
    usable
  )

/**
 * 4.1 `storage` nav leaf "VolumeSnapshot" parity: VolumeSnapshots in the
 * header-selected namespace (the ConfigMap pattern — the namespace comes
 * from the selected-namespace store, `?? 'default'`; a fix for 4.1's
 * hardcoded all-namespaces `list_cluster_custom_object` read, which
 * ignored `session['ns_select']`). A name opens the snapshot data page
 * via openObject (ADR-0040): the URL never carries object identity (R1) —
 * the list view is the sole producer of the data page's identity. The
 * read is a FULL custom object (the Cilium CRD seam, camelCase — an
 * improvement over 4.1's hardcoded `v1`; the CRD's own served version is
 * the authority); CRD absent (snapshot operator not installed) degrades
 * to the first-class empty state (the "No volume snapshots found" copy
 * doubles for the CRD-absent case). The card title is EXACTLY
 * "Volume Snapshot List": 4.1's title verbatim (the e2e smoke contract;
 * the nav label stays "VolumeSnapshot"). Placement under Storage is a
 * ratified deviation (ADR-0022, 2026-10-27): 4.1's own template lived in
 * storage/.
 */
const VolumeSnapshotView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<SnapshotRow[]>({
    queryKey: ['volumesnapshots', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<VolumeSnapshotItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/volumesnapshots?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem active>Volume Snapshot List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Volume Snapshot List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading volume snapshots...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading volume snapshots: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No volume snapshots found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as SnapshotRow, selected, navigate)}
            </Column>
            <Column title="Usable" data="usable">
              {(usable: unknown) => usableCell(usable as string)}
            </Column>
            <Column title="SnapshotClass" data="snapshotClass" />
            <Column title="VolumeClaim" data="volumeClaim" />
            <Column title="Restore Size" data="restoreSize" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default VolumeSnapshotView
