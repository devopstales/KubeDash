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
import type { VolumeSnapshotClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// The kind is cluster-scoped (no namespace): the list URL and the data open
// carry no namespace param. The route follows the 4.1 storage grouping
// (ADR-0022 placement).
const KIND = 'snapshotclass'
const LIST_ROUTE = '/storage/snapshot-class'

// The Default column is the snapshot.storage.kubernetes.io/is-default-class
// annotation value (4.1's template iterated the annotations looking for
// this exact key). "—" when absent (certainty rule: never guess).
const IS_DEFAULT = 'snapshot.storage.kubernetes.io/is-default-class'

type SnapshotClassRow = {
  name: string
  isDefault: string
  deletionPolicy: string
  driver: string
  created: string
}

const toRow = (item: VolumeSnapshotClassItem): SnapshotClassRow => ({
  name: item.metadata?.name ?? '',
  isDefault: item.metadata?.annotations?.[IS_DEFAULT] ?? '—',
  deletionPolicy: item.deletionPolicy ?? '—',
  driver: item.driver ?? '—',
  created: formatTimestamp(item.metadata?.creationTimestamp),
})

/**
 * 4.1 `storage` nav leaf "SnapshotClass": cluster-scoped
 * VolumeSnapshotClasses (the kind has no namespace: the list URL and the
 * data open carry none). A name opens the snapshot class data page (Task 3).
 * The card title is EXACTLY "Snapshot Classes List": the e2e smoke
 * (ui-smoke.spec.ts) asserts that string with exact: true. Placement under
 * Storage is a ratified deviation (ADR-0022, 2026-10-27): 4.1's own template
 * lived in storage/. 4.1's hidden-form + session navigation is the ratified
 * deviation (briefing.md): the name cell opens the detail through the
 * ADR-0040 object ref, not a query string. The read is a FULL custom object
 * (the Cilium CRD seam, camelCase) — the page needs deletionPolicy, driver,
 * and the is-default-class annotation.
 */
const SnapshotClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<SnapshotClassRow[]>({
    queryKey: ['volumesnapshotclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<VolumeSnapshotClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/volumesnapshotclasses`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  // ADR-0040: the name cell is a button (not a Link) — openObject writes
  // the ref to sessionStorage and navigates to the clean list route; the
  // URL never carries object identity (R1). Cluster-scoped: no namespace.
  const nameCell = (name: string) =>
    name ? (
      <>
        <button
          type="button"
          className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
          onClick={() => openObject(KIND, name, undefined, LIST_ROUTE, navigate)}
        >
          {name}
        </button>
      </>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem active>Snapshot Classes List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Snapshot Classes List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading snapshot classes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading snapshot classes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No snapshot classes found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="Default" data="isDefault" />
            <Column title="Deletion Policy" data="deletionPolicy" />
            <Column title="Driver" data="driver" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default SnapshotClassView
