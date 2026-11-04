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
import type { StorageClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// The kind is cluster-scoped (no namespace): the list URL and the data open
// carry no namespace param. The route follows the 4.1 storage grouping
// (ADR-0022 placement).
const KIND = 'storageclass'
const LIST_ROUTE = '/storage/storage-class'

// The Default column is the storageclass.kubernetes.io/is-default-class
// annotation value (4.1's template iterated the annotations looking for
// this exact key). "—" when absent (certainty rule: never guess).
const IS_DEFAULT = 'storageclass.kubernetes.io/is-default-class'

type StorageClassRow = {
  name: string
  isDefault: string
  reclaimPolicy: string
  volumeBindingMode: string
  created: string
}

const toRow = (item: StorageClassItem): StorageClassRow => ({
  name: item.metadata?.name ?? '',
  isDefault: item.metadata?.annotations?.[IS_DEFAULT] ?? '—',
  reclaimPolicy: item.reclaim_policy ?? '—',
  volumeBindingMode: item.volume_binding_mode ?? '—',
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

/**
 * 4.1 `storage` nav leaf "StorageClass": cluster-scoped StorageClasses
 * (the kind has no namespace: the list URL and the data open carry none).
 * A name opens the storage class data page (Task 3). The card title is
 * EXACTLY "Storage Classes List": the e2e smoke (ui-smoke.spec.ts) asserts
 * that string with exact: true. Placement under Storage is a ratified
 * deviation (ADR-0022, 2026-10-27): 4.1's own template lived in
 * storage/. 4.1's hidden-form + session navigation is the ratified
 * deviation (briefing.md): the name cell opens the detail through the
 * ADR-0040 object ref, not a query string.
 */
const StorageClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<StorageClassRow[]>({
    queryKey: ['storageclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<StorageClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/storageclasses`,
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
          <CBreadcrumbItem active>Storage Classes List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Storage Classes List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading storage classes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading storage classes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No storage classes found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="Default" data="isDefault" />
            <Column title="Reclaim Policy" data="reclaimPolicy" />
            <Column title="Volume Binding Mode" data="volumeBindingMode" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default StorageClassView
