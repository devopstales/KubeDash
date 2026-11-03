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
import type { RuntimeClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import ShareObjectButton from '../../components/ShareObjectButton'
import TopMenu from '../../components/TopMenu'

// The kind is cluster-scoped (no namespace); the route follows the
// priorityclass template kind (TICKET-02), migrated in TICKET-06.
const KIND = 'runtimeclass'
const LIST_ROUTE = '/other-resource/runtimeclass'

type RuntimeClassRow = {
  name: string
  handler: string
  overwriteNodeSelNoToleration: string
  podLevelOverhead: string
  created: string
}

const toRow = (item: RuntimeClassItem): RuntimeClassRow => ({
  name: item.metadata?.name ?? '',
  handler: item.handler ?? '—',
  overwriteNodeSelNoToleration:
    item.overwrite_node_sel_no_toleration == null
      ? '—'
      : String(item.overwrite_node_sel_no_toleration),
  podLevelOverhead: item.pod_level_overhead
    ? [item.pod_level_overhead.cpu, item.pod_level_overhead.memory]
        .filter(Boolean)
        .join(' / ')
    : '—',
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

/**
 * 4.1 `other-resources` nav leaf "Runtime Class": cluster-scoped RuntimeClasses
 * (the kind has no namespace: the list URL and the data link carry none).
 * A name opens the runtime class data page (Task 3). The card title is
 * EXACTLY "Runtime Classes": the e2e smoke (ui-smoke.spec.ts) asserts that
 * string with exact: true. Placement under Other Resources is a ratified
 * deviation (ADR-0022, 2026-10-27): 4.1's API already lived in
 * other-resources. 4.1 had NO runtimeclass template (dead nav link) — this
 * list+data shape follows the ratified 5.0 PriorityClass precedent, not a
 * 4.1 template (briefing.md ratified deviation 1).
 */
const RuntimeClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<RuntimeClassRow[]>({
    queryKey: ['runtimeclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<RuntimeClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/runtimeclasses`,
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
        </button>{' '}
        <ShareObjectButton kind={KIND} name={name} listRoute={LIST_ROUTE} />
      </>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem active>Runtime Classes</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Runtime Classes</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading runtime classes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading runtime classes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No runtime classes found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {(name: unknown) => nameCell(name as string)}
            </Column>
            <Column title="Handler" data="handler" />
            <Column title="Overwrite Node Sel No Toleration" data="overwriteNodeSelNoToleration" />
            <Column title="Pod Level Overhead" data="podLevelOverhead" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default RuntimeClassView
