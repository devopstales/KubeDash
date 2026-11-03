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
import type { PriorityClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import ShareObjectButton from '../../components/ShareObjectButton'
import TopMenu from '../../components/TopMenu'

// The kind is cluster-scoped (no namespace); this route is the template kind
// for ADR-0040 session object navigation (TICKET-02).
const KIND = 'priorityclass'
const LIST_ROUTE = '/other-resource/priorityclass'

type PriorityClassRow = {
  name: string
  value: string
  preemptionPolicy: string
  globalDefault: string
  description: string
  created: string
}

const toRow = (item: PriorityClassItem): PriorityClassRow => ({
  name: item.metadata?.name ?? '',
  value: String(item.value ?? '—'),
  preemptionPolicy: item.preemption_policy ?? '—',
  globalDefault: item.global_default == null ? '—' : String(item.global_default),
  description: item.description || '—',
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

/**
 * 4.1 `other-resources/priorityclass.html.j2`: PriorityClasses, cluster-scoped
 * (the kind has no namespace: the list URL and the data link carry none).
 * A name opens the priority class data page (Task 3). The card title is
 * EXACTLY "Priority Classes": the e2e smoke (ui-smoke.spec.ts) asserts that
 * string with exact: true. Placement under Other Resources is a ratified
 * deviation (ADR-0022, 2026-10-27): 4.1's API already lived in
 * other-resources.
 */
const PriorityClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<PriorityClassRow[]>({
    queryKey: ['priorityclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PriorityClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/priorityclasses`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map(toRow)
    },
  })

  // ADR-0040: the name cell is a button (not a Link) — openObject writes the
  // ref to sessionStorage and navigates to the clean list route; the URL
  // never carries object identity (R1). Cluster-scoped: no namespace.
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
          <CBreadcrumbItem active>Priority Classes</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Priority Classes</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading priority classes...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading priority classes: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No priority classes found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {nameCell}
            </Column>
            <Column title="Value" data="value" />
            <Column title="Preemption Policy" data="preemptionPolicy" />
            <Column title="Global Default" data="globalDefault" />
            <Column title="Description" data="description" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PriorityClassView
