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
import type { PriorityClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

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

  const nameLink = (name: string) =>
    name ? (
      <Link to={`/other-resource/priorityclass/data?name=${encodeURIComponent(name)}`}>
        {name}
      </Link>
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
              {nameLink}
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
