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
import type { LimitRangeItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

type LimitRangeRow = {
  name: string
  namespace: string
  created: string
}

const toRow = (item: LimitRangeItem, namespace: string): LimitRangeRow => ({
  name: item.metadata?.name ?? '',
  namespace: item.metadata?.namespace ?? namespace,
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

/**
 * 4.1 `other-resources/limit_range.html.j2`: LimitRanges in the
 * header-selected namespace (the Secret/NetworkPolicy pattern for
 * namespaced kinds — the namespace comes from the 5.0 cluster store, not
 * 4.1's per-page `ns_select` form). A name opens the limit range data
 * page and is the SOLE producer of its `?name=`/`?namespace=` query
 * strings. The columns keep 4.1's Name / Namespace / Created set (the
 * limits table lives on the data page). The card title is EXACTLY "Limit
 * Ranges": the e2e smoke (ui-smoke.spec.ts) asserts that string with
 * exact: true. Placement under Other Resources is a ratified deviation
 * (ADR-0022, 2026-10-27): 4.1's API already lived in other-resources.
 */
const LimitRangeView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'

  const query = useQuery<LimitRangeRow[]>({
    queryKey: ['limitranges', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<LimitRangeItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/limitranges?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  const nameLink = (name: string) =>
    name ? (
      <Link
        to={`/other-resource/limit-range/data?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`}
      >
        {name}
      </Link>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem active>Limit Ranges</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Limit Ranges</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading limit ranges...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading limit ranges: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No limit ranges found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data="name">
              {nameLink}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default LimitRangeView
