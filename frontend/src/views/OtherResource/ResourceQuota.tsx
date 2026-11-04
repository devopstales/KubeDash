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
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { ResourceList, ResourceQuotaItem } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders (TICKET-06).
const KIND = 'resourcequota'
const LIST_ROUTE = '/other-resource/resource-quota'

type QuotaRow = {
  name: string
  namespace: string
  requests: string[]
  limits: string[]
  created: string
}

// 4.1's four dimensions, 4.1's order. A key missing from status.used or
// status.hard renders "—" (certainty rule: 4.1 would KeyError the template;
// 5.0 renders certainty, never guesses).
const cell = (item: ResourceQuotaItem, key: string): string => {
  const used = item.status?.used?.[key] ?? '—'
  const hard = item.status?.hard?.[key] ?? '—'
  return `${key}: ${used} / ${hard}`
}

const toRow = (item: ResourceQuotaItem, namespace: string): QuotaRow => ({
  name: item.metadata?.name ?? '',
  // the row's OWN namespace: an all-namespaces list would carry mixed
  // namespaces, and the name link must follow the row, not the store.
  namespace: item.metadata?.namespace ?? namespace,
  requests: [cell(item, 'requests.cpu'), cell(item, 'requests.memory')],
  limits: [cell(item, 'limits.cpu'), cell(item, 'limits.memory')],
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

// The Requests/Limits cells: one line per dimension (4.1's badge pairs),
// joined by <br/> in the table cell.
const dimensionCell = (cells: string[]) =>
  cells.map((c, i) => (
    <React.Fragment key={i}>
      {c}
      {i < cells.length - 1 && <br />}
    </React.Fragment>
  ))

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). Namespaced: the namespace is carried
// in the ref, not the URL. The bold is driven by the active ref (R9).
const nameCell = (row: QuotaRow, selected: string | null, navigate: (p: string) => void) =>
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
 * 4.1 `other-resources/resource-quota.html.j2`: ResourceQuotas in the
 * header-selected namespace (the Secret pattern — the namespace comes
 * from the selected-namespace store, `?? 'default'`; 4.1's
 * `session['ns_select']` hidden form is the ratified ADR-0040 objectRef
 * delta, briefing.md). A name opens the quota data page via openObject
 * (ADR-0040): the URL never carries object identity (R1). The card title
 * is EXACTLY "Resource Quota List": the e2e smoke (ui-smoke.spec.ts)
 * asserts that string with exact: true. Request/Limit cells show the four
 * 4.1 dimensions as `used / hard`; a missing key renders "—" (certainty
 * rule).
 */
const ResourceQuotaView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<QuotaRow[]>({
    queryKey: ['resourcequotas', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ResourceQuotaItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/resourcequotas?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem active>Resource Quota List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Resource Quota List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading resource quotas...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading resource quotas: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No resource quotas found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as QuotaRow, selected, navigate)}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Requests" data="requests">
              {(cells: string[]) => dimensionCell(cells)}
            </Column>
            <Column title="Limits" data="limits">
              {(cells: string[]) => dimensionCell(cells)}
            </Column>
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ResourceQuotaView
