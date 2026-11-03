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
import { getActiveRef, openObject } from '../../lib/objectRef'
import type { PodDisruptionBudgetItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import ShareObjectButton from '../../components/ShareObjectButton'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (the API resource name) and the clean list
// route this view renders (TICKET-06).
const KIND = 'poddisruptionbudget'
const LIST_ROUTE = '/other-resource/pod-disruption-budget'

type PdbRow = {
  name: string
  namespace: string
  minAvailable: string
  maxUnavailable: string
  allowedDisruptions: string
}

// The k8s API enforces exactly one of min_available / max_unavailable;
// the absent one renders "—" (certainty rule: 4.1 rendered blank). A
// fresh PDB has no status at all — 4.1's Jinja would UndefinedError on
// `pdp.status.disruptions_allowed`; 5.0 renders "—", never guesses.
const toRow = (item: PodDisruptionBudgetItem, namespace: string): PdbRow => ({
  name: item.metadata?.name ?? '',
  // the row's OWN namespace: an all-namespaces list would carry mixed
  // namespaces, and the name link must follow the row, not the store.
  namespace: item.metadata?.namespace ?? namespace,
  minAvailable: item.spec?.min_available != null ? String(item.spec.min_available) : '—',
  maxUnavailable: item.spec?.max_unavailable != null ? String(item.spec.max_unavailable) : '—',
  allowedDisruptions:
    item.status?.disruptions_allowed != null ? String(item.status.disruptions_allowed) : '—',
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). Namespaced: the namespace is carried
// in the ref, not the URL. The bold is driven by the active ref (R9).
const nameCell = (row: PdbRow, selected: string | null, navigate: (p: string) => void) =>
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
      </button>{' '}
      <ShareObjectButton
        kind={KIND}
        name={row.name}
        namespace={row.namespace}
        listRoute={LIST_ROUTE}
      />
    </>
  ) : null

/**
 * 4.1 `other-resources/pod-disruption-budget.html.j2` parity: PodDisruptionBudgets
 * in the header-selected namespace (the Secret pattern — the namespace
 * comes from the selected-namespace store, `?? 'default'`; 4.1's
 * `session['ns_select']` hidden form is the ratified ADR-0040 objectRef
 * delta, briefing.md). A name opens the data page via openObject
 * (ADR-0040): the URL never carries object identity (R1). The card title
 * is EXACTLY "Pod Disruption Budget List": the e2e smoke asserts that
 * string with exact: true. 4.1 deviations (recorded in the change's
 * adr.md): the absent min/max and a missing status render "—" (4.1's
 * blank / UndefinedError).
 */
const PodDisruptionBudgetView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<PdbRow[]>({
    queryKey: ['poddisruptionbudgets', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PodDisruptionBudgetItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/poddisruptionbudgets?namespace=${encodeURIComponent(namespace)}`,
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
          <CBreadcrumbItem active>Pod Disruption Budget List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Pod Disruption Budget List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading pod disruption budgets...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading pod disruption budgets: {query.error.message}</div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No pod disruption budgets found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as PdbRow, selected, navigate)}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Min Available" data="minAvailable" />
            <Column title="Max Unavailable" data="maxUnavailable" />
            <Column title="Allowed Disruptions" data="allowedDisruptions" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PodDisruptionBudgetView
