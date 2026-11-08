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
import type { HorizontalPodAutoscalerItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (lowercase plural, the API resource name) and
// the clean list route this view renders (TICKET-06).
const KIND = 'horizontalpodautoscaler'
const LIST_ROUTE = '/other-resource/horizontal-pod-autoscaler'

type HpaRow = {
  name: string
  namespace: string
  owner: string
  targets: string
  minReplicas: string
  maxReplicas: string
  replicas: string
}

// 4.1's Targets badge: current/target CPU percent (a legacy autoscaling/v1
// field). The "UNKNOWN" literal is 4.1's exact fallback for an absent
// current (certainty rule: never guess). 4.1's list template swapped the
// Min/Max cells ({{ max_replicas }} under <th>MinReplicas</th>); 5.0
// renders the matching value under each header.
const toRow = (item: HorizontalPodAutoscalerItem, namespace: string): HpaRow => ({
  name: item.metadata?.name ?? '',
  // the row's OWN namespace: an all-namespaces list would carry mixed
  // namespaces, and the name link must follow the row, not the store.
  namespace: item.metadata?.namespace ?? namespace,
  // 4.1 linked Owner to /workload/<kind-lower>s; 5.0 has no
  // workload-page destination yet, so it is plain text (the full
  // scale_target_ref is in the data page's JSON block).
  owner: item.spec?.scale_target_ref?.name ?? '—',
  targets: `${item.status?.current_cpu_utilization_percentage ?? 'UNKNOWN'} / ${
    item.spec?.target_cpu_utilization_percentage ?? '—'
  } %`,
  minReplicas: item.spec?.min_replicas != null ? String(item.spec.min_replicas) : '—',
  maxReplicas: item.spec?.max_replicas != null ? String(item.spec.max_replicas) : '—',
  replicas: item.status?.current_replicas != null ? String(item.status.current_replicas) : '—',
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). Namespaced: the namespace is carried
// in the ref, not the URL. The bold is driven by the active ref (R9).
const nameCell = (row: HpaRow, selected: string | null, navigate: (p: string) => void) =>
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
 * 4.1 `other-resources/hpa.html.j2` parity: HorizontalPodAutoscalers in the
 * header-selected namespace (the Secret pattern — the namespace comes from
 * the selected-namespace store, `?? 'default'`; 4.1's
 * `session['ns_select']` hidden form is the ratified ADR-0040 objectRef
 * delta, briefing.md). A name opens the data page via openObject (ADR-0040):
 * the URL never carries object identity (R1). The card title is EXACTLY
 * "Horizontal Pod Autoscaler List": the e2e smoke asserts that string with
 * exact: true. 4.1 deviations (recorded in the change's adr.md): the
 * Min/Max header-cell swap is CORRECTED (each header shows its matching
 * value); Targets is the legacy v1 CPU field with the `UNKNOWN` literal for
 * an absent current; the Owner link to `/workload/<kind-lower>s` is dropped
 * (plain text — 5.0 has no workload page yet). Placement under Other
 * Resources is a ratified deviation (ADR-0022).
 */
const HorizontalPodAutoscalerView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<HpaRow[]>({
    queryKey: ['horizontalpodautoscalers', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<HorizontalPodAutoscalerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/horizontalpodautoscalers?namespace=${encodeURIComponent(namespace)}`,
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
          <CBreadcrumbItem active>Horizontal Pod Autoscaler List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">
          Horizontal Pod Autoscaler List
        </CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading horizontal pod autoscalers...</div>
        ) : query.error ? (
          <div className="text-danger">
            Error loading horizontal pod autoscalers: {query.error.message}
          </div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No horizontal pod autoscalers found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as HpaRow, selected, navigate)}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Owner" data="owner" />
            <Column title="Targets" data="targets" />
            <Column title="Min Replicas" data="minReplicas" />
            <Column title="Max Replicas" data="maxReplicas" />
            <Column title="Replicas" data="replicas" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default HorizontalPodAutoscalerView
