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
import { formatTimestamp } from '../../lib/format'
import type { DeploymentItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind (singular API resource name) and the clean
// list route this view renders (the pods-deployments-views change).
const KIND = 'deployment'
const LIST_ROUTE = '/workload/deployments'

type DeploymentRow = {
  name: string
  namespace: string
  status: string
  created: string
}

// 4.1's Status cell: `<desired>/<ready>` — status.replicas /
// status.ready_replicas, each defaulting to 0 (briefing R7).
const toRow = (item: DeploymentItem, namespace: string): DeploymentRow => ({
  name: item.metadata?.name ?? '',
  // the row's OWN namespace: an all-namespaces list would carry mixed
  // namespaces, and the name link must follow the row, not the store.
  namespace: item.metadata?.namespace ?? namespace,
  status: `${item.status?.replicas ?? 0}/${item.status?.ready_replicas ?? 0}`,
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref to sessionStorage and navigates to the clean list route; the URL
// never carries object identity (R1). The bold is driven by the active ref
// (R9).
const nameCell = (row: DeploymentRow, selected: string | null, navigate: (p: string) => void) =>
  row.name ? (
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
  ) : null

/**
 * 4.1 `workload/deployment.html.j2` parity: Deployments in the
 * header-selected namespace (the Secret pattern — the namespace comes from
 * the selected-namespace store, `?? 'default'`; 4.1's
 * `session['ns_select']` hidden form is the ratified ADR-0040 objectRef
 * delta, briefing.md). A name opens the data page via openObject (ADR-0040):
 * the URL never carries object identity (R1). The card title is EXACTLY
 * "Deployments List": the e2e smoke asserts that string with exact: true.
 * 4.1 deviations (recorded in the change's adr.md): 4.1's delete action is
 * commented out (not ported); the Status cell is 4.1's `<desired>/<ready>`
 * (status.replicas / status.ready_replicas, each defaulting to 0).
 */
const DeploymentsWorkloadView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()
  const selected =
    active !== null && active.kind === KIND && active.namespace === namespace
      ? active.name
      : null

  const query = useQuery<DeploymentRow[]>({
    queryKey: ['workload-deployments', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<DeploymentItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/deployments?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, namespace))
    },
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Workloads</CBreadcrumbItem>
          <CBreadcrumbItem active>Deployments List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Deployments List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading deployments...</div>
        ) : query.error ? (
          <div className="text-danger">
            Error loading deployments: {query.error.message}
          </div>
        ) : (query.data ?? []).length === 0 ? (
          <div className="text-center text-muted">No deployments found</div>
        ) : (
          <KubeDataTable data={query.data ?? []}>
            <Column title="Name" data={null}>
              {(row: unknown) => nameCell(row as DeploymentRow, selected, navigate)}
            </Column>
            <Column title="Namespace" data="namespace" />
            <Column title="Status" data="status" />
            <Column title="Created" data="created" />
          </KubeDataTable>
        )}
      </CCardBody>
    </CCard>
  )
}

export default DeploymentsWorkloadView
