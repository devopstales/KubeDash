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
import type { CiliumPolicyItem, NetworkPolicyItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kind is the policy's API kind (NetworkPolicy,
// CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy) — the kind the detail
// read needs to map to the right resource plural (policyUrl). The clusterwide
// kind is cluster-scoped (namespace undefined).
const LIST_ROUTE = '/security/network-policy'

type PolicyRow = {
  name: string
  kind: string
  namespace: string
  policyTypes: string
  ingress: number
  egress: number
  created: string
}

/**
 * Projects a vanilla (kubernetes `to_dict`, snake_case) or Cilium (full CRD,
 * camelCase) policy into one row shape. The Cilium CRDs have no
 * `policy_types`: "—" (certainty rule: never guess).
 */
type AnyPolicyItem = NetworkPolicyItem | CiliumPolicyItem
const toRow = (item: AnyPolicyItem, kind: string, namespace: string): PolicyRow => ({
  name: item.metadata?.name ?? '',
  kind,
  namespace,
  policyTypes: (item as NetworkPolicyItem).spec?.policy_types?.join(', ') ?? '—',
  ingress: item.spec?.ingress?.length ?? 0,
  egress: item.spec?.egress?.length ?? 0,
  created: formatTimestamp(item.metadata?.creation_timestamp),
})

// ADR-0040: the name cell is a button (not a Link) — openObject writes the
// ref (kind = the API kind, so the detail read maps to the right resource
// plural) and navigates to the clean list route; the URL never carries object
// identity (R1). The clusterwide kind is cluster-scoped (namespace undefined).
const nameCell = (row: PolicyRow, navigate: (path: string) => void) =>
  row.name ? (
    <>
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() =>
          openObject(
            row.kind,
            row.name,
            row.kind === 'CiliumClusterwideNetworkPolicy' ? undefined : row.namespace,
            LIST_ROUTE,
            navigate,
          )
        }
      >
        {row.name}
      </button>
    </>
  ) : null

/**
 * 4.1 `security/network-policy.html.j2`: NetworkPolicies in the
 * header-selected namespace, plus a Cilium section (CiliumNetworkPolicy +
 * CiliumClusterwideNetworkPolicy) appended when the cluster has any —
 * 4.1 appends clusterwide to every namespace view. A name opens the policy
 * data page (Task 4). The card title is EXACTLY "Network Policies": the e2e
 * smoke (ui-smoke.spec.ts) asserts that string with exact: true.
 */
const NetworkPolicyView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()

  const vanillaQuery = useQuery<PolicyRow[]>({
    queryKey: ['network-policies', cluster?.id, namespace, 'networkpolicies'],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<NetworkPolicyItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/networkpolicies?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, 'NetworkPolicy', namespace))
    },
  })

  const ciliumQuery = useQuery<PolicyRow[]>({
    queryKey: ['network-policies', cluster?.id, namespace, 'ciliumnetworkpolicies'],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<CiliumPolicyItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ciliumnetworkpolicies?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, 'CiliumNetworkPolicy', namespace))
    },
  })

  const clusterwideQuery = useQuery<PolicyRow[]>({
    queryKey: ['network-policies', cluster?.id, namespace, 'ciliumclusterwidenetworkpolicies'],
    enabled: cluster != null,
    queryFn: async () => {
      // Cluster-scoped kind: the list URL carries no namespace param.
      const r = await apiFetch<ResourceList<CiliumPolicyItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ciliumclusterwidenetworkpolicies`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => toRow(item, 'CiliumClusterwideNetworkPolicy', ''))
    },
  })

  const ciliumRows = [...(ciliumQuery.data ?? []), ...(clusterwideQuery.data ?? [])]
  // The section is visible when there are rows OR a query errored: an error
  // with the sibling query empty (no rows) must still surface, not vanish
  // behind an empty-section condition.
  const ciliumError = ciliumQuery.error ?? clusterwideQuery.error ?? null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Security</CBreadcrumbItem>
          <CBreadcrumbItem active>Network Policies</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Network Policies</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : (
          <>
            {vanillaQuery.isLoading ? (
              <div>Loading network policies...</div>
            ) : vanillaQuery.error ? (
              <div className="text-danger">
                Error loading network policies: {vanillaQuery.error.message}
              </div>
            ) : (vanillaQuery.data ?? []).length === 0 ? (
              <div className="text-center text-muted">No network policies found</div>
            ) : (
              <KubeDataTable data={vanillaQuery.data ?? []}>
                <Column title="Name" data={null}>
                  {(row: PolicyRow) => nameCell(row, navigate)}
                </Column>
                <Column title="Policy Types" data="policyTypes" />
                <Column title="Ingress" data="ingress" />
                <Column title="Egress" data="egress" />
                <Column title="Created" data="created" />
              </KubeDataTable>
            )}
            {(ciliumRows.length > 0 || ciliumError) && (
              <CCard className="shadow mb-0">
                <CCardHeader className="py-3">
                  <CCardTitle className="m-0 fw-bold text-primary fs-6">Cilium Policies</CCardTitle>
                </CCardHeader>
                <CCardBody>
                  {ciliumError ? (
                    <div className="text-danger">
                      Error loading Cilium policies: {ciliumError.message}
                    </div>
                  ) : (
                    <KubeDataTable data={ciliumRows}>
                      <Column title="Name" data={null}>
                        {(row: PolicyRow) => nameCell(row, navigate)}
                      </Column>
                      <Column title="Policy Types" data="policyTypes" />
                      <Column title="Ingress" data="ingress" />
                      <Column title="Egress" data="egress" />
                      <Column title="Created" data="created" />
                    </KubeDataTable>
                  )}
                </CCardBody>
              </CCard>
            )}
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default NetworkPolicyView
