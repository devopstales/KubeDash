import React from 'react'
import { useNavigate } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTabs,
  CTab,
  CTabPanel,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import { formatAge, formatTimestamp } from '../../lib/format'
import { openObject } from '../../lib/objectRef'
import type { GatewayClassItem, IngressClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the ONE clean list route this page renders. 4.1
// `network/ingress-class.html.j2` pattern (2026-11-07 owner decision): the
// page is a CoreUI tabbed surface — IngressClasses + GatewayClasses on the
// SAME route; the detail dispatcher (App.tsx IngressClassRoute) renders the
// ref-matched detail for either kind. Both kinds are cluster-scoped: the
// openObject refs carry NO namespace. The old /network/gateway-class URL
// redirects here (App.tsx).
//
// The gatewayclasses query key carries the 'gateway-api' prefix: the
// converter's post-apply invalidateQueries({ queryKey: ['gateway-api'] })
// (R7/R8, the Ingress detail page) marks this tab stale so applied
// GatewayClasses appear without a manual refresh.
const LIST_ROUTE = '/network/ingress-class'

type Row = Record<string, unknown>

/**
 * 4.1 `network/ingress-class.html.j2` parity, merged (2026-11-07 owner
 * decision): tabs IngressClasses | GatewayClasses (CoreUI CTabs — 4.1's
 * bootstrap tab pattern). The card title stays EXACTLY "IngressClass List"
 * (4.1's title verbatim). CTabPanel keeps both panels mounted, so both
 * fetch on mount. ADR-0040: name cells are buttons (openObject), never
 * Links — the URL stays clean (R1).
 */
const IngressClassView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const ingressClassesQuery = useQuery<Row[]>({
    queryKey: ['ingressclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IngressClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ingressclasses`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        // "—" when absent (certainty rule: never guess).
        controller: item.spec?.controller ?? '—',
        created: formatTimestamp(item.metadata?.creation_timestamp),
      }))
    },
  })

  const gatewayClassesQuery = useQuery<Row[]>({
    queryKey: ['gateway-api', 'gatewayclasses', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<GatewayClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/gatewayclasses`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        // FULL custom object — camelCase (the CRD seam, unlike the core API
        // kinds). "—" when absent (certainty rule: never guess).
        controller: item.spec?.controllerName ?? '—',
        age: formatAge(item.metadata?.creationTimestamp),
      }))
    },
  })

  // One name-cell factory for both tabs: the button's openObject call is
  // the ADR-0040 identity write and navigates to this SAME clean route —
  // the IngressClassRoute dispatcher renders the matching detail.
  const nameButton = (name: unknown, kind: string) =>
    typeof name === 'string' && name ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject(kind, name, undefined, LIST_ROUTE, navigate)}
      >
        {name}
      </button>
    ) : null

  const tabState = (
    query: { isLoading: boolean; error: Error | null; data: Row[] | undefined },
    { loading, empty, errorPrefix }: { loading: string; empty: string; errorPrefix: string },
  ) =>
    query.isLoading ? (
      <div>{loading}</div>
    ) : query.error ? (
      <div className="text-danger">
        {errorPrefix}: {query.error.message}
      </div>
    ) : (query.data ?? []).length === 0 ? (
      <div className="text-center text-muted">{empty}</div>
    ) : null

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem active>IngressClass List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">IngressClass List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : (
          <CTabs defaultActiveItemKey="ingressclasses">
            <CTab itemKey="ingressclasses">IngressClasses</CTab>
            <CTabPanel itemKey="ingressclasses">
              {tabState(ingressClassesQuery, {
                loading: 'Loading ingress classes...',
                empty: 'No ingress classes found',
                errorPrefix: 'Error loading ingress classes',
              }) ?? (
                <KubeDataTable data={ingressClassesQuery.data ?? []}>
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'ingressclass')}
                  </Column>
                  <Column title="Controller" data="controller" />
                  <Column title="Created" data="created" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="gatewayclasses">GatewayClasses</CTab>
            <CTabPanel itemKey="gatewayclasses">
              {tabState(gatewayClassesQuery, {
                loading: 'Loading gateway classes...',
                empty: 'No gateway classes found',
                errorPrefix: 'Error loading gateway classes',
              }) ?? (
                <KubeDataTable data={gatewayClassesQuery.data ?? []}>
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'gatewayclass')}
                  </Column>
                  <Column title="Controller" data="controller" />
                  <Column title="Age" data="age" />
                </KubeDataTable>
              )}
            </CTabPanel>
          </CTabs>
        )}
      </CCardBody>
    </CCard>
  )
}

export default IngressClassView
