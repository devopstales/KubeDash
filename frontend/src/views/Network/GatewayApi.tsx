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
import { formatAge } from '../../lib/format'
import { openObject } from '../../lib/objectRef'
import type {
  GatewayClassItem,
  GatewayItem,
  HTTPRouteItem,
  ReferenceGrantItem,
  ResourceList,
} from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: ONE clean route for the four ratified Gateway API kinds — the
// four tabs are the LIST (each a KubeDataTable on the generic resources
// route, the VPA CRD seam: full custom objects, camelCase; CRD-absent →
// [] → the tab's pinned empty state, the VPA absence contract). The
// registry kinds are the lowercase route kinds ('gateway', 'httproute',
// 'referencegrant'); the GatewayClasses tab DEDUPES to the standalone
// GatewayClass view (openObject → /network/gateway-class) — the spec's
// dedupe: one detail surface per class.
//
// The tab query keys share the 'gateway-api' prefix: the converter's
// post-apply invalidateQueries({ queryKey: ['gateway-api'] }) hits ALL
// four tabs so the applied resources appear without a manual refresh.
const LIST_ROUTE = '/network/gateway-api'

type Row = Record<string, unknown>

const listenersText = (spec: GatewayItem['spec']): string => {
  const list = spec?.listeners ?? []
  const parts = list
    .map((l) => [l.name, l.protocol, l.port].filter((x) => x != null && x !== '').join(':'))
    .filter((s) => s !== '')
  return parts.length > 0 ? parts.join(', ') : '—'
}

/**
 * 2026-10-28-ingress-gateway-api-views: the Gateway API page — four CoreUI
 * tabs (GatewayClasses / Gateways / HTTPRoutes / ReferenceGrants). The
 * card title is EXACTLY "Gateway API" (the spec's pinned page title).
 * Namespaced tabs (Gateways / HTTPRoutes) ride the selected namespace
 * (the Pvc pattern: ?? 'default'); the cluster-scoped tabs (GatewayClasses
 * / ReferenceGrants) carry no namespace. ADR-0040: name cells are buttons
 * (openObject), never Links — the URL stays clean (R1).
 */
const GatewayApiView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()

  // Four independent tab queries (CTabPanel keeps all panels mounted, so
  // all four fetch on mount). Query keys share the 'gateway-api' prefix
  // (the converter's invalidation seam).
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
        controller: item.spec?.controllerName ?? '—',
        age: formatAge(item.metadata?.creationTimestamp),
      }))
    },
  })

  const gatewaysQuery = useQuery<Row[]>({
    queryKey: ['gateway-api', 'gateways', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<GatewayItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/gateways?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        gatewayClass: item.spec?.gatewayClassName ?? '—',
        listeners: listenersText(item.spec),
      }))
    },
  })

  const httpRoutesQuery = useQuery<Row[]>({
    queryKey: ['gateway-api', 'httproutes', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<HTTPRouteItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/httproutes?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => {
        const hostnames = (item.spec?.hostnames ?? []).filter((h) => Boolean(h))
        const refs = (item.spec?.parentRefs ?? []).map((p) =>
          p.namespace ? `${p.name ?? '—'}/${p.namespace}` : (p.name ?? '—'),
        )
        return {
          name: item.metadata?.name ?? '',
          hostnames: hostnames.length > 0 ? hostnames.join(', ') : '—',
          parentRefs: refs.length > 0 ? refs.join(', ') : '—',
        }
      })
    },
  })

  const referenceGrantsQuery = useQuery<Row[]>({
    queryKey: ['gateway-api', 'referencegrants', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ReferenceGrantItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/referencegrants`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => {
        const from = (item.spec?.from ?? []).map((f) =>
          [f.group, f.kind].filter(Boolean).join(':'),
        )
        const to = (item.spec?.to ?? []).map((t) => [t.group, t.kind].filter(Boolean).join(':'))
        return {
          name: item.metadata?.name ?? '',
          from: from.length > 0 ? from.join(', ') : '—',
          to: to.length > 0 ? to.join(', ') : '—',
        }
      })
    },
  })

  if (!cluster) {
    return (
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Network</CBreadcrumbItem>
            <CBreadcrumbItem active>Gateway API</CBreadcrumbItem>
          </CBreadcrumb>
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Gateway API</CCardTitle>
        </CCardHeader>
        <CCardBody>
          <div>No cluster selected.</div>
        </CCardBody>
      </CCard>
    )
  }

  // One name-cell factory per tab: the button's openObject call is the
  // ADR-0040 identity write (the ref carries name + the row's namespace
  // for the namespaced kinds; the GatewayClasses tab targets the
  // STANDALONE route — the dedupe).
  const nameButton = (name: unknown, kind: string, listRoute: string, ns: string | undefined) =>
    typeof name === 'string' && name ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject(kind, name, ns, listRoute, navigate)}
      >
        {name}
      </button>
    ) : null

  const tabState = (
    query: { isLoading: boolean; error: Error | null; data: Row[] | undefined },
    {
      loading,
      empty,
      errorPrefix,
    }: { loading: string; empty: string; errorPrefix: string },
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
          <CBreadcrumbItem active>Gateway API</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Gateway API</CCardTitle>
      </CCardHeader>
      <CCardBody>
        <CTabs defaultActiveItemKey="gatewayclasses">
          <CTab itemKey="gatewayclasses">GatewayClasses</CTab>
          <CTabPanel itemKey="gatewayclasses">
            {tabState(gatewayClassesQuery, {
              loading: 'Loading gateway classes...',
              empty: 'No gateway classes found',
              errorPrefix: 'Error loading gateway classes',
            }) ?? (
              <KubeDataTable data={gatewayClassesQuery.data ?? []}>
                <Column title="Name" data="name">
                  {(name: unknown) =>
                    nameButton(name, 'gatewayclass', '/network/gateway-class', undefined)
                  }
                </Column>
                <Column title="Controller" data="controller" />
                <Column title="Age" data="age" />
              </KubeDataTable>
            )}
          </CTabPanel>

          <CTab itemKey="gateways">Gateways</CTab>
          <CTabPanel itemKey="gateways">
            {tabState(gatewaysQuery, {
              loading: 'Loading gateways...',
              empty: 'No gateways found',
              errorPrefix: 'Error loading gateways',
            }) ?? (
              <KubeDataTable data={gatewaysQuery.data ?? []}>
                <Column title="Name" data="name">
                  {(name: unknown) => nameButton(name, 'gateway', LIST_ROUTE, namespace)}
                </Column>
                <Column title="GatewayClass" data="gatewayClass" />
                <Column title="Listeners" data="listeners" />
              </KubeDataTable>
            )}
          </CTabPanel>

          <CTab itemKey="httproutes">HTTPRoutes</CTab>
          <CTabPanel itemKey="httproutes">
            {tabState(httpRoutesQuery, {
              loading: 'Loading http routes...',
              empty: 'No http routes found',
              errorPrefix: 'Error loading http routes',
            }) ?? (
              <KubeDataTable data={httpRoutesQuery.data ?? []}>
                <Column title="Name" data="name">
                  {(name: unknown) => nameButton(name, 'httproute', LIST_ROUTE, namespace)}
                </Column>
                <Column title="Hostnames" data="hostnames" />
                <Column title="ParentRefs" data="parentRefs" />
              </KubeDataTable>
            )}
          </CTabPanel>

          <CTab itemKey="referencegrants">ReferenceGrants</CTab>
          <CTabPanel itemKey="referencegrants">
            {tabState(referenceGrantsQuery, {
              loading: 'Loading reference grants...',
              empty: 'No reference grants found',
              errorPrefix: 'Error loading reference grants',
            }) ?? (
              <KubeDataTable data={referenceGrantsQuery.data ?? []}>
                <Column title="Name" data="name">
                  {(name: unknown) => nameButton(name, 'referencegrant', LIST_ROUTE, undefined)}
                </Column>
                <Column title="From" data="from" />
                <Column title="To" data="to" />
              </KubeDataTable>
            )}
          </CTabPanel>
        </CTabs>
      </CCardBody>
    </CCard>
  )
}

export default GatewayApiView
