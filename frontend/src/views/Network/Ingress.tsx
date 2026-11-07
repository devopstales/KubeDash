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
import { openObject } from '../../lib/objectRef'
import type {
  GatewayItem,
  HTTPRouteItem,
  IngressItem,
  ReferenceGrantItem,
  ResourceList,
} from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040: the registry kinds (API resource names) and the ONE clean list
// route this page renders. 4.1 `network/ingress.html.j2` pattern (2026-11-07
// owner decision): the page is a CoreUI tabbed surface — Ingresses + the
// three Gateway API kinds (gateway / httproute / referencegrant) live on the
// SAME route; the detail dispatcher (App.tsx IngressRoute) renders the
// ref-matched detail for any of the four kinds. Ingress/IngressClass rows
// ride the selected namespace (R8, the Pvc pattern); the cluster-scoped
// ReferenceGrants tab carries no namespace. The old /network/gateway-api
// URL redirects here (App.tsx).
//
// The gateway-kind query keys keep the 'gateway-api' prefix: the converter's
// post-apply invalidateQueries({ queryKey: ['gateway-api'] }) (R7/R8) hits
// ALL three tabs so applied resources appear without a manual refresh.
const LIST_ROUTE = '/network/ingress'

type Row = Record<string, unknown>

const listenersText = (spec: GatewayItem['spec']): string => {
  const list = spec?.listeners ?? []
  const parts = list
    .map((l) => [l.name, l.protocol, l.port].filter((x) => x != null && x !== '').join(':'))
    .filter((s) => s !== '')
  return parts.length > 0 ? parts.join(', ') : '—'
}

/**
 * 4.1 `network/ingress.html.j2` parity, merged (2026-11-07 owner decision):
 * tabs Ingresses | Gateways | HTTPRoutes | ReferenceGrants (CoreUI CTabs —
 * 4.1's bootstrap tab pattern). The card title stays EXACTLY "Ingress List"
 * (the spec's pinned title). CTabPanel keeps every panel mounted, so all
 * four fetch on mount. ADR-0040: name cells are buttons (openObject), never
 * Links — the URL stays clean (R1).
 */
const IngressView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()

  const ingressesQuery = useQuery<Row[]>({
    queryKey: ['ingresses', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IngressItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ingresses?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => {
        // 4.1 parity columns: Name / IngressClass / Hostname.
        const hosts = (item.spec?.rules ?? [])
          .map((r) => r.host)
          .filter((h): h is string => Boolean(h))
        return {
          name: item.metadata?.name ?? '',
          // "—" when absent (certainty rule: never guess).
          ingressClass: item.spec?.ingress_class_name ?? '—',
          hostname: hosts.length > 0 ? hosts.join(', ') : '—',
        }
      })
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

  // One name-cell factory for every tab: the button's openObject call is the
  // ADR-0040 identity write (the ref carries the row's namespace for the
  // namespaced kinds) and navigates to this SAME clean route — the
  // IngressRoute dispatcher renders the matching detail.
  const nameButton = (name: unknown, kind: string, ns: string | undefined) =>
    typeof name === 'string' && name ? (
      <button
        type="button"
        className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
        onClick={() => openObject(kind, name, ns, LIST_ROUTE, navigate)}
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
          <CBreadcrumbItem active>Ingress List</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Ingress List</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : (
          <CTabs defaultActiveItemKey="ingresses">
            <CTab itemKey="ingresses">Ingresses</CTab>
            <CTabPanel itemKey="ingresses">
              {tabState(ingressesQuery, {
                loading: 'Loading ingresses...',
                empty: 'No ingresses found',
                errorPrefix: 'Error loading ingresses',
              }) ?? (
                <KubeDataTable data={ingressesQuery.data ?? []}>
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'ingress', namespace)}
                  </Column>
                  <Column title="IngressClass" data="ingressClass" />
                  <Column title="Hostname" data="hostname" />
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
                    {(name: unknown) => nameButton(name, 'gateway', namespace)}
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
                    {(name: unknown) => nameButton(name, 'httproute', namespace)}
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
                    {(name: unknown) => nameButton(name, 'referencegrant', undefined)}
                  </Column>
                  <Column title="From" data="from" />
                  <Column title="To" data="to" />
                </KubeDataTable>
              )}
            </CTabPanel>
          </CTabs>
        )}
      </CCardBody>
    </CCard>
  )
}

export default IngressView
