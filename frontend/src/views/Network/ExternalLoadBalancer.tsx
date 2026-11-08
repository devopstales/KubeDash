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
import { getActiveRef, openObject } from '../../lib/objectRef'
import type {
  BgpAdvertisementItem,
  BgpPeerItem,
  IpAddressPoolItem,
  LabelSelector,
  L2AdvertisementItem,
  ResourceList,
} from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040 (2026-10-29-certmanager-external-loadbalancer-views): the four
// external-LB registry kinds and the ONE clean list route this page renders.
// The 4.1 `/plugins/external-loadbalancer` page is re-implemented at
// /network/external-loadbalancer (the /plugins/ -> /network/ move, ratified
// 2026-10-29 — NO Plugins group revived). The ExternalLoadBalancerRoute
// dispatcher (App.tsx) renders the ref-matched ExternalLoadBalancerData for
// any of the four kinds on this clean route. All four kinds ride the
// selected namespace in the ref (R8) — the backend's provider detection
// (MetalLB primary, Cilium fallback, bgpadvertisements MetalLB-only) is
// server-side; the view renders the detected `provider` tag as the Type
// column (a certified 5.0 deviation — 4.1 hardcoded the type per read).
const LIST_ROUTE = '/network/external-loadbalancer'

type Row = Record<string, unknown>

// A LabelSelector rendered compactly: matchLabels as `k=v` pairs,
// matchExpressions as JSON (the certainty rule — never guess a shape).
const selectorText = (sel: LabelSelector | undefined): string => {
  if (!sel) return '—'
  const labels = Object.entries(sel.matchLabels ?? {})
    .map(([k, v]) => `${k}=${v}`)
    .join(', ')
  const exprs = sel.matchExpressions
  if (labels !== '' && exprs && exprs.length > 0) return `${labels}, ${JSON.stringify(exprs)}`
  if (labels !== '') return labels
  if (exprs && exprs.length > 0) return JSON.stringify(exprs)
  return '—'
}

// The provider-specific address-range field (the SAME column for both
// providers — 4.1's column contract): MetalLB `spec.addresses` / Cilium
// `spec.cidrs`.
const addressesText = (spec: IpAddressPoolItem['spec']): string => {
  const list = spec?.addresses ?? spec?.cidrs
  return list && list.length > 0 ? list.join(', ') : '—'
}

// The provider-specific "what this L2 policy applies to" field: MetalLB
// `spec.ipAddressPools` / Cilium `spec.serviceSelector`.
const l2PoolsText = (spec: L2AdvertisementItem['spec']): string => {
  const pools = spec?.ipAddressPools
  if (pools && pools.length > 0) return pools.join(', ')
  return selectorText(spec?.serviceSelector)
}

// The provider-specific peer identity: MetalLB `spec.peerAddress` / Cilium
// the first `spec.virtualRouters[].neighbors[].peerAddress` (the spec's
// single-identity list cell — the data view renders the full virtualRouters).
const peerText = (spec: BgpPeerItem['spec']): string => {
  if (spec?.peerAddress) return spec.peerAddress
  const routers = spec?.virtualRouters ?? []
  for (const router of routers) {
    const neighbor = (router.neighbors ?? []).find((n) => n.peerAddress)
    if (neighbor?.peerAddress) return neighbor.peerAddress
  }
  return '—'
}

// The pool references (both tabs render `spec.ipAddressPools` — MetalLB
// only for BGP Advertisements).
const poolsText = (pools: string[] | undefined): string =>
  pools && pools.length > 0 ? pools.join(', ') : '—'

/**
 * 4.1 `plugins/external_loadbalancer/templates/external-loadbalancer.html.j2`
 * parity: the MetalLB / Cilium LB CRDs as CoreUI tabs (IP Address Pools /
 * L2 Advertisements / BGP Peers / BGP Advertisements — the 4.1 order). The
 * card title stays EXACTLY "LoadBalancer Objects" (the e2e-smoke contract).
 * CTabPanel keeps every panel mounted, so all four fetch on mount.
 * ADR-0040: the Name cells are buttons (openObject), never Links — the URL
 * stays clean (R1). Both-providers-absent renders the same first-class
 * empty state (the CRD-seam contract: absent -> []).
 */
const ExternalLoadBalancerView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()

  const ipAddressPoolsQuery = useQuery<Row[]>({
    queryKey: ['external-lb', 'ipaddresspools', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IpAddressPoolItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ipaddresspools?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        type: item.provider ?? '—',
        addresses: addressesText(item.spec),
      }))
    },
  })

  const l2AdvertisementsQuery = useQuery<Row[]>({
    queryKey: ['external-lb', 'l2advertisements', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<L2AdvertisementItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/l2advertisements?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        type: item.provider ?? '—',
        pools: l2PoolsText(item.spec),
      }))
    },
  })

  const bgpPeersQuery = useQuery<Row[]>({
    queryKey: ['external-lb', 'bgppeers', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<BgpPeerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/bgppeers?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        type: item.provider ?? '—',
        peer: peerText(item.spec),
      }))
    },
  })

  const bgpAdvertisementsQuery = useQuery<Row[]>({
    queryKey: ['external-lb', 'bgpadvertisements', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<BgpAdvertisementItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/bgpadvertisements?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        type: item.provider ?? '—',
        pools: poolsText(item.spec?.ipAddressPools),
      }))
    },
  })

  // One name-cell factory for every tab: the button's openObject call is
  // the ADR-0040 identity write (the ref rides the selected namespace —
  // R8) and navigates to this SAME clean route — the ExternalLoadBalancerRoute
  // dispatcher renders the matching detail. The bold is driven by the
  // active ref (R9).
  const isSelected = (kind: string) =>
    active !== null && active.kind === kind && active.namespace === namespace

  const nameButton = (name: unknown, kind: string) =>
    typeof name === 'string' && name ? (
      <button
        type="button"
        className={
          'btn btn-link btn-sm p-0 text-primary text-decoration-underline' +
          (isSelected(kind) ? ' fw-bold' : '')
        }
        aria-current={isSelected(kind) ? 'true' : undefined}
        onClick={() => openObject(kind, name, namespace, LIST_ROUTE, navigate)}
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

  const loadState = { loading: 'Loading load-balancer objects...' }
  const errState = { errorPrefix: 'Error loading load-balancer objects' }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem active>LoadBalancer Objects</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">LoadBalancer Objects</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : (
          <CTabs defaultActiveItemKey="ipaddresspools">
            <CTab itemKey="ipaddresspools">IP Address Pools</CTab>
            <CTabPanel itemKey="ipaddresspools">
              {tabState(ipAddressPoolsQuery, {
                ...loadState,
                ...errState,
                empty: 'No IP address pools found',
              }) ?? (
                <KubeDataTable data={ipAddressPoolsQuery.data ?? []}>
                  <Column title="Type" data="type" />
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'ipaddresspool')}
                  </Column>
                  <Column title="Addresses" data="addresses" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="l2advertisements">L2 Advertisements</CTab>
            <CTabPanel itemKey="l2advertisements">
              {tabState(l2AdvertisementsQuery, {
                ...loadState,
                ...errState,
                empty: 'No L2 advertisements found',
              }) ?? (
                <KubeDataTable data={l2AdvertisementsQuery.data ?? []}>
                  <Column title="Type" data="type" />
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'l2advertisement')}
                  </Column>
                  <Column title="Pools" data="pools" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="bgppeers">BGP Peers</CTab>
            <CTabPanel itemKey="bgppeers">
              {tabState(bgpPeersQuery, {
                ...loadState,
                ...errState,
                empty: 'No BGP peers found',
              }) ?? (
                <KubeDataTable data={bgpPeersQuery.data ?? []}>
                  <Column title="Type" data="type" />
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'bgppeers')}
                  </Column>
                  <Column title="Peer" data="peer" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="bgpadvertisements">BGP Advertisements</CTab>
            <CTabPanel itemKey="bgpadvertisements">
              {tabState(bgpAdvertisementsQuery, {
                ...loadState,
                ...errState,
                empty: 'No BGP advertisements found',
              }) ?? (
                <KubeDataTable data={bgpAdvertisementsQuery.data ?? []}>
                  <Column title="Type" data="type" />
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'bgpadvertisement')}
                  </Column>
                  <Column title="Pools" data="pools" />
                </KubeDataTable>
              )}
            </CTabPanel>
          </CTabs>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ExternalLoadBalancerView
