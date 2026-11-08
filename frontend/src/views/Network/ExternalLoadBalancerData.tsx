import { Link } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef } from '../../lib/objectRef'
import type {
  BgpAdvertisementItem,
  BgpPeerItem,
  IpAddressPoolItem,
  LabelSelector,
  L2AdvertisementItem,
  ResourceList,
} from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as the sibling data views: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the full custom object, so the json grammar
// is the truthful classifier for the exact text rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// The closed kind set (validated BEFORE the fetch — a bad kind renders the
// error line with NO network hit). The registry kind maps to the API
// resource plural + the pinned copy set. All four kinds are namespaced in
// the URL (the backend's provider detection picks the call; the Cilium
// fallbacks ignore the namespace server-side). The card title is `<type>
// Objects` (4.1's shape, e.g. `ipaddresspool Objects`).
const KIND_INFO = {
  ipaddresspool: {
    resource: 'ipaddresspools',
    label: 'IP Address Pool',
    title: 'ipaddresspool Objects',
    loading: 'Loading IP address pool data...',
    notFound: (name: string) => `No ipaddresspool '${name}' found`,
    missingName: 'Error: ipaddresspool name not provided',
  },
  l2advertisement: {
    resource: 'l2advertisements',
    label: 'L2 Advertisement',
    title: 'l2advertisement Objects',
    loading: 'Loading L2 advertisement data...',
    notFound: (name: string) => `No l2advertisement '${name}' found`,
    missingName: 'Error: l2advertisement name not provided',
  },
  bgppeers: {
    resource: 'bgppeers',
    label: 'BGP Peer',
    title: 'bgppeers Objects',
    loading: 'Loading BGP peer data...',
    notFound: (name: string) => `No bgppeers '${name}' found`,
    missingName: 'Error: bgppeers name not provided',
  },
  bgpadvertisement: {
    resource: 'bgpadvertisements',
    label: 'BGP Advertisement',
    title: 'bgpadvertisement Objects',
    loading: 'Loading BGP advertisement data...',
    notFound: (name: string) => `No bgpadvertisement '${name}' found`,
    missingName: 'Error: bgpadvertisement name not provided',
  },
} as const

type ExlbKind = keyof typeof KIND_INFO
type Item = IpAddressPoolItem | L2AdvertisementItem | BgpPeerItem | BgpAdvertisementItem

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

// A LabelSelector LIST rendered one selector per line (the 4.1 sub-tables
// collapsed to the 5.0 single-cell text form).
const selectorListText = (sels: LabelSelector[] | undefined): string => {
  if (!sels || sels.length === 0) return '—'
  return sels.map((s) => selectorText(s)).join('; ')
}

const joinOrDash = (list: string[] | undefined): string =>
  list && list.length > 0 ? list.join(', ') : '—'

const boolOrDash = (v: boolean | undefined): string => (v === undefined ? '—' : String(v))

const textOrDash = (v: string | number | undefined): string =>
  v === undefined || v === null ? '—' : String(v)

/**
 * 4.1 `plugins/external_loadbalancer/templates/external-loadbalancer-data.html.j2`
 * port: one external-LB object per registry kind, with the PROVIDER-SPECIFIC
 * row set (the 4.1 per-object_type + type rows). ADR-0040: identity arrives
 * as props from the route's dispatcher (the active ref — kind + name +
 * namespace), never from useSearchParams (R1/R8). The single `?name=`
 * request re-fetches by identity (4.1's hidden-form `ast.literal_eval`
 * round-trip is NOT replicated). The `provider` tag selects the row set
 * (metal-lb vs cilium) and renders as the Type row. Empty `items` is the
 * kind's pinned not-found STATE (muted, never an error; the
 * both-providers-absent state is the same). The page GAINS the full-object
 * JSON block (a ratified 5.0 deviation).
 */
const ExternalLoadBalancerDataView = ({
  name,
  kind,
  namespace,
}: {
  name: string
  kind: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const info = KIND_INFO[kind as ExlbKind]

  const query = useQuery<Item>({
    queryKey: ['external-lb-data', kind, cluster?.id, name, namespace],
    enabled: cluster != null && name !== '' && info !== undefined,
    queryFn: async () => {
      const url =
        `/api/v1/clusters/${cluster!.id}/resources/${info!.resource}?name=${encodeURIComponent(name)}` +
        `&namespace=${encodeURIComponent(namespace)}`
      const r = await apiFetch<ResourceList<Item>>(url)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  // The closed-set validation (bad kind → error line, no fetch — the query
  // is disabled for a bad kind).
  if (!info) {
    return (
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Network</CBreadcrumbItem>
            <CBreadcrumbItem>
              <Link to="/network/external-loadbalancer" onClick={clearActiveRef}>
                LoadBalancer Objects
              </Link>
            </CBreadcrumbItem>
            <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
          </CBreadcrumb>
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">LoadBalancer Data</CCardTitle>
        </CCardHeader>
        <CCardBody>
          <div className="text-danger">
            Error: unknown external load balancer kind: {kind || '(none)'}
          </div>
        </CCardBody>
      </CCard>
    )
  }

  const item = query.data
  const provider = item?.provider ?? '—'

  // The 4.1 per-object_type + provider row set.
  const kindRows: { label: string; value: string }[] = []
  if (item) {
    if (kind === 'ipaddresspool') {
      const p = item as IpAddressPoolItem
      const sa = p.spec?.serviceAllocation
      if (provider === 'cilium') {
        kindRows.push(
          { label: 'Blocks', value: joinOrDash(p.spec?.cidrs) },
          { label: 'Allow First Last IPs', value: boolOrDash(p.spec?.allowFirstLastIPs) },
          { label: 'Disabled', value: boolOrDash(p.spec?.disabled) },
          { label: 'IP Family Policy', value: textOrDash(p.spec?.ipFamilyPolicy) },
          { label: 'IP Families', value: joinOrDash(p.spec?.ipFamilies) },
        )
      } else {
        kindRows.push(
          { label: 'Addresses', value: joinOrDash(p.spec?.addresses) },
          { label: 'Auto assign', value: boolOrDash(p.spec?.autoAssign) },
          { label: 'Avoid buggy IPs', value: boolOrDash(p.spec?.avoidBuggyIPs) },
          { label: 'Allocation Namespaces', value: joinOrDash(sa?.namespaces) },
          { label: 'Allocation Namespace Selectors', value: selectorListText(sa?.namespaceSelectors) },
          { label: 'Service Selectors', value: selectorListText(sa?.serviceSelectors) },
          { label: 'Allocation Service Selectors', value: selectorText(sa?.podSelector) },
        )
      }
    } else if (kind === 'l2advertisement') {
      const l = item as L2AdvertisementItem
      if (provider === 'cilium') {
        kindRows.push(
          { label: 'Service Selector', value: selectorText(l.spec?.serviceSelector) },
          { label: 'Node Selector', value: selectorText(l.spec?.nodeSelector) },
          { label: 'Interfaces', value: joinOrDash(l.spec?.interfaces) },
          { label: 'External IPs', value: joinOrDash(l.spec?.externalIPs) },
          { label: 'Load Balancer IPs', value: joinOrDash(l.spec?.loadBalancerIPs) },
        )
      } else {
        kindRows.push(
          { label: 'IP Address Pools', value: joinOrDash(l.spec?.ipAddressPools) },
          { label: 'Interfaces', value: joinOrDash(l.spec?.interfaces) },
          { label: 'Node Selectors', value: selectorListText(l.spec?.nodeSelectors) },
          {
            label: 'IP Address Pool Selectors',
            value: selectorListText(l.spec?.ipAddressPoolSelectors),
          },
        )
      }
    } else if (kind === 'bgppeers') {
      const b = item as BgpPeerItem
      if (provider === 'cilium') {
        // 4.1's virtualRouters render (localASN / exportPodCIDR / neighbors
        // with peerAddress / peerASN), one line per router.
        const routers = (b.spec?.virtualRouters ?? [])
          .map((r) => {
            const neighbors = (r.neighbors ?? [])
              .map((n) => `${n.peerAddress ?? '—'}(${n.peerASN ?? '—'})`)
              .join(', ')
            return `localASN: ${textOrDash(r.localASN)}, exportPodCIDR: ${boolOrDash(
              r.exportPodCIDR,
            )}, neighbors: ${neighbors === '' ? '—' : neighbors}`
          })
          .join('; ')
        kindRows.push({ label: 'Virtual Routers', value: routers === '' ? '—' : routers })
      } else {
        kindRows.push(
          { label: 'My ASN', value: textOrDash(b.spec?.myASN) },
          { label: 'Peer Address', value: textOrDash(b.spec?.peerAddress) },
          { label: 'Peer ASN', value: textOrDash(b.spec?.peerASN) },
          { label: 'Node Selectors', value: selectorListText(b.spec?.nodeSelectors) },
          { label: 'Source Address', value: textOrDash(b.spec?.sourceAddress) },
          { label: 'Peer Port', value: textOrDash(b.spec?.peerPort) },
          { label: 'Hold Time', value: textOrDash(b.spec?.holdTime) },
          { label: 'Keepalive Time', value: textOrDash(b.spec?.keepaliveTime) },
          { label: 'Connect Time', value: textOrDash(b.spec?.connectTime) },
          { label: 'Router ID', value: textOrDash(b.spec?.routerID) },
          { label: 'VRF', value: textOrDash(b.spec?.vrf) },
          { label: 'EBGP Multi Hop', value: textOrDash(b.spec?.ebgpMultiHop) },
          { label: 'Disable MP', value: boolOrDash(b.spec?.disableMP) },
          { label: 'Password Secret', value: b.spec?.passwordSecret?.name ?? '—' },
          { label: 'BFD Profile', value: textOrDash(b.spec?.bfdProfile) },
        )
      }
    } else {
      const a = item as BgpAdvertisementItem
      kindRows.push(
        { label: 'Aggregation Length', value: textOrDash(a.spec?.aggregationLength) },
        { label: 'Aggregation Length V6', value: textOrDash(a.spec?.aggregationLengthV6) },
        { label: 'Local Pref', value: textOrDash(a.spec?.localPref) },
        { label: 'Communities', value: joinOrDash(a.spec?.communities) },
        { label: 'IP Address Pools', value: joinOrDash(a.spec?.ipAddressPools) },
        {
          label: 'IP Address Pool Selectors',
          value: selectorListText(a.spec?.ipAddressPoolSelectors),
        },
        { label: 'Node Selectors', value: selectorListText(a.spec?.nodeSelectors) },
        { label: 'Peers', value: joinOrDash(a.spec?.peers) },
      )
    }
  }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/network/external-loadbalancer" onClick={clearActiveRef}>
              LoadBalancer Objects
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">{info.title}</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">{info.missingName}</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>{info.loading}</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">{info.notFound(name)}</div>
          ) : (
            <div className="text-danger">
              Error loading {info.label.toLowerCase()}: {query.error.message}
            </div>
          )
        ) : (
          <>
            <CTable bordered>
              <tbody>
                <tr>
                  <th scope="row">Name:</th>
                  <td>{item?.metadata?.name ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Type:</th>
                  <td>{provider}</td>
                </tr>
                {kindRows.map((row) => (
                  <tr key={row.label}>
                    <th scope="row">{row.label}:</th>
                    <td>{row.value}</td>
                  </tr>
                ))}
              </tbody>
            </CTable>
            <CCard className="mb-0 mt-3">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">{info.label}</CCardTitle>
              </CCardHeader>
              <CCardBody>
                <SyntaxHighlighter
                  language="json"
                  style={anOldHope}
                  wrapLongLines
                  customStyle={{ margin: 0 }}
                  codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
                >
                  {JSON.stringify(item, null, 2)}
                </SyntaxHighlighter>
              </CCardBody>
            </CCard>
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ExternalLoadBalancerDataView
