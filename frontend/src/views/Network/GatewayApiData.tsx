import React from 'react'
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
import { formatTimestamp } from '../../lib/format'
import type { GatewayItem, HTTPRouteItem, ReferenceGrantItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as the sibling data views: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the full custom object, so the json grammar
// is the truthful classifier for the exact text rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// The closed kind set (validated BEFORE the fetch — a bad kind renders the
// error line with NO network hit). The registry kind (lowercase) maps to
// the API resource plural + the pinned copy set. referencegrant is
// CLUSTER-scoped (no namespace param); gateway + httproute are namespaced.
const KIND_INFO = {
  gateway: {
    resource: 'gateways',
    label: 'Gateway',
    title: 'Gateway Data',
    loading: 'Loading gateway data...',
    notFound: (name: string) => `No Gateway '${name}' found`,
    namespaced: true,
  },
  httproute: {
    resource: 'httproutes',
    label: 'HTTPRoute',
    title: 'HTTPRoute Data',
    loading: 'Loading http route data...',
    notFound: (name: string) => `No HTTPRoute '${name}' found`,
    namespaced: true,
  },
  referencegrant: {
    resource: 'referencegrants',
    label: 'ReferenceGrant',
    title: 'ReferenceGrant Data',
    loading: 'Loading reference grant data...',
    notFound: (name: string) => `No ReferenceGrant '${name}' found`,
    namespaced: false,
  },
} as const

type ApiKind = keyof typeof KIND_INFO
type Item = GatewayItem | HTTPRouteItem | ReferenceGrantItem

const listenersText = (spec: GatewayItem['spec']): string => {
  const list = spec?.listeners ?? []
  const parts = list
    .map((l) => [l.name, l.protocol, l.port].filter((x) => x != null && x !== '').join(':'))
    .filter((s) => s !== '')
  return parts.length > 0 ? parts.join(', ') : '—'
}

/**
 * 2026-10-28-ingress-gateway-api-views: the Gateway API detail — one view
 * dispatched by the registry kind (gateway / httproute / referencegrant,
 * arriving from the route's dispatcher — the active ref, never the URL,
 * ADR-0040 R1/R8). The kind is validated against the closed set BEFORE the
 * fetch (bad kind → the error line, no network hit). Each kind renders its
 * CTable (the same field set as its list tab) + the Labels/Annotations
 * sub-tables + the full object as a JSON block. Empty `items` is the
 * kind's pinned not-found STATE (CRD-absent included), never an error.
 * trimAnnotations IS replicated (2026-11-05 user request — the override
 * note is in the change's adr.md); the JSON block still renders the full
 * object.
 */
const GatewayApiDataView = ({
  name,
  kind,
  namespace,
}: {
  name: string
  kind: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const info = KIND_INFO[kind as ApiKind]

  const query = useQuery<Item>({
    queryKey: ['gateway-api-data', kind, cluster?.id, name, namespace],
    enabled: cluster != null && name !== '' && info !== undefined,
    queryFn: async () => {
      const url =
        `/api/v1/clusters/${cluster!.id}/resources/${info!.resource}?name=${encodeURIComponent(name)}` +
        (info!.namespaced
          ? `&namespace=${encodeURIComponent(namespace)}`
          : '')
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
              <Link to="/network/ingress" onClick={clearActiveRef}>
                Ingress List
              </Link>
            </CBreadcrumbItem>
            <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
          </CBreadcrumb>
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Gateway API Data</CCardTitle>
        </CCardHeader>
        <CCardBody>
          <div className="text-danger">Error: unknown gateway api kind: {kind || '(none)'}</div>
        </CCardBody>
      </CCard>
    )
  }

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  // 4.1's trimAnnotations: the two machine-managed keys are dropped from the
  // rendered annotations (replicated 2026-11-05 per user request). The JSON
  // block still renders the full object.
  const annotations = Object.entries(item?.metadata?.annotations ?? {}).filter(
    ([key]) =>
      key !== 'kubectl.kubernetes.io/last-applied-configuration'
      && key !== 'autoscaling.alpha.kubernetes.io/conditions',
  )

  // The kind's CTable field rows (the same field set as the list tab).
  const kindRows: { label: string; value: string }[] = []
  if (item) {
    if (kind === 'gateway') {
      const g = item as GatewayItem
      kindRows.push(
        { label: 'GatewayClass:', value: g.spec?.gatewayClassName ?? '—' },
        { label: 'Listeners:', value: listenersText(g.spec) },
      )
    } else if (kind === 'httproute') {
      const h = item as HTTPRouteItem
      const hostnames = (h.spec?.hostnames ?? []).filter((x) => Boolean(x))
      const refs = (h.spec?.parentRefs ?? []).map((p) =>
        p.namespace ? `${p.name ?? '—'}/${p.namespace}` : (p.name ?? '—'),
      )
      kindRows.push(
        { label: 'Hostnames:', value: hostnames.length > 0 ? hostnames.join(', ') : '—' },
        { label: 'ParentRefs:', value: refs.length > 0 ? refs.join(', ') : '—' },
      )
    } else {
      const rg = item as ReferenceGrantItem
      const from = (rg.spec?.from ?? []).map((f) => [f.group, f.kind].filter(Boolean).join(':'))
      const to = (rg.spec?.to ?? []).map((t) => [t.group, t.kind].filter(Boolean).join(':'))
      kindRows.push(
        { label: 'From:', value: from.length > 0 ? from.join(', ') : '—' },
        { label: 'To:', value: to.length > 0 ? to.join(', ') : '—' },
      )
    }
  }

  const kvTable = (entries: [string, string][], none: string) =>
    entries.length === 0 ? (
      none
    ) : (
      <CTable bordered small className="mb-0">
        <thead>
          <tr>
            <th>Key</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {entries.map(([key, value]) => (
            <tr key={key}>
              <td>{key}</td>
              <td className="text-break">{value}</td>
            </tr>
          ))}
        </tbody>
      </CTable>
    )

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/network/ingress" onClick={clearActiveRef}>
              Ingress List
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
          <div className="text-danger">Error: object name not provided</div>
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
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creationTimestamp)}</td>
                </tr>
                {kindRows.map((row) => (
                  <tr key={row.label}>
                    <th scope="row">{row.label}</th>
                    <td>{row.value}</td>
                  </tr>
                ))}
                <tr>
                  <th scope="row">Labels:</th>
                  <td>{kvTable(labels, 'No labels')}</td>
                </tr>
                <tr>
                  <th scope="row">Annotations:</th>
                  <td>{kvTable(annotations, 'No annotations')}</td>
                </tr>
              </tbody>
            </CTable>
            <CCard className="mb-0">
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

export default GatewayApiDataView
