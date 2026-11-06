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
import type { IngressItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as the sibling data views: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the to_dict object (a YAML subset), so the
// json grammar is the truthful classifier for the exact text rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

type RuleRow = {
  host: string
  path: string
  pathType: string
  service: string
  port: string
  tls: string
}

/**
 * 4.1 `network/ingress-data.html.j2` parity: one Ingress's metadata
 * (ingressClass, created, labels, annotations) plus the 4.1 "Routs" table —
 * one row per `spec.rules[].http.paths[]` (Host / Path / PathType / Service
 * / Port / TLS) — plus the full object as a syntax-highlighted block.
 * Port renders the `number`, else the `name`, else "—"; TLS is "yes" when
 * `spec.tls` is non-empty, else "—"; an empty rules list is the pinned
 * "No rules" state. The read is a SINGLE `?name=`+`?namespace=` fetch
 * (not 4.1's list-then-filter). Empty `items` is a not-found STATE (pinned
 * copy), not an error. 4.1 deviations (briefing.md): 4.1's "Type" header is
 * NOT replicated (renders `PathType`); the row order is the spec's
 * Name/IngressClass/Created/Labels/Annotations; trimAnnotations IS
 * replicated (2026-11-05 user request, overriding the 2026-10-28 "render
 * verbatim" deviation — the override note is in the change's adr.md); the
 * full-object JSON block is a 5.0 addition.
 */
// ADR-0040: identity arrives as props from the route's dispatcher
// (the active ref), never from useSearchParams — the URL stays clean (R1).
// The namespace IS the ref's namespace (R8); this kind was a stub until
// this change: the /data URL never shipped, so there is no legacy route
// (no R7 redirect) to pass the name through.
const IngressDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<IngressItem>({
    queryKey: ['ingress-data', cluster?.id, name, namespace],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IngressItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/ingresses?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

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
  // The 4.1 Routes table: one row per spec.rules[].http.paths[].
  const rules: RuleRow[] = []
  for (const rule of item?.spec?.rules ?? []) {
    for (const p of rule.http?.paths ?? []) {
      const port = p.backend?.service?.port
      rules.push({
        host: rule.host ?? '—',
        path: p.path ?? '—',
        pathType: p.path_type ?? '—',
        service: p.backend?.service?.name ?? '—',
        port: port?.number != null ? String(port.number) : (port?.name ?? '—'),
        tls: (item?.spec?.tls?.length ?? 0) > 0 ? 'yes' : '—',
      })
    }
  }

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
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Ingress Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: ingress name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading ingress data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No Ingress '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading ingress: {query.error.message}</div>
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
                  <th scope="row">IngressClass:</th>
                  <td>{item?.spec?.ingress_class_name ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp)}</td>
                </tr>
                <tr>
                  <th scope="row">Labels:</th>
                  <td>
                    {labels.length === 0 ? (
                      'No labels'
                    ) : (
                      <CTable bordered small className="mb-0">
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {labels.map(([key, value]) => (
                            <tr key={key}>
                              <td>{key}</td>
                              <td className="text-break">{value}</td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )}
                  </td>
                </tr>
                <tr>
                  <th scope="row">Annotations:</th>
                  <td>
                    {annotations.length === 0 ? (
                      'No annotations'
                    ) : (
                      <CTable bordered small className="mb-0">
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {annotations.map(([key, value]) => (
                            <tr key={key}>
                              <td>{key}</td>
                              <td className="text-break">{value}</td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )}
                  </td>
                </tr>
              </tbody>
            </CTable>
            <CCard className="mb-3">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Rules</CCardTitle>
              </CCardHeader>
              <CCardBody>
                {rules.length === 0 ? (
                  <div>No rules</div>
                ) : (
                  <CTable bordered>
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Path</th>
                        <th>PathType</th>
                        <th>Service</th>
                        <th>Port</th>
                        <th>TLS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rules.map((row, i) => (
                        <tr key={i}>
                          <td>{row.host}</td>
                          <td>{row.path}</td>
                          <td>{row.pathType}</td>
                          <td>{row.service}</td>
                          <td>{row.port}</td>
                          <td>{row.tls}</td>
                        </tr>
                      ))}
                    </tbody>
                  </CTable>
                )}
              </CCardBody>
            </CCard>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Ingress</CCardTitle>
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

export default IngressDataView
