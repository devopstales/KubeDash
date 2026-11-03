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
import { formatTimestamp } from '../../lib/format'
import type { LimitRangeItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / PriorityClassData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact
// text rendered (ratified 2026-10-28, PriorityClassData final review).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

type LimitPair = { cpu?: string; memory?: string } | undefined

/**
 * 4.1 `other-resources/limit_range-data.html.j2` parity: one LimitRange's
 * metadata, the Container Limits table, and the full object as a
 * syntax-highlighted block. The read is a SINGLE `?name=` fetch (not 4.1's
 * list-then-filter); the kind is namespaced, so the namespace resolves
 * `?namespace=` → store → `default` (the SecretData pattern) and the URL
 * carries it. Empty `items` is a not-found STATE (pinned copy), not an
 * error. The list view's name links are the sole producer of these query
 * strings. The limits table iterates `spec.limits[]` by each entry's `type`
 * field (4.1 hardcoded cpu+memory rows; the rendered output for standard
 * LimitRanges is identical) and renders absent fields as `None` (4.1's
 * pinned copy).
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. The legacy /data route (TICKET-07 keeps it working
// until the contract pass) passes the legacy ?name=/?namespace= through as
// props (its own store/'default' fallback); this view no longer reads the
// URL or the store.
const LimitRangeDataView = ({
  name,
  namespace,
}: {
  name: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<LimitRangeItem>({
    queryKey: ['limit-range-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<LimitRangeItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/limitranges?namespace=${encodeURIComponent(namespace)}&name=${encodeURIComponent(name)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  const annotations = Object.entries(item?.metadata?.annotations ?? {})

  // The 4.1 Container Limits table: one row per spec.limits[] entry, the
  // entry's `type` naming the resource (absent type → cpu + memory rows,
  // 4.1's hardcoded output). `pair` renders `cpu / memory` compact; absent
  // fields render None (4.1's pinned copy).
  const pair = (v: LimitPair): string => {
    if (!v) return 'None'
    const parts = [v.cpu, v.memory].filter(Boolean)
    return parts.length > 0 ? parts.join(' / ') : 'None'
  }
  const limitsRows: { key: string; resource: string; min: string; max: string; def: string; defReq: string; ratio: string }[] = []
  for (const entry of item?.spec?.limits ?? []) {
    const resources = entry.type ? [entry.type] : ['cpu', 'memory']
    for (const r of resources) {
      limitsRows.push({
        key: `${entry.type ?? 'entry'}-${r}-${limitsRows.length}`,
        resource: r,
        min: pair(entry.min),
        max: pair(entry.max),
        def: pair(entry.default),
        defReq: pair(entry.default_request),
        ratio: pair(entry.max_limit_request_ratio),
      })
    }
  }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/other-resource/limit-range">Limit Ranges</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Limit Range Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: limit range name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading limit range data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No LimitRange '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading limit range: {query.error.message}</div>
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
                  <th scope="row">Namespace:</th>
                  <td>{namespace}</td>
                </tr>
                <tr>
                  <th scope="row">Kind:</th>
                  <td>LimitRange</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp)}</td>
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
              </tbody>
            </CTable>
            <CCard className="mb-3">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Container Limits</CCardTitle>
              </CCardHeader>
              <CCardBody>
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>Resource</th>
                      <th>Minimum</th>
                      <th>Maximum</th>
                      <th>Default Limit</th>
                      <th>Default Request</th>
                      <th>Minimum Limit Request Ratio</th>
                    </tr>
                  </thead>
                  <tbody>
                    {limitsRows.map((row) => (
                      <tr key={row.key}>
                        <td>{row.resource}</td>
                        <td>{row.min}</td>
                        <td>{row.max}</td>
                        <td>{row.def}</td>
                        <td>{row.defReq}</td>
                        <td>{row.ratio}</td>
                      </tr>
                    ))}
                  </tbody>
                </CTable>
              </CCardBody>
            </CCard>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Limit Range</CCardTitle>
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

export default LimitRangeDataView
