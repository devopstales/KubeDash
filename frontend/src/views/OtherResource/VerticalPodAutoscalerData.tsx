import React from 'react'
import { Link, useSearchParams } from 'react-router-dom'
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
import type { ResourceList, VerticalPodAutoscalerItem } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as PriorityClassData.tsx / NetworkPolicyData.tsx: the hljs
// language module is a singleton, so a second registration is harmless.
// Register `json` — the block is `JSON.stringify` of the custom object
// (a YAML subset), so the json grammar is the truthful classifier for the
// exact text rendered (ratified rule, PriorityClassData final review
// 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// Min/Max Allowed render "resource: value" lines. An ABSENT bound renders
// N/A (certainty rule: never guess); a present-but-empty object renders —
// (the bound exists, it is simply empty — not the absence sentinel).
const bounds = (b?: Record<string, string>) => {
  if (b == null) return ['N/A']
  const entries = Object.entries(b).map(([k, v]) => `${k}: ${v}`)
  return entries.length > 0 ? entries : ['—']
}

/**
 * 4.1 `other-resources/vpa-data.html.j2` port: one VerticalPodAutoscaler's
 * metadata plus the 4.1 Container Policies + Conditions tables, and the
 * full object as a syntax-highlighted block (`JSON.stringify` — the block
 * is JSON text with the truthful `json` highlighter). The read is a SINGLE
 * `?name=&namespace=` fetch (4.1's list-then-filter is dropped; the list
 * view's name links are the sole producer of these query strings). The
 * kind is a namespaced CRD (autoscaling.k8s.io, full custom object,
 * camelCase — the Cilium seam). The Conditions table reads
 * `status.conditions` — 4.1 iterated a top-level `conditions` key its read
 * function never populated (a dead table); the real conditions live under
 * `status`. The Target (Owner) link (4.1's `/workload/<kind-lower>s`) is
 * dropped: 5.0 has no workload-page destination yet (plain text; the full
 * targetRef is in the JSON block). `trimAnnotations` is not replicated —
 * annotations render verbatim. Empty `items` is a not-found STATE (pinned
 * copy), not an error — also the CRD-absent state (the backend returns []
 * in both cases). Placement under Other Resources is a ratified deviation
 * (ADR-0022).
 */
const VerticalPodAutoscalerDataView = () => {
  const [params] = useSearchParams()
  const name = params.get('name') ?? ''
  const namespace = params.get('namespace') ?? ''
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<VerticalPodAutoscalerItem>({
    queryKey: ['vpa-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<VerticalPodAutoscalerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/verticalpodautoscalers?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
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
  const policies = item?.spec?.resourcePolicy?.containerPolicies ?? []
  const conditions = item?.status?.conditions ?? []

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/other-resource/vertical-pod-autoscaler">Vertical Pod Autoscaler List</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Vertical Pod Autoscaler Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: vertical pod autoscaler name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading vertical pod autoscaler data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            // A miss (or the CRD-absent state) is a state, not an error.
            <div className="text-center text-muted">
              No VerticalPodAutoscaler '{name}' found
            </div>
          ) : (
            <div className="text-danger">
              Error loading vertical pod autoscaler: {query.error.message}
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
                <tr>
                  <th scope="row">Namespace:</th>
                  <td>{item?.metadata?.namespace ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Target (Owner):</th>
                  <td>{item?.spec?.targetRef?.name ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Update Mode:</th>
                  <td>{item?.spec?.updatePolicy?.updateMode ?? 'N/A'}</td>
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
            <CTable bordered className="mt-4">
              <thead>
                <tr>
                  <th>Container Name</th>
                  <th>Controlled Values</th>
                  <th>Mode</th>
                  <th>Min Allowed</th>
                  <th>Max Allowed</th>
                  <th>Controlled Resources</th>
                </tr>
              </thead>
              <tbody>
                {policies.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center text-muted">
                      No container policies
                    </td>
                  </tr>
                ) : (
                  policies.map((cp, i) => (
                    <tr key={cp?.containerName ?? i}>
                      <td>{cp?.containerName ?? 'N/A'}</td>
                      <td>{cp?.controlledValues ?? 'N/A'}</td>
                      <td>{cp?.mode ?? 'N/A'}</td>
                      <td>{bounds(cp?.minAllowed).join('<br/>')}</td>
                      <td>{bounds(cp?.maxAllowed).join('<br/>')}</td>
                      <td>{cp?.controlledResources?.join(', ') || 'N/A'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </CTable>
            <CTable bordered className="mt-4">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Last Transition Time</th>
                  <th>Reason</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {conditions.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center text-muted">
                      No conditions
                    </td>
                  </tr>
                ) : (
                  conditions.map((c, i) => (
                    <tr key={c?.type ?? i}>
                      <td>{c?.type ?? 'N/A'}</td>
                      <td>{c?.status ?? 'N/A'}</td>
                      <td>{c?.lastTransitionTime ?? 'N/A'}</td>
                      <td>{c?.reason ?? 'N/A'}</td>
                      <td>{c?.message ?? 'N/A'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </CTable>
            <CCard className="mb-0 mt-4">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">VerticalPodAutoscaler</CCardTitle>
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

export default VerticalPodAutoscalerDataView
